"""HTTP/SSE (Streamable HTTP and legacy SSE) MCP security proxy built on Starlette and httpx."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from mcp_guard.engine.pipeline import SecurityPipeline
from mcp_guard.models.jsonrpc import make_error_response, parse_jsonrpc_frame
from mcp_guard.models.policy import PolicyConfig
from mcp_guard.ui import (
    EmbeddedUiHandle,
    EventBus,
    start_embedded_ui_server,
    validate_loopback_host,
)
from mcp_guard.utils.canonical import normalize_server_id
from mcp_guard.utils.logging import configure_logger

MAX_INFLIGHT_REQUESTS = 4096
PARSE_ERROR_CODE = -32700

_HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
    }
)

_RESPONSE_STRIP_HEADERS: frozenset[str] = _HOP_BY_HOP_HEADERS | frozenset({"content-encoding"})


@dataclass(frozen=True, slots=True)
class _HttpRequestMeta:
    method: str
    tool_name: str | None = None
    uri: str | None = None


def _make_request_key(req_id: Any) -> tuple[str, int | str] | None:
    if req_id is None or isinstance(req_id, bool):
        return None
    if not isinstance(req_id, (int, str)):
        return None
    return (type(req_id).__name__, req_id)


def _extract_meta(msg: dict[str, Any]) -> _HttpRequestMeta:
    method = str(msg.get("method", ""))
    params = msg.get("params")
    tool_name: str | None = None
    uri: str | None = None
    if isinstance(params, dict):
        if method == "tools/call":
            raw_name = params.get("name")
            if isinstance(raw_name, str) and raw_name:
                tool_name = raw_name
        elif method == "resources/read":
            raw_uri = params.get("uri")
            if isinstance(raw_uri, str) and raw_uri:
                uri = raw_uri
    return _HttpRequestMeta(method=method, tool_name=tool_name, uri=uri)


class _RequestTracker:
    """Bounded FIFO-evicting OrderedDict mapping request IDs to method/tool/uri."""

    def __init__(self, max_entries: int = MAX_INFLIGHT_REQUESTS) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, int | str], _HttpRequestMeta] = OrderedDict()

    def record_frame(self, frame: dict[str, Any] | list[dict[str, Any]]) -> None:
        items = frame if isinstance(frame, list) else [frame]
        for item in items:
            if "id" not in item or "method" not in item:
                continue
            key = _make_request_key(item.get("id"))
            if key is None:
                continue
            self._entries[key] = _extract_meta(item)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def pop_for_id(self, req_id: Any) -> _HttpRequestMeta | None:
        key = _make_request_key(req_id)
        if key is None:
            return None
        return self._entries.pop(key, None)


def _serialize_jsonrpc(frame: dict[str, Any] | list[dict[str, Any]]) -> bytes:
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _filter_request_headers(headers: Any) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _HOP_BY_HOP_HEADERS:
            continue
        filtered[key] = value
    return filtered


def _filter_response_headers(headers: httpx.Headers) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _RESPONSE_STRIP_HEADERS:
            continue
        filtered[key] = value
    return filtered


def _resolve_upstream_url(target_url: str, incoming_path: str, incoming_query: str) -> str:
    """Resolve the upstream URL for root, Streamable HTTP, and legacy SSE subpaths."""
    parsed_target = urlsplit(target_url)
    origin = urlunsplit((parsed_target.scheme, parsed_target.netloc, "", "", ""))

    if incoming_path in ("", "/"):
        if incoming_query:
            combined_query = (
                f"{parsed_target.query}&{incoming_query}" if parsed_target.query else incoming_query
            )
            return urlunsplit(
                (parsed_target.scheme, parsed_target.netloc, parsed_target.path, combined_query, "")
            )
        return urlunsplit(
            (
                parsed_target.scheme,
                parsed_target.netloc,
                parsed_target.path,
                parsed_target.query,
                "",
            )
        )

    return (
        urlunsplit(
            (
                parsed_target.scheme,
                parsed_target.netloc,
                incoming_path if incoming_path.startswith("/") else f"/{incoming_path}",
                incoming_query,
                "",
            )
        )
        if origin
        else target_url
    )


def _rewrite_endpoint_data(raw_data: str, target_url: str, proxy_base_url: str) -> str:
    """Rewrite legacy SSE 'endpoint' data to point through the proxy while keeping query params."""
    stripped = raw_data.strip()
    resolved = urljoin(target_url, stripped)
    parsed = urlsplit(resolved)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    base = proxy_base_url.rstrip("/")
    if base:
        return f"{base}{path}{query}"
    return f"{path}{query}"


def _find_sse_boundary(buf: bytearray) -> tuple[int, int] | None:
    """Return (index, separator_length) of the earliest SSE event boundary in buf."""
    idx_lf = buf.find(b"\n\n")
    idx_crlf = buf.find(b"\r\n\r\n")
    if idx_lf == -1 and idx_crlf == -1:
        return None
    if idx_lf == -1:
        return (idx_crlf, 4)
    if idx_crlf == -1:
        return (idx_lf, 2)
    if idx_crlf < idx_lf:
        return (idx_crlf, 4)
    return (idx_lf, 2)


def _format_sse_event(
    meta_lines: list[str],
    data_payload: str,
) -> bytes:
    lines = list(meta_lines)
    for data_line in data_payload.split("\n"):
        lines.append(f"data: {data_line}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


async def _inspect_response_frame(
    frame: dict[str, Any] | list[dict[str, Any]],
    pipeline: SecurityPipeline,
    tracker: _RequestTracker,
) -> dict[str, Any] | list[dict[str, Any]] | None:
    if isinstance(frame, dict):
        meta = tracker.pop_for_id(frame.get("id"))
        decision = await pipeline.inspect_response(
            frame,
            method=meta.method if meta else None,
            tool_name=meta.tool_name if meta else None,
            uri=meta.uri if meta else None,
        )
        return decision.message

    out_items: list[dict[str, Any]] = []
    for item in frame:
        meta = tracker.pop_for_id(item.get("id"))
        decision = await pipeline.inspect_response(
            item,
            method=meta.method if meta else None,
            tool_name=meta.tool_name if meta else None,
            uri=meta.uri if meta else None,
        )
        if isinstance(decision.message, dict):
            out_items.append(decision.message)
    return out_items or None


async def _process_sse_event_block(
    raw_block: bytes,
    *,
    target_url: str,
    proxy_base_url: str,
    pipeline: SecurityPipeline,
    tracker: _RequestTracker,
    logger: logging.Logger,
) -> bytes:
    if not raw_block.strip():
        return b""

    text = raw_block.decode("utf-8", errors="replace")
    lines = text.splitlines()

    event_type: str | None = None
    meta_lines: list[str] = []
    data_lines: list[str] = []
    has_data = False

    for line in lines:
        if line.startswith(":"):
            meta_lines.append(line)
            continue
        if ":" in line:
            field, rest = line.split(":", 1)
            value = rest[1:] if rest.startswith(" ") else rest
        else:
            field, value = line, ""

        if field == "data":
            has_data = True
            data_lines.append(value)
        elif field == "event":
            event_type = value
            meta_lines.append(line)
        else:
            meta_lines.append(line)

    if not has_data:
        return (text + "\n\n").encode("utf-8")

    joined_data = "\n".join(data_lines)

    if event_type == "endpoint":
        rewritten = _rewrite_endpoint_data(joined_data, target_url, proxy_base_url)
        return _format_sse_event(meta_lines, rewritten)

    if not joined_data.strip():
        return (text + "\n\n").encode("utf-8")

    try:
        parsed = parse_jsonrpc_frame(joined_data)
    except ValueError:
        # Non-JSON SSE message (e.g. heartbeat/status text): pass through cleanly.
        logger.debug("Passing through non-JSON-RPC SSE event payload")
        return (text + "\n\n").encode("utf-8")

    inspected = await _inspect_response_frame(parsed, pipeline, tracker)
    if inspected is None:
        return b""

    serialized = json.dumps(inspected, separators=(",", ":"), ensure_ascii=False)
    return _format_sse_event(meta_lines, serialized)


async def _stream_sse_events(
    upstream_resp: httpx.Response,
    *,
    target_url: str,
    proxy_base_url: str,
    pipeline: SecurityPipeline,
    tracker: _RequestTracker,
    logger: logging.Logger,
) -> AsyncIterator[bytes]:
    buffer = bytearray()
    try:
        async for chunk in upstream_resp.aiter_bytes():
            if not chunk:
                continue
            buffer.extend(chunk)
            while True:
                boundary = _find_sse_boundary(buffer)
                if boundary is None:
                    break
                end_idx, sep_len = boundary
                raw_block = bytes(buffer[:end_idx])
                del buffer[: end_idx + sep_len]
                out_bytes = await _process_sse_event_block(
                    raw_block,
                    target_url=target_url,
                    proxy_base_url=proxy_base_url,
                    pipeline=pipeline,
                    tracker=tracker,
                    logger=logger,
                )
                if out_bytes:
                    yield out_bytes

        if buffer.strip():
            out_bytes = await _process_sse_event_block(
                bytes(buffer),
                target_url=target_url,
                proxy_base_url=proxy_base_url,
                pipeline=pipeline,
                tracker=tracker,
                logger=logger,
            )
            if out_bytes:
                yield out_bytes
    finally:
        await upstream_resp.aclose()


def create_http_proxy_app(
    target_url: str,
    policy: PolicyConfig,
    *,
    logger: logging.Logger | None = None,
    upstream_client: httpx.AsyncClient | None = None,
    event_bus: EventBus | None = None,
) -> Starlette:
    """Create a Starlette ASGI application proxying Streamable HTTP and legacy SSE MCP traffic."""
    log_path = Path(policy.log_file) if policy.log_file else None
    eff_logger = logger or configure_logger("mcp_guard.proxy.http", log_file=log_path)
    server_id = policy.server_id or normalize_server_id(target_url)
    pipeline = SecurityPipeline(
        policy,
        server_id=server_id,
        logger=eff_logger,
        event_sink=event_bus.publish if event_bus is not None else None,
    )
    tracker = _RequestTracker()

    owns_client = upstream_client is None
    client = upstream_client or httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_client:
                await client.aclose()

    async def handle_proxy(request: Request) -> Response:
        upstream_url = _resolve_upstream_url(
            target_url,
            request.url.path,
            request.url.query,
        )
        fwd_headers = _filter_request_headers(request.headers)
        proxy_base_url = str(request.base_url).rstrip("/")

        if request.method == "POST":
            raw_body = await request.body()
            if raw_body.strip():
                try:
                    parsed_req = parse_jsonrpc_frame(raw_body)
                except ValueError as exc:
                    eff_logger.warning("Malformed JSON-RPC POST request: %s", exc)
                    err = make_error_response(None, PARSE_ERROR_CODE, f"Parse error: {exc}")
                    return JSONResponse(err, status_code=400)

                decision = await pipeline.inspect_request(parsed_req)
                if not decision.allowed:
                    if decision.message is None:
                        return Response(status_code=202)
                    return Response(
                        content=_serialize_jsonrpc(decision.message),
                        status_code=200,
                        media_type="application/json",
                    )

                outgoing_req = decision.message if decision.message is not None else parsed_req
                tracker.record_frame(outgoing_req)
                forward_body = _serialize_jsonrpc(outgoing_req)
            else:
                forward_body = raw_body

            upstream_req = client.build_request(
                "POST",
                upstream_url,
                headers=fwd_headers,
                content=forward_body,
            )
            upstream_resp = await client.send(upstream_req, stream=True)
            resp_headers = _filter_response_headers(upstream_resp.headers)
            content_type = upstream_resp.headers.get("content-type", "").lower()

            if "text/event-stream" in content_type:
                return StreamingResponse(
                    _stream_sse_events(
                        upstream_resp,
                        target_url=target_url,
                        proxy_base_url=proxy_base_url,
                        pipeline=pipeline,
                        tracker=tracker,
                        logger=eff_logger,
                    ),
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                    media_type="text/event-stream",
                )

            try:
                resp_bytes = await upstream_resp.aread()
            finally:
                await upstream_resp.aclose()

            if not resp_bytes.strip():
                return Response(
                    content=resp_bytes,
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                )

            try:
                parsed_resp = parse_jsonrpc_frame(resp_bytes)
            except ValueError:
                return Response(
                    content=resp_bytes,
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                )

            inspected_resp = await _inspect_response_frame(parsed_resp, pipeline, tracker)
            if inspected_resp is None:
                return Response(status_code=204, headers=resp_headers)

            return Response(
                content=_serialize_jsonrpc(inspected_resp),
                status_code=upstream_resp.status_code,
                headers=resp_headers,
                media_type="application/json",
            )

        if request.method == "GET":
            upstream_req = client.build_request("GET", upstream_url, headers=fwd_headers)
            upstream_resp = await client.send(upstream_req, stream=True)
            resp_headers = _filter_response_headers(upstream_resp.headers)
            content_type = upstream_resp.headers.get("content-type", "").lower()

            if "text/event-stream" in content_type:
                return StreamingResponse(
                    _stream_sse_events(
                        upstream_resp,
                        target_url=target_url,
                        proxy_base_url=proxy_base_url,
                        pipeline=pipeline,
                        tracker=tracker,
                        logger=eff_logger,
                    ),
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                    media_type="text/event-stream",
                )

            try:
                resp_bytes = await upstream_resp.aread()
            finally:
                await upstream_resp.aclose()
            return Response(
                content=resp_bytes,
                status_code=upstream_resp.status_code,
                headers=resp_headers,
            )

        # DELETE / other MCP lifecycle methods
        body = await request.body()
        upstream_req = client.build_request(
            request.method,
            upstream_url,
            headers=fwd_headers,
            content=body,
        )
        upstream_resp = await client.send(upstream_req, stream=False)
        resp_headers = _filter_response_headers(upstream_resp.headers)
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )

    routes = [
        Route(
            "/{path:path}",
            endpoint=handle_proxy,
            methods=["GET", "POST", "DELETE"],
        ),
        Route(
            "/",
            endpoint=handle_proxy,
            methods=["GET", "POST", "DELETE"],
        ),
    ]

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.pipeline = pipeline
    app.state.logger = eff_logger
    app.state.event_bus = event_bus
    return app


def run_http_proxy(
    target_url: str,
    policy: PolicyConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    logger: logging.Logger | None = None,
    ui_port: int | None = None,
    ui_host: str = "127.0.0.1",
    event_bus: EventBus | None = None,
) -> None:
    """Start the HTTP/SSE MCP security proxy using uvicorn."""
    log_path = Path(policy.log_file) if policy.log_file else None
    eff_logger = logger or configure_logger("mcp_guard.proxy.http", log_file=log_path)
    validated_ui_host = validate_loopback_host(ui_host) if ui_port is not None else ui_host
    eff_bus = event_bus or (EventBus() if ui_port is not None else None)
    app = create_http_proxy_app(
        target_url,
        policy,
        logger=eff_logger,
        event_bus=eff_bus,
    )
    if ui_port is None:
        with contextlib.suppress(KeyboardInterrupt):
            uvicorn.run(app, host=host, port=port, log_level="warning")
        return

    async def _serve_with_ui() -> None:
        ui_handle: EmbeddedUiHandle | None = None
        ui_handle = await start_embedded_ui_server(
            policy=policy,
            event_bus=eff_bus,
            pipeline=app.state.pipeline,
            pin_file=policy.pinning.pin_file,
            server_id=app.state.pipeline.server_id,
            host=validated_ui_host,
            port=ui_port,
            logger=eff_logger,
        )
        if ui_handle is not None:
            eff_logger.info("MCP-Guard Web UI listening at %s", ui_handle.url)
        try:
            config = uvicorn.Config(app, host=host, port=port, log_level="warning")
            server = uvicorn.Server(config)
            await server.serve()
        finally:
            if ui_handle is not None:
                await ui_handle.stop()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve_with_ui())
