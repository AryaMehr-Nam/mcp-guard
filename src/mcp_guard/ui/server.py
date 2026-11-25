"""Hardened loopback Web UI server (embedded and standalone) for MCP-Guard."""

from __future__ import annotations

import asyncio
import contextlib
import difflib
import hmac
import importlib.resources
import json
import logging
import math
import os
import secrets
import shlex
import socket
import sys
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
import yaml
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_guard.engine.pinning import PinStore
from mcp_guard.engine.pipeline import SecurityPipeline
from mcp_guard.models.findings import ScanReport
from mcp_guard.models.policy import PolicyConfig
from mcp_guard.reporters import (
    render_json_report,
    render_markdown_report,
    render_sarif_report,
)
from mcp_guard.scanner.active_scanner import ActiveScanner
from mcp_guard.ui.events import EventBus, SecurityEvent
from mcp_guard.utils.logging import configure_logger

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_SESSION_COOKIE = "mcp_guard_session"
_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)
_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "DELETE"})


@dataclass
class EmbeddedUiHandle:
    """Handle to a running embedded MCP-Guard Web UI server."""

    server: uvicorn.Server
    task: asyncio.Task[None]
    host: str
    port: int
    token: str
    url: str

    async def stop(self) -> None:
        """Request graceful shutdown and wait for the UI server task."""
        self.server.should_exit = True
        try:
            await asyncio.wait_for(self.task, timeout=2.0)
        except TimeoutError:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)


def validate_loopback_host(host: str) -> str:
    """Validate that the UI bind host is strictly loopback (127.0.0.1, localhost, or ::1)."""
    normalized = host.strip().lower()
    if normalized not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"UI server must bind to a loopback host (127.0.0.1, localhost, or ::1); got {host!r}"
        )
    return normalized


def _format_ui_url(host: str, port: int, token: str) -> str:
    host_part = "[::1]" if host == "::1" else host
    return f"http://{host_part}:{port}/?token={token}"


def _build_allowed_hosts(
    port: int,
    extra_allowed_hosts: Iterable[str] | None = None,
) -> set[str]:
    hosts = {
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        f"[::1]:{port}",
    }
    if extra_allowed_hosts is not None:
        for item in extra_allowed_hosts:
            cleaned = item.strip().lower()
            if cleaned:
                hosts.add(cleaned)
    return hosts


def _build_allowed_origins(
    port: int,
    extra_allowed_origins: Iterable[str] | None = None,
) -> set[str]:
    origins = {
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        f"http://[::1]:{port}",
    }
    if extra_allowed_origins is not None:
        for item in extra_allowed_origins:
            cleaned = item.strip().lower()
            if cleaned:
                origins.add(cleaned)
    return origins


_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none">'
    '<rect width="32" height="32" rx="8" fill="#0B1117"/>'
    '<path d="M16 4L26 8.2V15.4C26 21.4 21.7 26.2 16 28C10.3 26.2 6 21.4 6 15.4V8.2L16 4Z" '
    'stroke="#22D3EE" stroke-width="2" fill="#0F2633"/>'
    '<path d="M12.5 16L15 18.5L20 13.2" stroke="#34D399" stroke-width="2.2" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    "</svg>"
)


def _load_ui_asset(filename: str) -> str | None:
    try:
        resource = importlib.resources.files("mcp_guard.ui").joinpath(filename)
        if not resource.is_file():
            return None
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None


def _resolve_demo_server_path() -> Path | None:
    candidates = [
        Path(__file__).resolve().parents[3] / "demo" / "vulnerable_server.py",
        Path.cwd() / "demo" / "vulnerable_server.py",
        Path("/app/demo/vulnerable_server.py"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _normalized_tool_for_diff(tool: Any) -> dict[str, Any]:
    if not isinstance(tool, dict):
        return {"name": "", "description": "", "inputSchema": {}}
    schema = tool.get("inputSchema")
    return {
        "name": tool.get("name") if tool.get("name") is not None else "",
        "description": tool.get("description") if tool.get("description") is not None else "",
        "inputSchema": schema if schema is not None else {},
    }


def _compute_pin_diff(
    tool_name: str, pinned_rec: dict[str, Any], pending_rec: dict[str, Any]
) -> dict[str, Any]:
    pinned_tool = _normalized_tool_for_diff(pinned_rec.get("tool"))
    pending_tool = _normalized_tool_for_diff(pending_rec.get("tool"))
    pinned_lines = json.dumps(
        pinned_tool, indent=2, sort_keys=True, ensure_ascii=False
    ).splitlines()
    pending_lines = json.dumps(
        pending_tool, indent=2, sort_keys=True, ensure_ascii=False
    ).splitlines()
    diff_lines = list(
        difflib.unified_diff(
            pinned_lines,
            pending_lines,
            fromfile=f"{tool_name} (pinned)",
            tofile=f"{tool_name} (pending)",
            lineterm="",
        )
    )
    return {
        "tool_name": tool_name,
        "pinned_hash": str(pinned_rec.get("hash", "")),
        "pending_hash": str(pending_rec.get("hash", "")),
        "pinned_tool": pinned_tool,
        "pending_tool": pending_tool,
        "unified_diff": "\n".join(diff_lines) if diff_lines else "(schema hash changed)",
    }


def _deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _build_client_snippets(policy: PolicyConfig) -> dict[str, Any]:
    args: list[str] = ["wrap", "--mode", policy.mode.value]
    if policy.server_id:
        args.extend(["--server-id", policy.server_id])
    if policy.llm_judge.enabled:
        args.append("--llm-judge")
    args.extend(["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."])
    config_obj = {
        "mcpServers": {
            "filesystem-guarded": {
                "command": "mcp-guard",
                "args": args,
            }
        }
    }
    return {
        "claude_desktop": config_obj,
        "cursor": config_obj,
    }


def _split_stdio_command(raw_command: str) -> list[str]:
    """Split a STDIO command string, preserving backslashes on Windows paths."""
    is_windows = os.name == "nt"
    parts = shlex.split(raw_command, posix=not is_windows)
    if not is_windows:
        return parts
    cleaned: list[str] = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in ('"', "'"):
            cleaned.append(part[1:-1])
        else:
            cleaned.append(part)
    return [part for part in cleaned if part]


def _parse_scan_options(body: dict[str, Any]) -> tuple[int, float] | None:
    raw_probes = body.get("rug_pull_probes", 2)
    raw_timeout = body.get("timeout", 15.0)
    if isinstance(raw_probes, bool) or isinstance(raw_timeout, bool):
        return None
    try:
        probes = int(raw_probes)
        timeout = float(raw_timeout)
    except (TypeError, ValueError):
        return None
    if probes < 1 or probes > 10 or not math.isfinite(timeout) or timeout < 0.5 or timeout > 120.0:
        return None
    return probes, timeout


def _policy_response_payload(policy: PolicyConfig) -> dict[str, Any]:
    dumped = policy.model_dump(mode="json")
    return {
        "policy": dumped,
        "yaml": yaml.safe_dump(dumped, sort_keys=False),
        "snippets": _build_client_snippets(policy),
    }


class _UiState:
    def __init__(
        self,
        *,
        policy: PolicyConfig,
        event_bus: EventBus,
        pipeline: SecurityPipeline | None,
        pin_store: PinStore,
        allow_exec: bool,
        server_id: str,
        logger: logging.Logger,
        keepalive_seconds: float,
    ) -> None:
        self.policy = policy
        self.event_bus = event_bus
        self.pipeline = pipeline
        self.pin_store = pin_store
        self.allow_exec = allow_exec
        self.server_id = server_id
        self.logger = logger
        self.keepalive_seconds = keepalive_seconds
        self.latest_report: ScanReport | None = None


class _SecurityMiddleware:
    """Pure ASGI middleware enforcing Host allowlist, token/cookie auth, Origin checks, and CSP."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        token: str,
        allowed_hosts: set[str],
        allowed_origins: set[str],
    ) -> None:
        self.app = app
        self._token = token
        self._allowed_hosts = allowed_hosts
        self._allowed_origins = allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = _CSP_HEADER
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
            await send(message)

        request = Request(scope)
        host_hdr = request.headers.get("host", "").strip().lower()
        if host_hdr not in self._allowed_hosts:
            resp = JSONResponse({"error": "Forbidden Host header"}, status_code=403)
            await resp(scope, receive, send_with_headers)
            return

        if request.method == "GET" and request.url.path == "/" and "token" in request.query_params:
            query_token = request.query_params["token"]
            if not hmac.compare_digest(query_token, self._token):
                resp = JSONResponse({"error": "Invalid authentication token"}, status_code=401)
                await resp(scope, receive, send_with_headers)
                return
            redirect = RedirectResponse(url="/", status_code=302)
            redirect.set_cookie(
                key=_SESSION_COOKIE,
                value=self._token,
                httponly=True,
                samesite="strict",
                path="/",
            )
            await redirect(scope, receive, send_with_headers)
            return

        auth_hdr = request.headers.get("authorization", "")
        bearer_token: str | None = None
        if auth_hdr.lower().startswith("bearer "):
            bearer_token = auth_hdr[7:].strip()
        cookie_token = request.cookies.get(_SESSION_COOKIE)

        bearer_ok = bearer_token is not None and hmac.compare_digest(bearer_token, self._token)
        cookie_ok = cookie_token is not None and hmac.compare_digest(cookie_token, self._token)

        if not bearer_ok and not cookie_ok:
            resp = JSONResponse({"error": "Authentication required"}, status_code=401)
            await resp(scope, receive, send_with_headers)
            return

        if request.method in _MUTATING_METHODS:
            raw_origin = request.headers.get("origin")
            origin_norm = raw_origin.strip().lower() if raw_origin is not None else None
            if bearer_ok:
                if origin_norm is not None and origin_norm not in self._allowed_origins:
                    resp = JSONResponse({"error": "Forbidden Origin header"}, status_code=403)
                    await resp(scope, receive, send_with_headers)
                    return
            elif not origin_norm or origin_norm not in self._allowed_origins:
                resp = JSONResponse(
                    {"error": "Missing or forbidden Origin header"},
                    status_code=403,
                )
                await resp(scope, receive, send_with_headers)
                return

        await self.app(scope, receive, send_with_headers)


def _matches_query(event: dict[str, Any], query: str) -> bool:
    needle = query.lower()
    fields: list[str] = [
        str(event.get("method", "")),
        str(event.get("tool_name") or ""),
        str(event.get("uri") or ""),
        str(event.get("summary", "")),
        str(event.get("server_id", "")),
        str(event.get("action", "")),
    ]
    findings = event.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict):
                fields.extend(
                    [
                        str(item.get("rule_id", "")),
                        str(item.get("detector", "")),
                        str(item.get("title", "")),
                        str(item.get("target", "")),
                    ]
                )
    return any(needle in value.lower() for value in fields if value)


def _filter_events(
    events: list[dict[str, Any]],
    *,
    action: str | None,
    severity: str | None,
    query: str | None,
) -> list[dict[str, Any]]:
    action_norm = action.strip().lower() if action else ""
    severity_norm = severity.strip().lower() if severity else ""
    query_norm = query.strip() if query else ""

    filtered: list[dict[str, Any]] = []
    for event in events:
        if (
            action_norm
            and action_norm != "all"
            and str(event.get("action", "")).lower() != action_norm
        ):
            continue
        if severity_norm and severity_norm != "all":
            ev_sev = str(event.get("max_severity") or "").lower()
            findings = event.get("findings")
            has_finding_sev = isinstance(findings, list) and any(
                isinstance(f, dict) and str(f.get("severity", "")).lower() == severity_norm
                for f in findings
            )
            if ev_sev != severity_norm and not has_finding_sev:
                continue
        if query_norm and not _matches_query(event, query_norm):
            continue
        filtered.append(event)
    return filtered


def create_ui_app(
    *,
    policy: PolicyConfig | None = None,
    event_bus: EventBus | None = None,
    pipeline: SecurityPipeline | None = None,
    pin_file: str | Path | None = None,
    server_id: str | None = None,
    token: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8766,
    allow_exec: bool = False,
    extra_allowed_hosts: Iterable[str] | None = None,
    extra_allowed_origins: Iterable[str] | None = None,
    allowed_hosts_ref: set[str] | None = None,
    allowed_origins_ref: set[str] | None = None,
    logger: logging.Logger | None = None,
    keepalive_seconds: float = 15.0,
) -> Starlette:
    """Create the hardened Starlette Web UI ASGI application."""
    validate_loopback_host(host)
    eff_policy = policy or (pipeline.policy if pipeline is not None else PolicyConfig())
    eff_bus = event_bus or EventBus()
    eff_logger = logger or configure_logger("mcp_guard.ui")
    eff_token = token if token is not None else secrets.token_urlsafe(32)

    if pipeline is not None and pin_file is None:
        eff_pin_store = pipeline.pinner.store
    else:
        eff_pin_store = PinStore(pin_file if pin_file is not None else eff_policy.pinning.pin_file)

    eff_server_id = (
        server_id
        or (pipeline.server_id if pipeline is not None else None)
        or eff_policy.server_id
        or "standalone"
    )

    state = _UiState(
        policy=eff_policy,
        event_bus=eff_bus,
        pipeline=pipeline,
        pin_store=eff_pin_store,
        allow_exec=allow_exec,
        server_id=eff_server_id,
        logger=eff_logger,
        keepalive_seconds=keepalive_seconds,
    )

    allowed_hosts = (
        allowed_hosts_ref
        if allowed_hosts_ref is not None
        else _build_allowed_hosts(port, extra_allowed_hosts)
    )
    if allowed_hosts_ref is not None and extra_allowed_hosts is not None:
        for item in extra_allowed_hosts:
            cleaned = item.strip().lower()
            if cleaned:
                allowed_hosts.add(cleaned)

    allowed_origins = (
        allowed_origins_ref
        if allowed_origins_ref is not None
        else _build_allowed_origins(port, extra_allowed_origins)
    )
    if allowed_origins_ref is not None and extra_allowed_origins is not None:
        for item in extra_allowed_origins:
            cleaned = item.strip().lower()
            if cleaned:
                allowed_origins.add(cleaned)

    async def index_page(_request: Request) -> Response:
        html = _load_ui_asset("index.html")
        if html is None:
            return JSONResponse({"error": "UI index.html asset not found"}, status_code=404)
        return HTMLResponse(html)

    async def static_css(_request: Request) -> Response:
        css = _load_ui_asset("styles.css")
        if css is None:
            return JSONResponse({"error": "UI styles.css asset not found"}, status_code=404)
        return Response(content=css, media_type="text/css; charset=utf-8")

    async def static_js(_request: Request) -> Response:
        js = _load_ui_asset("app.js")
        if js is None:
            return JSONResponse({"error": "UI app.js asset not found"}, status_code=404)
        return Response(content=js, media_type="application/javascript; charset=utf-8")

    async def favicon_svg(_request: Request) -> Response:
        return Response(content=_FAVICON_SVG, media_type="image/svg+xml; charset=utf-8")

    async def api_status(_request: Request) -> JSONResponse:
        events = state.event_bus.history(limit=500)
        counts: dict[str, int] = {
            "total": len(events),
            "allow": 0,
            "block": 0,
            "redact": 0,
            "strip_tool": 0,
            "log": 0,
        }
        for ev in events:
            act = str(ev.get("action", "allow")).lower()
            if act in counts:
                counts[act] += 1
        return JSONResponse(
            {
                "status": "ok",
                "mode": state.policy.mode.value,
                "runtime_mode": "proxy" if state.pipeline is not None else "standalone",
                "embedded": state.pipeline is not None,
                "server_id": state.server_id,
                "allow_exec": state.allow_exec,
                "pin_file": str(state.pin_store.pin_file),
                "event_count": len(events),
                "counts": counts,
                "has_latest_scan": state.latest_report is not None,
            }
        )

    async def api_history(request: Request) -> JSONResponse:
        raw_limit = request.query_params.get("limit", "500")
        try:
            limit = max(1, min(500, int(raw_limit)))
        except ValueError:
            limit = 500
        events = state.event_bus.history(limit=limit)
        filtered = _filter_events(
            events,
            action=request.query_params.get("action"),
            severity=request.query_params.get("severity"),
            query=request.query_params.get("q"),
        )
        return JSONResponse({"events": filtered, "total": len(filtered)})

    async def api_events(_request: Request) -> StreamingResponse:
        async def event_stream() -> AsyncIterator[str]:
            queue = state.event_bus.subscribe()
            try:
                for event in state.event_bus.history():
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                while True:
                    try:
                        event = await asyncio.wait_for(
                            queue.get(),
                            timeout=state.keepalive_seconds,
                        )
                        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    except TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                state.event_bus.unsubscribe(queue)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    async def api_pins(request: Request) -> JSONResponse:
        target_sid = request.query_params.get("server_id") or None
        try:
            raw_servers = state.pin_store.list_pins(server_id=target_sid)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        enriched: dict[str, Any] = {}
        for sid, entry in raw_servers.items():
            if not isinstance(entry, dict):
                continue
            tools = entry.get("tools", {})
            pending = entry.get("pending", {})
            diffs: dict[str, Any] = {}
            if isinstance(tools, dict) and isinstance(pending, dict):
                for tool_name, pending_rec in pending.items():
                    pinned_rec = tools.get(tool_name)
                    if isinstance(pinned_rec, dict) and isinstance(pending_rec, dict):
                        diffs[tool_name] = _compute_pin_diff(tool_name, pinned_rec, pending_rec)
            enriched[sid] = {
                "tools": tools if isinstance(tools, dict) else {},
                "pending": pending if isinstance(pending, dict) else {},
                "diffs": diffs,
            }

        return JSONResponse(
            {
                "pin_file": str(state.pin_store.pin_file),
                "servers": enriched,
            }
        )

    async def _read_optional_json(request: Request) -> dict[str, Any] | None:
        raw = await request.body()
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    async def api_pins_approve(request: Request) -> JSONResponse:
        body = await _read_optional_json(request)
        if body is None:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        target_sid = body.get("server_id")
        target_tool = body.get("tool_name") or body.get("tool")
        try:
            approved = state.pin_store.approve(
                server_id=str(target_sid) if target_sid else None,
                tool_name=str(target_tool) if target_tool else None,
            )
            servers = state.pin_store.list_pins()
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse({"approved": approved, "servers": servers})

    async def api_pins_reset(request: Request) -> JSONResponse:
        body = await _read_optional_json(request)
        if body is None:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        target_sid = body.get("server_id")
        sid_str = str(target_sid) if target_sid else None
        try:
            cleared = state.pin_store.reset(server_id=sid_str)
            if state.pipeline is not None:
                state.pipeline.pinner.reset_session(server_id=sid_str)
            servers = state.pin_store.list_pins()
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse({"cleared": cleared, "servers": servers})

    async def _execute_scan(
        *,
        kind: str,
        target: str | list[str] | None,
        rug_pull_probes: int,
        timeout: float,
    ) -> Response:
        scan_policy = state.policy.model_copy(
            update={
                "pinning": state.policy.pinning.model_copy(
                    update={"pin_file": str(state.pin_store.pin_file)}
                )
            }
        )
        scanner = ActiveScanner(scan_policy, logger=state.logger)

        if kind == "demo":
            demo_path = _resolve_demo_server_path()
            if demo_path is None:
                return JSONResponse(
                    {"error": "Demo vulnerable_server.py could not be found"},
                    status_code=404,
                )
            report = await scanner.scan_stdio(
                [sys.executable, str(demo_path)],
                rug_pull_probes=rug_pull_probes,
                timeout=timeout,
            )
        elif kind == "stdio":
            if not state.allow_exec:
                return JSONResponse(
                    {"error": "STDIO scanning is disabled; restart with --allow-exec to enable"},
                    status_code=403,
                )
            if isinstance(target, list):
                cmd = [str(part) for part in target if str(part)]
            elif isinstance(target, str):
                try:
                    cmd = _split_stdio_command(target)
                except ValueError as exc:
                    return JSONResponse(
                        {"error": f"Invalid command string: {exc}"}, status_code=400
                    )
            else:
                cmd = []
            if not cmd:
                return JSONResponse({"error": "Missing STDIO command for scan"}, status_code=400)
            report = await scanner.scan_stdio(
                cmd,
                rug_pull_probes=rug_pull_probes,
                timeout=timeout,
            )
        elif kind == "http":
            if not isinstance(target, str) or not target.strip():
                return JSONResponse({"error": "Missing target URL for HTTP scan"}, status_code=400)
            url = target.strip()
            if not (url.startswith("http://") or url.startswith("https://")):
                return JSONResponse(
                    {"error": "HTTP scan URL must start with http:// or https://"},
                    status_code=400,
                )
            report = await scanner.scan_http(
                url,
                rug_pull_probes=rug_pull_probes,
                timeout=timeout,
            )
        else:
            return JSONResponse(
                {"error": f"Unsupported scan kind {kind!r}; expected demo, http, or stdio"},
                status_code=400,
            )

        state.latest_report = report
        finding_dicts = [
            {
                "rule_id": finding.rule_id,
                "detector": finding.detector,
                "severity": finding.severity.value,
                "title": finding.title,
                "target": finding.target,
                "action_taken": finding.action_taken.value,
            }
            for finding in report.findings
        ]
        max_sev = (
            max(report.findings, key=lambda f: f.severity.rank).severity.value
            if report.findings
            else None
        )
        state.event_bus.publish(
            SecurityEvent(
                direction="scan",
                method=f"scan/{kind}",
                tool_name=None,
                uri=report.target,
                allowed=len(report.findings) == 0,
                action="block" if report.findings else "allow",
                max_severity=max_sev,
                findings=finding_dicts,
                summary=(
                    f"Scan ({kind}) of {report.target}: {len(report.findings)} finding(s) "
                    f"across {report.tools_scanned} tool(s)"
                ),
                server_id=report.server_id,
            ).model_dump(mode="json")
        )
        return JSONResponse(report.model_dump(mode="json"))

    async def api_scan(request: Request) -> Response:
        body = await _read_optional_json(request)
        if body is None:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        kind = str(body.get("kind", "")).strip().lower()
        if not kind:
            return JSONResponse({"error": "Missing required 'kind' field"}, status_code=400)
        target: str | list[str] | None = None
        if kind == "http":
            raw_url = body.get("url") if body.get("url") is not None else body.get("target")
            target = str(raw_url) if raw_url is not None else None
        elif kind == "stdio":
            raw_cmd = body.get("command") if body.get("command") is not None else body.get("target")
            if isinstance(raw_cmd, list):
                target = [str(part) for part in raw_cmd]
            elif raw_cmd is not None:
                target = str(raw_cmd)

        parsed_opts = _parse_scan_options(body)
        if parsed_opts is None:
            return JSONResponse({"error": "Invalid scan numeric parameter"}, status_code=400)
        probes, timeout = parsed_opts

        return await _execute_scan(
            kind=kind,
            target=target,
            rug_pull_probes=probes,
            timeout=timeout,
        )

    async def api_demo(request: Request) -> Response:
        body = await _read_optional_json(request)
        if body is None:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        parsed_opts = _parse_scan_options(body)
        if parsed_opts is None:
            return JSONResponse({"error": "Invalid demo parameter"}, status_code=400)
        probes, timeout = parsed_opts
        return await _execute_scan(
            kind="demo",
            target=None,
            rug_pull_probes=probes,
            timeout=timeout,
        )

    async def api_export_latest_scan(request: Request) -> Response:
        if state.latest_report is None:
            return JSONResponse({"error": "No scan report available yet"}, status_code=404)
        fmt = request.query_params.get("format", "json").strip().lower()
        if fmt == "json":
            return Response(
                content=render_json_report(state.latest_report),
                media_type="application/json; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="mcp-guard-report.json"'},
            )
        if fmt in ("markdown", "md"):
            return Response(
                content=render_markdown_report(state.latest_report),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="mcp-guard-report.md"'},
            )
        if fmt == "sarif":
            return Response(
                content=render_sarif_report(state.latest_report),
                media_type="application/sarif+json; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="mcp-guard-report.sarif"'},
            )
        return JSONResponse(
            {"error": f"Unsupported export format {fmt!r}; expected json, markdown, or sarif"},
            status_code=400,
        )

    async def api_get_policy(_request: Request) -> JSONResponse:
        return JSONResponse(_policy_response_payload(state.policy))

    async def api_post_policy(request: Request) -> JSONResponse:
        body = await _read_optional_json(request)
        if body is None:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

        patch = body["policy"] if isinstance(body.get("policy"), dict) else body
        current_dict = state.policy.model_dump(mode="python")
        merged = _deep_merge(current_dict, patch)
        try:
            updated = PolicyConfig.model_validate(merged)
        except ValidationError as exc:
            return JSONResponse({"error": f"Invalid policy configuration: {exc}"}, status_code=400)

        if (
            updated.rate_limit.requests_per_minute < 0
            or updated.rate_limit.burst < 0
            or not math.isfinite(updated.response_guard.entropy_threshold)
            or not (0.0 <= updated.response_guard.entropy_threshold <= 8.0)
        ):
            return JSONResponse(
                {"error": "Invalid policy configuration: numeric threshold out of range"},
                status_code=400,
            )

        state.policy = updated
        if state.pipeline is not None:
            state.pipeline.update_policy(updated)
        return JSONResponse(_policy_response_payload(updated))

    routes = [
        Route("/", endpoint=index_page, methods=["GET"]),
        Route("/favicon.svg", endpoint=favicon_svg, methods=["GET"]),
        Route("/static/styles.css", endpoint=static_css, methods=["GET"]),
        Route("/static/app.js", endpoint=static_js, methods=["GET"]),
        Route("/api/status", endpoint=api_status, methods=["GET"]),
        Route("/api/history", endpoint=api_history, methods=["GET"]),
        Route("/api/events", endpoint=api_events, methods=["GET"]),
        Route("/api/pins", endpoint=api_pins, methods=["GET"]),
        Route("/api/pins/approve", endpoint=api_pins_approve, methods=["POST"]),
        Route("/api/pins/reset", endpoint=api_pins_reset, methods=["POST"]),
        Route("/api/scan", endpoint=api_scan, methods=["POST"]),
        Route("/api/demo", endpoint=api_demo, methods=["POST"]),
        Route("/api/scans/latest/export", endpoint=api_export_latest_scan, methods=["GET"]),
        Route("/api/policy", endpoint=api_get_policy, methods=["GET"]),
        Route("/api/policy", endpoint=api_post_policy, methods=["POST"]),
    ]

    app = Starlette(routes=routes)
    app.add_middleware(
        _SecurityMiddleware,
        token=eff_token,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )
    app.state.token = eff_token
    app.state.auth_token = eff_token
    app.state.allowed_hosts = allowed_hosts
    app.state.allowed_origins = allowed_origins
    app.state.ui_state = state
    app.state.event_bus = eff_bus
    return app


def _bind_loopback_socket(
    host: str,
    port: int,
    logger: logging.Logger,
) -> socket.socket | None:
    """Bind a loopback TCP socket, respecting Windows port-collision semantics."""
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    bind_host = "127.0.0.1" if host == "localhost" else host

    def _try_bind(target_port: int) -> socket.socket:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            # On Windows, SO_REUSEADDR allows binding an already-bound port cleanly without error,
            # masking port collisions; only enable SO_REUSEADDR on POSIX systems.
            if os.name != "nt":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.bind((bind_host, target_port, 0, 0))
            else:
                sock.bind((bind_host, target_port))
            sock.listen(128)
            sock.setblocking(False)
            return sock
        except OSError:
            sock.close()
            raise

    try:
        return _try_bind(port)
    except OSError as exc:
        if port == 0:
            logger.warning("Failed to bind UI server socket on %s:0: %s", host, exc)
            return None
        logger.warning(
            "UI port %s:%d unavailable (%s); falling back to ephemeral port",
            host,
            port,
            exc,
        )
        try:
            return _try_bind(0)
        except OSError as fallback_exc:
            logger.warning(
                "Failed to bind ephemeral UI socket on %s (%s); continuing without Web UI",
                host,
                fallback_exc,
            )
            return None


class _EmbeddedUvicornServer(uvicorn.Server):
    """Uvicorn server subclass that leaves signal handlers to the parent proxy process."""

    def install_signal_handlers(self) -> None:
        return None


async def start_embedded_ui_server(
    *,
    policy: PolicyConfig | None = None,
    event_bus: EventBus | None = None,
    pipeline: SecurityPipeline | None = None,
    pin_file: str | Path | None = None,
    server_id: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8766,
    token: str | None = None,
    allow_exec: bool = False,
    extra_allowed_hosts: Iterable[str] | None = None,
    extra_allowed_origins: Iterable[str] | None = None,
    logger: logging.Logger | None = None,
) -> EmbeddedUiHandle | None:
    """Start the embedded Web UI on a pre-bound loopback socket; return None if bind fails."""
    validated_host = validate_loopback_host(host)
    eff_logger = logger or configure_logger("mcp_guard.ui")
    eff_token = token if token is not None else secrets.token_urlsafe(32)

    sock = _bind_loopback_socket(validated_host, port, eff_logger)
    if sock is None:
        return None

    bound_port = int(sock.getsockname()[1])
    allowed_hosts = _build_allowed_hosts(bound_port, extra_allowed_hosts)
    allowed_origins = _build_allowed_origins(bound_port, extra_allowed_origins)

    app = create_ui_app(
        policy=policy,
        event_bus=event_bus,
        pipeline=pipeline,
        pin_file=pin_file,
        server_id=server_id,
        token=eff_token,
        host=validated_host,
        port=bound_port,
        allow_exec=allow_exec,
        allowed_hosts_ref=allowed_hosts,
        allowed_origins_ref=allowed_origins,
        logger=eff_logger,
    )

    config = uvicorn.Config(
        app,
        host=validated_host,
        port=bound_port,
        log_config=None,
        access_log=False,
        log_level="warning",
    )
    server = _EmbeddedUvicornServer(config)
    task = asyncio.create_task(server.serve(sockets=[sock]))

    loop = asyncio.get_running_loop()
    deadline = loop.time() + 2.0
    while not server.started and not task.done() and loop.time() < deadline:
        await asyncio.sleep(0.01)

    if task.done():
        exc = task.exception()
        eff_logger.warning("Embedded UI server exited prematurely: %s", exc)
        with contextlib.suppress(OSError):
            sock.close()
        return None

    url = _format_ui_url(validated_host, bound_port, eff_token)
    return EmbeddedUiHandle(
        server=server,
        task=task,
        host=validated_host,
        port=bound_port,
        token=eff_token,
        url=url,
    )


def run_ui_server(
    *,
    policy: PolicyConfig | None = None,
    event_bus: EventBus | None = None,
    pipeline: SecurityPipeline | None = None,
    pin_file: str | Path | None = None,
    server_id: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8766,
    token: str | None = None,
    allow_exec: bool = False,
    logger: logging.Logger | None = None,
    on_ready: Callable[[str], None] | None = None,
) -> None:
    """Run the standalone MCP-Guard Web UI server in the foreground."""
    validated_host = validate_loopback_host(host)
    eff_logger = logger or configure_logger("mcp_guard.ui")
    eff_token = token if token is not None else secrets.token_urlsafe(32)

    sock = _bind_loopback_socket(validated_host, port, eff_logger)
    if sock is None:
        raise RuntimeError(f"Unable to bind MCP-Guard Web UI socket on {validated_host}:{port}")

    bound_port = int(sock.getsockname()[1])
    allowed_hosts = _build_allowed_hosts(bound_port)
    allowed_origins = _build_allowed_origins(bound_port)

    app = create_ui_app(
        policy=policy,
        event_bus=event_bus,
        pipeline=pipeline,
        pin_file=pin_file,
        server_id=server_id,
        token=eff_token,
        host=validated_host,
        port=bound_port,
        allow_exec=allow_exec,
        allowed_hosts_ref=allowed_hosts,
        allowed_origins_ref=allowed_origins,
        logger=eff_logger,
    )

    url = _format_ui_url(validated_host, bound_port, eff_token)
    eff_logger.info("MCP-Guard Web UI listening at %s", url)
    if on_ready is not None:
        on_ready(url)

    config = uvicorn.Config(
        app,
        host=validated_host,
        port=bound_port,
        log_config=None,
        access_log=False,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(server.serve(sockets=[sock]))
