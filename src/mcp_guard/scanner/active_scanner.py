"""Active MCP server scanner over STDIO and Streamable HTTP / SSE."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from collections.abc import Sequence
from typing import Any

import httpx

from mcp_guard.engine.pipeline import SecurityPipeline
from mcp_guard.models.findings import ScanReport, SecurityFinding
from mcp_guard.models.jsonrpc import parse_jsonrpc_frame
from mcp_guard.models.policy import PolicyConfig
from mcp_guard.utils.canonical import normalize_server_id
from mcp_guard.utils.logging import configure_logger

_PROTOCOL_VERSION = "2024-11-05"
_METHOD_NOT_FOUND = -32601
_MAX_STDIO_LINE_BYTES = 16 * 1024 * 1024


def _finding_dedup_key(finding: SecurityFinding) -> tuple[str, str, str, str, str, str]:
    return (
        finding.rule_id,
        finding.detector,
        finding.target,
        finding.title,
        finding.evidence,
        finding.description,
    )


def _extract_error_info(resp: dict[str, Any]) -> tuple[int | None, str]:
    err = resp.get("error")
    if not isinstance(err, dict):
        return None, "Unknown JSON-RPC error"
    code = err.get("code")
    msg = err.get("message", "Unknown JSON-RPC error")
    return (code if isinstance(code, int) and not isinstance(code, bool) else None), str(msg)


def _parse_sse_messages(body: str) -> list[dict[str, Any]]:
    """Extract JSON-RPC objects from an SSE response body."""
    messages: list[dict[str, Any]] = []
    normalized = body.replace("\r\n", "\n")
    for block in normalized.split("\n\n"):
        if not block.strip():
            continue
        data_lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
        if not data_lines:
            continue
        payload = "\n".join(data_lines).strip()
        if not payload or payload == "[DONE]":
            continue
        parsed = parse_jsonrpc_frame(payload)
        if isinstance(parsed, list):
            messages.extend(parsed)
        else:
            messages.append(parsed)
    return messages


def _select_matching_response(
    messages: list[dict[str, Any]],
    req_id: int,
) -> dict[str, Any]:
    for msg in messages:
        if msg.get("id") == req_id:
            return msg
    for msg in messages:
        if "result" in msg or "error" in msg:
            return msg
    if messages:
        return messages[0]
    raise ValueError("No JSON-RPC response message found in HTTP/SSE payload")


class _FindingCollector:
    """Deduplicates identical findings across probes while preserving new findings."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str, str, str, str, str]] = set()
        self.findings: list[SecurityFinding] = []

    def extend(self, new_findings: list[SecurityFinding]) -> None:
        for finding in new_findings:
            key = _finding_dedup_key(finding)
            if key not in self._seen:
                self._seen.add(key)
                self.findings.append(finding)


class ActiveScanner:
    """Connects to an MCP server over STDIO or HTTP, probes capabilities, and scans metadata."""

    def __init__(self, policy: PolicyConfig, *, logger: logging.Logger | None = None) -> None:
        self.policy = policy
        self._logger = logger or configure_logger("mcp_guard.scanner")

    async def scan_stdio(
        self,
        command: Sequence[str],
        *,
        rug_pull_probes: int = 2,
        timeout: float = 15.0,
    ) -> ScanReport:
        """Spawn a STDIO MCP server, probe tools/prompts/resources, and return a ScanReport."""
        if not command:
            raise ValueError("command must not be empty")
        if rug_pull_probes < 1:
            raise ValueError("rug_pull_probes must be >= 1")

        cmd_list = [str(part) for part in command]
        server_id = self.policy.server_id or normalize_server_id(cmd_list)
        target = " ".join(cmd_list)

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        proc: asyncio.subprocess.Process | None = None
        stderr_task: asyncio.Task[None] | None = None
        stderr_lines: list[str] = []
        errors: list[str] = []
        collector = _FindingCollector()
        server_info: dict[str, Any] = {}
        tools_scanned = 0
        prompts_scanned = 0
        resources_scanned = 0

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                limit=_MAX_STDIO_LINE_BYTES,
            )
            if proc.stdin is None or proc.stdout is None or proc.stderr is None:
                raise RuntimeError("Subprocess pipes were not created")

            stderr_task = asyncio.create_task(self._drain_stderr(proc.stderr, stderr_lines))

            pipeline = SecurityPipeline(
                self.policy,
                server_id=server_id,
                logger=self._logger,
            )

            deadline = time.monotonic() + timeout
            req_counter = 0

            async def _remaining() -> float:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"Scan timed out after {timeout:.1f}s")
                return rem

            async def _send_msg(payload: dict[str, Any]) -> None:
                assert proc is not None and proc.stdin is not None
                encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
                proc.stdin.write(encoded)
                await asyncio.wait_for(proc.stdin.drain(), timeout=await _remaining())

            async def _read_response(expected_id: int) -> dict[str, Any]:
                assert proc is not None and proc.stdout is not None
                while True:
                    raw_line = await asyncio.wait_for(
                        proc.stdout.readline(),
                        timeout=await _remaining(),
                    )
                    if not raw_line:
                        tail = " | ".join(stderr_lines[-5:]) if stderr_lines else "no stderr output"
                        raise EOFError(
                            "MCP server closed stdout unexpectedly while waiting for "
                            f"id={expected_id} ({tail})"
                        )
                    stripped = raw_line.rstrip(b"\r\n")
                    if not stripped:
                        continue
                    parsed = parse_jsonrpc_frame(stripped)
                    if isinstance(parsed, list):
                        for item in parsed:
                            if item.get("id") == expected_id:
                                return item
                        continue
                    if "id" not in parsed:
                        # Server-initiated notification; keep reading for our response.
                        continue
                    if parsed.get("id") == expected_id or parsed.get("id") is None:
                        return parsed

            async def _rpc_call(
                method: str,
                params: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                nonlocal req_counter
                req_counter += 1
                req_id = req_counter
                msg: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": method,
                    "params": params if params is not None else {},
                }
                await _send_msg(msg)
                return await _read_response(req_id)

            # 1. initialize
            init_resp = await _rpc_call(
                "initialize",
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-guard", "version": "0.1.0"},
                },
            )
            if "error" in init_resp and init_resp.get("error") is not None:
                code, msg = _extract_error_info(init_resp)
                errors.append(f"initialize failed ({code}): {msg}")
            else:
                init_result = init_resp.get("result")
                if isinstance(init_result, dict):
                    info = init_result.get("serverInfo")
                    if isinstance(info, dict):
                        server_info = dict(info)

            # 2. notifications/initialized
            await _send_msg(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                }
            )

            # 3. tools/list (x rug_pull_probes)
            seen_tool_names: set[str] = set()
            max_tools_in_probe = 0
            for probe_idx in range(rug_pull_probes):
                tools_resp = await _rpc_call("tools/list")
                if "error" in tools_resp and tools_resp.get("error") is not None:
                    code, msg = _extract_error_info(tools_resp)
                    if code == _METHOD_NOT_FOUND:
                        break
                    errors.append(f"tools/list probe {probe_idx + 1} failed ({code}): {msg}")
                    break

                result = tools_resp.get("result")
                if isinstance(result, dict) and isinstance(result.get("tools"), list):
                    raw_tools = [t for t in result["tools"] if isinstance(t, dict)]
                    max_tools_in_probe = max(max_tools_in_probe, len(raw_tools))
                    for tool in raw_tools:
                        name = tool.get("name")
                        if isinstance(name, str) and name:
                            seen_tool_names.add(name)
                    decision = await pipeline.inspect_response(tools_resp, method="tools/list")
                    collector.extend(decision.findings)

            tools_scanned = len(seen_tool_names) if seen_tool_names else max_tools_in_probe

            # 4. prompts/list
            prompts_resp = await _rpc_call("prompts/list")
            if "error" in prompts_resp and prompts_resp.get("error") is not None:
                code, msg = _extract_error_info(prompts_resp)
                if code != _METHOD_NOT_FOUND:
                    errors.append(f"prompts/list failed ({code}): {msg}")
            else:
                result = prompts_resp.get("result")
                if isinstance(result, dict) and isinstance(result.get("prompts"), list):
                    raw_prompts = [p for p in result["prompts"] if isinstance(p, dict)]
                    prompts_scanned = len(raw_prompts)
                    decision = await pipeline.inspect_response(prompts_resp, method="prompts/list")
                    collector.extend(decision.findings)

            # 5. resources/list
            resources_resp = await _rpc_call("resources/list")
            if "error" in resources_resp and resources_resp.get("error") is not None:
                code, msg = _extract_error_info(resources_resp)
                if code != _METHOD_NOT_FOUND:
                    errors.append(f"resources/list failed ({code}): {msg}")
            else:
                result = resources_resp.get("result")
                if isinstance(result, dict) and isinstance(result.get("resources"), list):
                    raw_resources = [r for r in result["resources"] if isinstance(r, dict)]
                    resources_scanned = len(raw_resources)
                    decision = await pipeline.inspect_response(
                        resources_resp, method="resources/list"
                    )
                    collector.extend(decision.findings)

        except (OSError, TimeoutError, EOFError, ValueError, RuntimeError) as exc:
            errors.append(str(exc))
        finally:
            if proc is not None:
                if proc.stdin is not None and not proc.stdin.is_closing():
                    with contextlib.suppress(OSError):
                        proc.stdin.close()
                if proc.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                    except TimeoutError:
                        with contextlib.suppress(ProcessLookupError):
                            proc.kill()
                        with contextlib.suppress(ProcessLookupError):
                            await proc.wait()
            if stderr_task is not None and not stderr_task.done():
                stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)

        return ScanReport(
            target=target,
            server_id=server_id,
            server_info=server_info,
            tools_scanned=tools_scanned,
            prompts_scanned=prompts_scanned,
            resources_scanned=resources_scanned,
            findings=collector.findings,
            errors=errors,
        )

    async def scan_http(
        self,
        url: str,
        *,
        rug_pull_probes: int = 2,
        timeout: float = 15.0,
        headers: dict[str, str] | None = None,
    ) -> ScanReport:
        """Probe a Streamable HTTP / SSE MCP server and return a ScanReport."""
        if not url.strip():
            raise ValueError("url must not be empty")
        if rug_pull_probes < 1:
            raise ValueError("rug_pull_probes must be >= 1")

        server_id = self.policy.server_id or normalize_server_id(url)
        pipeline = SecurityPipeline(
            self.policy,
            server_id=server_id,
            logger=self._logger,
        )

        collector = _FindingCollector()
        errors: list[str] = []
        server_info: dict[str, Any] = {}
        tools_scanned = 0
        prompts_scanned = 0
        resources_scanned = 0

        base_headers: dict[str, str] = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if headers:
            base_headers.update(headers)

        session_id: str | None = None
        protocol_version: str | None = None
        req_counter = 0

        async def _post_rpc(
            client: httpx.AsyncClient,
            payload: dict[str, Any],
            *,
            expect_response: bool,
        ) -> dict[str, Any] | None:
            nonlocal session_id
            req_headers = dict(base_headers)
            if session_id:
                req_headers["Mcp-Session-Id"] = session_id
            if protocol_version:
                req_headers["MCP-Protocol-Version"] = protocol_version

            response = await client.post(url, json=payload, headers=req_headers)
            resp_session = response.headers.get("mcp-session-id")
            if resp_session:
                session_id = resp_session

            if (
                not expect_response
                and response.status_code in (200, 202, 204)
                and not response.content.strip()
            ):
                return None

            response.raise_for_status()
            if not response.content.strip():
                if expect_response:
                    raise ValueError(f"Empty HTTP response body for method {payload.get('method')}")
                return None

            content_type = response.headers.get("content-type", "").lower()
            if "text/event-stream" in content_type:
                messages = _parse_sse_messages(response.text)
                req_id = payload.get("id")
                if isinstance(req_id, int):
                    return _select_matching_response(messages, req_id)
                return messages[0] if messages else None

            parsed = parse_jsonrpc_frame(response.content)
            if isinstance(parsed, list):
                req_id = payload.get("id")
                if isinstance(req_id, int):
                    return _select_matching_response(parsed, req_id)
                return parsed[0]
            return parsed

        async def _rpc_call(
            client: httpx.AsyncClient,
            method: str,
            params: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            nonlocal req_counter
            req_counter += 1
            req_id = req_counter
            payload: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params if params is not None else {},
            }
            resp = await _post_rpc(client, payload, expect_response=True)
            if resp is None:
                raise ValueError(f"Missing JSON-RPC response for {method}")
            return resp

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                # 1. initialize
                init_resp = await _rpc_call(
                    client,
                    "initialize",
                    {
                        "protocolVersion": _PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-guard", "version": "0.1.0"},
                    },
                )
                if "error" in init_resp and init_resp.get("error") is not None:
                    code, msg = _extract_error_info(init_resp)
                    errors.append(f"initialize failed ({code}): {msg}")
                else:
                    init_result = init_resp.get("result")
                    if isinstance(init_result, dict):
                        if isinstance(init_result.get("serverInfo"), dict):
                            server_info = dict(init_result["serverInfo"])
                        proto = init_result.get("protocolVersion")
                        if isinstance(proto, str) and proto:
                            protocol_version = proto

                # 2. notifications/initialized
                await _post_rpc(
                    client,
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                    expect_response=False,
                )

                # 3. tools/list (x rug_pull_probes)
                seen_tool_names: set[str] = set()
                max_tools_in_probe = 0
                for probe_idx in range(rug_pull_probes):
                    tools_resp = await _rpc_call(client, "tools/list")
                    if "error" in tools_resp and tools_resp.get("error") is not None:
                        code, msg = _extract_error_info(tools_resp)
                        if code == _METHOD_NOT_FOUND:
                            break
                        errors.append(f"tools/list probe {probe_idx + 1} failed ({code}): {msg}")
                        break

                    result = tools_resp.get("result")
                    if isinstance(result, dict) and isinstance(result.get("tools"), list):
                        raw_tools = [t for t in result["tools"] if isinstance(t, dict)]
                        max_tools_in_probe = max(max_tools_in_probe, len(raw_tools))
                        for tool in raw_tools:
                            name = tool.get("name")
                            if isinstance(name, str) and name:
                                seen_tool_names.add(name)
                        decision = await pipeline.inspect_response(tools_resp, method="tools/list")
                        collector.extend(decision.findings)

                tools_scanned = len(seen_tool_names) if seen_tool_names else max_tools_in_probe

                # 4. prompts/list
                prompts_resp = await _rpc_call(client, "prompts/list")
                if "error" in prompts_resp and prompts_resp.get("error") is not None:
                    code, msg = _extract_error_info(prompts_resp)
                    if code != _METHOD_NOT_FOUND:
                        errors.append(f"prompts/list failed ({code}): {msg}")
                else:
                    result = prompts_resp.get("result")
                    if isinstance(result, dict) and isinstance(result.get("prompts"), list):
                        raw_prompts = [p for p in result["prompts"] if isinstance(p, dict)]
                        prompts_scanned = len(raw_prompts)
                        decision = await pipeline.inspect_response(
                            prompts_resp, method="prompts/list"
                        )
                        collector.extend(decision.findings)

                # 5. resources/list
                resources_resp = await _rpc_call(client, "resources/list")
                if "error" in resources_resp and resources_resp.get("error") is not None:
                    code, msg = _extract_error_info(resources_resp)
                    if code != _METHOD_NOT_FOUND:
                        errors.append(f"resources/list failed ({code}): {msg}")
                else:
                    result = resources_resp.get("result")
                    if isinstance(result, dict) and isinstance(result.get("resources"), list):
                        raw_resources = [r for r in result["resources"] if isinstance(r, dict)]
                        resources_scanned = len(raw_resources)
                        decision = await pipeline.inspect_response(
                            resources_resp, method="resources/list"
                        )
                        collector.extend(decision.findings)

        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            errors.append(str(exc))

        return ScanReport(
            target=url,
            server_id=server_id,
            server_info=server_info,
            tools_scanned=tools_scanned,
            prompts_scanned=prompts_scanned,
            resources_scanned=resources_scanned,
            findings=collector.findings,
            errors=errors,
        )

    async def _drain_stderr(
        self,
        stream: asyncio.StreamReader,
        sink: list[str],
    ) -> None:
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if text:
                sink.append(text)
                if len(sink) > 50:
                    del sink[: len(sink) - 50]
                self._logger.debug("target stderr: %s", text)
