"""End-to-end integration tests for the STDIO MCP security proxy."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_SERVER = PROJECT_ROOT / "demo" / "vulnerable_server.py"


def _build_env() -> dict[str, str]:
    env = dict(os.environ)
    src_path = str(PROJECT_ROOT / "src")
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing_pp}" if existing_pp else src_path
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _assert_valid_jsonrpc_frame(raw_line: bytes) -> dict[str, Any]:
    text = raw_line.decode("utf-8", errors="strict")
    parsed = json.loads(text)
    assert isinstance(parsed, dict), f"Expected JSON-RPC object, got {type(parsed).__name__}"
    assert parsed.get("jsonrpc") == "2.0", f"Invalid jsonrpc frame on stdout: {parsed}"
    assert "id" in parsed or "method" in parsed
    return parsed


async def _spawn_proxy(
    *,
    mode: str,
    pin_file: Path,
    log_file: Path,
) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_guard.proxy.stdio_proxy",
        "--mode",
        mode,
        "--pin-file",
        str(pin_file),
        "--log-file",
        str(log_file),
        "--",
        sys.executable,
        str(DEMO_SERVER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_build_env(),
    )


async def _send_frame(proc: asyncio.subprocess.Process, payload: dict[str, Any] | bytes) -> None:
    assert proc.stdin is not None
    raw = (
        payload
        if isinstance(payload, bytes)
        else json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    proc.stdin.write(raw + b"\n")
    await proc.stdin.drain()


async def _read_rpc_line(
    proc: asyncio.subprocess.Process,
    *,
    timeout: float = 8.0,
) -> dict[str, Any]:
    assert proc.stdout is not None
    raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
    assert raw_line != b"", "Proxy stdout closed unexpectedly"
    return _assert_valid_jsonrpc_frame(raw_line.rstrip(b"\r\n"))


async def _close_and_drain(proc: asyncio.subprocess.Process) -> tuple[int, list[bytes], bytes]:
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    proc.stdin.close()
    if hasattr(proc.stdin, "wait_closed"):
        await asyncio.wait_for(proc.stdin.wait_closed(), timeout=3.0)

    remaining_stdout = await asyncio.wait_for(proc.stdout.read(), timeout=8.0)
    remaining_stderr = await asyncio.wait_for(proc.stderr.read(), timeout=8.0)
    rc = await asyncio.wait_for(proc.wait(), timeout=8.0)
    extra_lines = [line for line in remaining_stdout.splitlines() if line.strip()]
    for line in extra_lines:
        _assert_valid_jsonrpc_frame(line)
    return rc, extra_lines, remaining_stderr


def _parse_logged_events(log_file: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not log_file.is_file():
        return events
    for line in log_file.read_text(encoding="utf-8").splitlines():
        if " | " not in line:
            continue
        payload_str = line.rsplit(" | ", 1)[-1]
        if payload_str.startswith("{"):
            events.append(json.loads(payload_str))
    return events


@pytest.mark.asyncio
async def test_stdio_proxy_enforce_mode_e2e(tmp_path: Path) -> None:
    """Verify real-subprocess STDIO proxy enforcement across all 6 attack vectors."""
    pin_file = tmp_path / "pins.json"
    log_file = tmp_path / "proxy_enforce.log"
    proc = await _spawn_proxy(mode="enforce", pin_file=pin_file, log_file=log_file)

    try:
        # 1. Initialize handshake + initialized notification
        await _send_frame(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "e2e-test", "version": "1.0"},
                },
            },
        )
        init_resp = await _read_rpc_line(proc)
        assert init_resp["id"] == 1
        assert init_resp["result"]["serverInfo"]["name"] == "vulnerable-demo-mcp"

        await _send_frame(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        # 2. First tools/list: strips poisoned (add_numbers), stego (format_text),
        #    and shadowing (notes_helper); pins benign weather_lookup, fetch_url, read_project_file
        await _send_frame(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        list1_resp = await _read_rpc_line(proc)
        assert list1_resp["id"] == 2
        names1 = [tool["name"] for tool in list1_resp["result"]["tools"]]
        assert "add_numbers" not in names1
        assert "format_text" not in names1
        assert "notes_helper" not in names1
        assert names1 == ["weather_lookup", "fetch_url", "read_project_file"]

        # 3. Second tools/list: weather_lookup performs dynamic rug pull -> stripped!
        await _send_frame(proc, {"jsonrpc": "2.0", "id": "list-2", "method": "tools/list"})
        list2_resp = await _read_rpc_line(proc)
        assert list2_resp["id"] == "list-2"
        names2 = [tool["name"] for tool in list2_resp["result"]["tools"]]
        assert "weather_lookup" not in names2
        assert names2 == ["fetch_url", "read_project_file"]

        # 4. Path traversal blocked with -32001 (../../.env and ~/.ssh/id_rsa)
        await _send_frame(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_project_file", "arguments": {"path": "../../.env"}},
            },
        )
        trav1 = await _read_rpc_line(proc)
        assert trav1["id"] == 3
        assert trav1["error"]["code"] == -32001
        assert "MCP-ARG-001" in trav1["error"]["data"]["rules"]

        await _send_frame(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_project_file", "arguments": {"path": "~/.ssh/id_rsa"}},
            },
        )
        trav2 = await _read_rpc_line(proc)
        assert trav2["id"] == 4
        assert trav2["error"]["code"] == -32001
        assert "MCP-ARG-001" in trav2["error"]["data"]["rules"]

        # 5. Indirect Prompt Injection blocked in enforce mode (fetch_url)
        await _send_frame(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "fetch_url", "arguments": {"url": "https://example.com/page"}},
            },
        )
        ipi_resp = await _read_rpc_line(proc)
        assert ipi_resp["id"] == 5
        assert ipi_resp["error"]["code"] == -32001
        assert "MCP-IPI-001" in ipi_resp["error"]["data"]["rules"]

        # 6. Malformed JSON resilience: proxy emits -32700 and keeps serving
        await _send_frame(proc, b"{not valid json!!!")
        parse_err = await _read_rpc_line(proc)
        assert parse_err["id"] is None
        assert parse_err["error"]["code"] == -32700

        await _send_frame(proc, {"jsonrpc": "2.0", "id": 6, "method": "ping"})
        ping_resp = await _read_rpc_line(proc)
        assert ping_resp == {"jsonrpc": "2.0", "id": 6, "result": {}}

        rc, extra_stdout, stderr_bytes = await _close_and_drain(proc)
        assert rc == 0
        assert extra_stdout == []
        assert stderr_bytes  # structured logs emitted to stderr, never stdout
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()

    events = _parse_logged_events(log_file)
    all_rules = {rule for evt in events for rule in evt.get("rules", [])}
    assert {
        "MCP-POI-001",
        "MCP-UNI-001",
        "MCP-RUG-001",
        "MCP-SHD-001",
        "MCP-ARG-001",
        "MCP-IPI-001",
    } <= all_rules


@pytest.mark.asyncio
async def test_stdio_proxy_redact_mode_dlp_e2e(tmp_path: Path) -> None:
    """Verify real-subprocess STDIO proxy redacts leaked secrets cleanly in redact mode."""
    pin_file = tmp_path / "pins_redact.json"
    log_file = tmp_path / "proxy_redact.log"
    proc = await _spawn_proxy(mode="redact", pin_file=pin_file, log_file=log_file)

    try:
        await _send_frame(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
            },
        )
        init_resp = await _read_rpc_line(proc)
        assert init_resp["id"] == 1

        await _send_frame(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "fetch_url",
                    "arguments": {"url": "https://example.com/secrets"},
                },
            },
        )
        fetch_resp = await _read_rpc_line(proc)
        assert fetch_resp["id"] == 2
        text = fetch_resp["result"]["content"][0]["text"]
        assert "[REDACTED:MCP-DLP-001]" in text
        assert "[REDACTED:MCP-DLP-002]" in text
        aws_prefix = "AKIA" + "IOSFODNN7EXAMPLE"
        gh_prefix = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        assert aws_prefix not in text
        assert gh_prefix not in text

        rc, extra_stdout, _ = await _close_and_drain(proc)
        assert rc == 0
        assert extra_stdout == []
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
