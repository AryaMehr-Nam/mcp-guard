"""Self-contained live demonstration of MCP-Guard active scanning and runtime proxy."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_guard.models.policy import GuardMode, PinningConfig, PinningMode, PolicyConfig
from mcp_guard.reporters import render_console_report
from mcp_guard.scanner.active_scanner import ActiveScanner

VULNERABLE_SERVER_PATH = Path(__file__).resolve().parent / "vulnerable_server.py"


def _proxy_env() -> dict[str, str]:
    env = dict(os.environ)
    pkg_root = Path(__file__).resolve().parents[2]
    if pkg_root.is_dir():
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{pkg_root}{os.pathsep}{existing}" if existing else str(pkg_root)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


async def _send_rpc(proc: asyncio.subprocess.Process, payload: dict[str, Any]) -> None:
    assert proc.stdin is not None
    encoded = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    proc.stdin.write(encoded)
    await proc.stdin.drain()


async def _read_rpc(
    proc: asyncio.subprocess.Process,
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    assert proc.stdout is not None
    while True:
        raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
        if not raw_line:
            raise EOFError("STDIO proxy closed stdout unexpectedly")
        stripped = raw_line.rstrip(b"\r\n")
        if not stripped:
            continue
        parsed: Any = json.loads(stripped.decode("utf-8"))
        if isinstance(parsed, dict):
            return parsed


async def _spawn_wrapped_demo_server(
    *,
    mode: GuardMode,
    pin_file: Path,
    log_file: Path,
    server_path: Path,
) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_guard.proxy.stdio_proxy",
        "--mode",
        mode.value,
        "--pin-file",
        str(pin_file),
        "--log-file",
        str(log_file),
        "--",
        sys.executable,
        str(server_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_proxy_env(),
    )


async def _shutdown_process(proc: asyncio.subprocess.Process) -> None:
    if proc.stdin is not None and not proc.stdin.is_closing():
        with contextlib.suppress(OSError):
            proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=3.0)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(ProcessLookupError):
                await proc.wait()


async def _handshake(proc: asyncio.subprocess.Process) -> None:
    await _send_rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-guard-demo", "version": "0.1.0"},
            },
        },
    )
    await _read_rpc(proc)
    await _send_rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})


async def _run_enforce_demo(server_path: Path, tmp_dir: Path) -> list[tuple[str, str, str]]:
    """Verify StdioProxy enforce mode strips bad tools and blocks traversal & injection."""
    pin_file = tmp_dir / "enforce_pins.json"
    log_file = tmp_dir / "enforce_proxy.log"
    proc = await _spawn_wrapped_demo_server(
        mode=GuardMode.ENFORCE,
        pin_file=pin_file,
        log_file=log_file,
        server_path=server_path,
    )
    results: list[tuple[str, str, str]] = []
    try:
        await _handshake(proc)

        await _send_rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        list_resp = await _read_rpc(proc)
        tool_names = [t.get("name", "") for t in list_resp.get("result", {}).get("tools", [])]
        stripped_ok = all(
            bad not in tool_names for bad in ("add_numbers", "format_text", "notes_helper")
        )
        results.append(
            (
                "tools/list catalog stripping",
                "PASS" if stripped_ok else "FAIL",
                f"Visible safe tools: {', '.join(tool_names) or 'none'}",
            )
        )
        if not stripped_ok:
            raise RuntimeError(f"Expected poisoned tools to be stripped, got: {tool_names}")

        # Path traversal attempt: read_project_file("../../.env")
        await _send_rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_project_file", "arguments": {"path": "../../.env"}},
            },
        )
        trav_resp = await _read_rpc(proc)
        trav_err = trav_resp.get("error", {})
        if trav_err.get("code") != -32001:
            raise RuntimeError(f"Expected -32001 block for path traversal, got: {trav_resp}")
        results.append(
            (
                "Path traversal (../../.env)",
                "BLOCKED (-32001)",
                str(trav_err.get("message", "")),
            )
        )

        # Indirect prompt injection attempt: fetch_url("https://example.com")
        await _send_rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "fetch_url", "arguments": {"url": "https://example.com"}},
            },
        )
        ipi_resp = await _read_rpc(proc)
        ipi_err = ipi_resp.get("error", {})
        if ipi_err.get("code") != -32001:
            raise RuntimeError(f"Expected -32001 block for IPI, got: {ipi_resp}")
        results.append(
            (
                "Indirect Prompt Injection (fetch_url)",
                "BLOCKED (-32001)",
                str(ipi_err.get("message", "")),
            )
        )
    finally:
        await _shutdown_process(proc)
    return results


async def _run_redact_demo(server_path: Path, tmp_dir: Path) -> str:
    """Verify StdioProxy redact mode masks synthetic AWS & GitHub secrets cleanly."""
    pin_file = tmp_dir / "redact_pins.json"
    log_file = tmp_dir / "redact_proxy.log"
    proc = await _spawn_wrapped_demo_server(
        mode=GuardMode.REDACT,
        pin_file=pin_file,
        log_file=log_file,
        server_path=server_path,
    )
    try:
        await _handshake(proc)
        await _send_rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "fetch_url", "arguments": {"url": "https://example.com"}},
            },
        )
        resp = await _read_rpc(proc)
        content = resp.get("result", {}).get("content", [])
        text = str(content[0].get("text", "")) if content else ""
        if "[REDACTED:MCP-DLP-" not in text:
            raise RuntimeError(f"Expected [REDACTED:MCP-DLP-*] token in redacted output: {resp}")
        if "AKIA" + "IOSFODNN7EXAMPLE" in text or "ghp_" in text:
            raise RuntimeError(f"Unredacted secret leaked in redact mode: {text}")
        return text
    finally:
        await _shutdown_process(proc)


async def _run_demo_async(console: Console) -> int:
    if not VULNERABLE_SERVER_PATH.is_file():
        raise FileNotFoundError(f"Missing vulnerable demo server at {VULNERABLE_SERVER_PATH}")

    console.print(
        Panel(
            "[bold]Live Demonstration: Active Scan + STDIO Proxy (Enforce & Redact)[/bold]\n"
            f"Target server: {VULNERABLE_SERVER_PATH}",
            title="[bold cyan]MCP-Guard Demo[/bold cyan]",
            border_style="cyan",
        )
    )

    with tempfile.TemporaryDirectory(prefix="mcp-guard-demo-") as tmp_str:
        tmp_dir = Path(tmp_str)

        # 1. Active Scan (catches vectors 1-4: poisoning, unicode, rug pull, shadowing)
        scan_policy = PolicyConfig(
            mode=GuardMode.ENFORCE,
            pinning=PinningConfig(
                enabled=True,
                mode=PinningMode.TOFU,
                pin_file=str(tmp_dir / "scan_pins.json"),
            ),
        )
        scanner = ActiveScanner(scan_policy)
        report = await scanner.scan_stdio(
            [sys.executable, str(VULNERABLE_SERVER_PATH)],
            rug_pull_probes=2,
            timeout=15.0,
        )
        console.print("\n[bold]Phase 1: Active Catalog Scan (2 rug-pull probes)[/bold]")
        render_console_report(report, console=console)

        rule_ids = {f.rule_id for f in report.findings}
        if not any(r.startswith("MCP-POI-") for r in rule_ids):
            raise RuntimeError("Demo active scan did not detect tool poisoning (MCP-POI-*)")
        if "MCP-UNI-001" not in rule_ids:
            raise RuntimeError(
                "Demo active scan did not detect Unicode tag steganography (MCP-UNI-001)"
            )
        if "MCP-RUG-001" not in rule_ids:
            raise RuntimeError("Demo active scan did not detect rug pull (MCP-RUG-001)")
        if "MCP-SHD-001" not in rule_ids:
            raise RuntimeError("Demo active scan did not detect cross-tool shadowing (MCP-SHD-001)")

        # 2. Runtime STDIO Proxy (enforce mode)
        console.print("\n[bold]Phase 2: Live STDIO Proxy (enforce mode)[/bold]")
        enforce_rows = await _run_enforce_demo(VULNERABLE_SERVER_PATH, tmp_dir)
        enforce_table = Table(show_lines=True)
        enforce_table.add_column("Attack Vector", style="bold")
        enforce_table.add_column("Outcome", style="green")
        enforce_table.add_column("Proxy Response")
        for vector, outcome, detail in enforce_rows:
            enforce_table.add_row(escape(vector), escape(outcome), escape(detail))
        console.print(enforce_table)

        # 3. Runtime STDIO Proxy (redact mode)
        console.print("\n[bold]Phase 3: Live STDIO Proxy (redact mode — DLP secret masking)[/bold]")
        redacted_text = await _run_redact_demo(VULNERABLE_SERVER_PATH, tmp_dir)
        console.print(
            Panel(
                Text(redacted_text.strip()),
                title="[bold green]Sanitized fetch_url Response (JSON Preserved)[/bold green]",
                border_style="green",
            )
        )

    console.print("[bold green]MCP-Guard live demo completed successfully.[/bold green]")
    return 0


def run_live_demo(*, console: Console | None = None) -> int:
    """Run the end-to-end live demonstration synchronously and return exit code 0."""
    target_console = console if console is not None else Console()
    return asyncio.run(_run_demo_async(target_console))


if __name__ == "__main__":
    raise SystemExit(run_live_demo())
