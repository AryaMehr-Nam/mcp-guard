"""Typer CLI for MCP-Guard scanning, proxying, pin management, and live demo."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import io
import webbrowser
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mcp_guard import __version__
from mcp_guard.engine.pinning import PinStore
from mcp_guard.models.findings import ScanReport, Severity
from mcp_guard.models.policy import GuardMode, PinningConfig, PolicyConfig
from mcp_guard.policy.loader import default_policy_yaml, load_policy
from mcp_guard.proxy.http_proxy import run_http_proxy
from mcp_guard.proxy.stdio_proxy import run_stdio_proxy
from mcp_guard.reporters import (
    render_console_report,
    render_json_report,
    render_markdown_report,
    render_sarif_report,
)
from mcp_guard.scanner.active_scanner import ActiveScanner
from mcp_guard.ui import run_ui_server, validate_loopback_host
from mcp_guard.utils.logging import configure_logger

app = typer.Typer(
    name="mcp-guard",
    no_args_is_help=True,
    help="Security scanner, static analyzer, and runtime proxy for MCP servers.",
)
pins_app = typer.Typer(
    name="pins",
    no_args_is_help=True,
    help="Inspect, approve, or reset cryptographic tool schema pins.",
)
app.add_typer(pins_app, name="pins")


class OutputFormat(StrEnum):
    """Supported report output formats."""

    CONSOLE = "console"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class FailOnLevel(StrEnum):
    """Minimum finding severity required to fail a scan with exit code 1."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _extract_child_command(ctx: typer.Context) -> list[str]:
    """Extract the wrapped child command from ctx.args, stripping a single leading '--'."""
    args = list(ctx.args)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        typer.echo(
            "Error: Missing target MCP server command. "
            "Pass it after '--', e.g. `-- python server.py`.",
            err=True,
        )
        raise typer.Exit(code=2)
    return args


def _load_effective_policy(
    *,
    policy: Path | None = None,
    mode: GuardMode | None = None,
    pin_file: str | None = None,
    server_id: str | None = None,
    log_file: str | None = None,
    llm_judge: bool = False,
) -> PolicyConfig:
    try:
        return load_policy(
            policy,
            mode=mode.value if mode is not None else None,
            pin_file=pin_file,
            server_id=server_id,
            log_file=log_file,
            llm_judge=True if llm_judge else None,
        )
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _render_report_text(report: ScanReport, output_format: OutputFormat) -> str:
    if output_format == OutputFormat.JSON:
        return render_json_report(report)
    if output_format == OutputFormat.MARKDOWN:
        return render_markdown_report(report)
    if output_format == OutputFormat.SARIF:
        return render_sarif_report(report)

    buf = io.StringIO()
    capture_console = Console(file=buf, force_terminal=False, no_color=True, width=120)
    render_console_report(report, console=capture_console)
    return buf.getvalue()


def _emit_report_and_check_threshold(
    report: ScanReport,
    *,
    output_format: OutputFormat,
    output: Path | None,
    fail_on: FailOnLevel,
) -> None:
    if output is not None:
        rendered = _render_report_text(report, output_format)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    elif output_format == OutputFormat.CONSOLE:
        render_console_report(report)
    else:
        rendered = _render_report_text(report, output_format)
        typer.echo(rendered)

    if fail_on != FailOnLevel.NONE:
        threshold = Severity(fail_on.value)
        if any(finding.severity.meets_threshold(threshold) for finding in report.findings):
            raise typer.Exit(code=1)


def _resolve_pin_file(pin_file: str | None) -> str:
    return pin_file if pin_file is not None else PinningConfig().pin_file


def _validate_ui_host_or_exit(host: str) -> str:
    try:
        return validate_loopback_host(host)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcp-guard {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main_callback(
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show MCP-Guard version and exit.",
        ),
    ] = False,
) -> None:
    """MCP-Guard CLI root callback."""


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def scan(
    ctx: typer.Context,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Report output format."),
    ] = OutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write report output to a UTF-8 file."),
    ] = None,
    fail_on: Annotated[
        FailOnLevel,
        typer.Option("--fail-on", help="Exit with code 1 when findings meet/exceed severity."),
    ] = FailOnLevel.HIGH,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to YAML policy file."),
    ] = None,
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", help="Override normalized server ID."),
    ] = None,
    rug_pull_probes: Annotated[
        int,
        typer.Option("--rug-pull-probes", min=1, help="Number of tools/list probes per scan."),
    ] = 2,
    llm_judge: Annotated[
        bool,
        typer.Option("--llm-judge", help="Enable optional semantic LLM-as-a-judge inspection."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout in seconds for server probes."),
    ] = 15.0,
) -> None:
    """Actively scan a STDIO MCP server command for poisoning, Unicode, rug pulls, and shadowing."""
    command = _extract_child_command(ctx)
    cfg = _load_effective_policy(
        policy=policy,
        pin_file=pin_file,
        server_id=server_id,
        llm_judge=llm_judge,
    )
    scanner = ActiveScanner(cfg)
    report = asyncio.run(
        scanner.scan_stdio(command, rug_pull_probes=rug_pull_probes, timeout=timeout)
    )
    _emit_report_and_check_threshold(
        report,
        output_format=output_format,
        output=output,
        fail_on=fail_on,
    )


@app.command("scan-http")
def scan_http(
    url: Annotated[
        str,
        typer.Option("--url", help="Target Streamable HTTP or SSE MCP server URL."),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Report output format."),
    ] = OutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write report output to a UTF-8 file."),
    ] = None,
    fail_on: Annotated[
        FailOnLevel,
        typer.Option("--fail-on", help="Exit with code 1 when findings meet/exceed severity."),
    ] = FailOnLevel.HIGH,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to YAML policy file."),
    ] = None,
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", help="Override normalized server ID."),
    ] = None,
    rug_pull_probes: Annotated[
        int,
        typer.Option("--rug-pull-probes", min=1, help="Number of tools/list probes per scan."),
    ] = 2,
    llm_judge: Annotated[
        bool,
        typer.Option("--llm-judge", help="Enable optional semantic LLM-as-a-judge inspection."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout in seconds for HTTP requests."),
    ] = 15.0,
) -> None:
    """Actively scan an HTTP/SSE MCP server URL."""
    cfg = _load_effective_policy(
        policy=policy,
        pin_file=pin_file,
        server_id=server_id,
        llm_judge=llm_judge,
    )
    scanner = ActiveScanner(cfg)
    report = asyncio.run(scanner.scan_http(url, rug_pull_probes=rug_pull_probes, timeout=timeout))
    _emit_report_and_check_threshold(
        report,
        output_format=output_format,
        output=output,
        fail_on=fail_on,
    )


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def wrap(
    ctx: typer.Context,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to YAML policy file."),
    ] = None,
    mode: Annotated[
        GuardMode | None,
        typer.Option("--mode", "-m", help="Proxy enforcement mode (audit, enforce, redact)."),
    ] = None,
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", help="Override normalized server ID."),
    ] = None,
    log_file: Annotated[
        str | None,
        typer.Option("--log-file", help="Optional path for security audit logs."),
    ] = None,
    llm_judge: Annotated[
        bool,
        typer.Option("--llm-judge", help="Enable optional semantic LLM-as-a-judge inspection."),
    ] = False,
    ui_port: Annotated[
        int | None,
        typer.Option(
            "--ui-port",
            min=0,
            max=65535,
            help="Optional loopback port for the embedded SecOps Web UI (0 for ephemeral).",
        ),
    ] = None,
    ui_host: Annotated[
        str,
        typer.Option("--ui-host", help="Loopback bind host for the embedded SecOps Web UI."),
    ] = "127.0.0.1",
) -> None:
    """Wrap a STDIO MCP server command with the runtime security proxy."""
    # CRITICAL: Never write non-JSON-RPC banners or Rich output to stdout in `wrap`.
    command = _extract_child_command(ctx)
    validated_ui_host = _validate_ui_host_or_exit(ui_host) if ui_port is not None else ui_host
    cfg = _load_effective_policy(
        policy=policy,
        mode=mode,
        pin_file=pin_file,
        server_id=server_id,
        log_file=log_file,
        llm_judge=llm_judge,
    )
    log_path = Path(cfg.log_file) if cfg.log_file else None
    logger = configure_logger("mcp_guard.proxy.stdio", log_file=log_path)
    if ui_port is not None:
        exit_code = run_stdio_proxy(
            command,
            cfg,
            logger=logger,
            ui_port=ui_port,
            ui_host=validated_ui_host,
        )
    else:
        exit_code = run_stdio_proxy(command, cfg, logger=logger)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command("wrap-http")
def wrap_http(
    target: Annotated[
        str,
        typer.Option("--target", help="Upstream MCP server HTTP/SSE base URL."),
    ],
    host: Annotated[
        str,
        typer.Option("--host", help="Bind host for the HTTP security proxy."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=65535, help="Bind port for the HTTP security proxy."),
    ] = 8765,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to YAML policy file."),
    ] = None,
    mode: Annotated[
        GuardMode | None,
        typer.Option("--mode", "-m", help="Proxy enforcement mode (audit, enforce, redact)."),
    ] = None,
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", help="Override normalized server ID."),
    ] = None,
    log_file: Annotated[
        str | None,
        typer.Option("--log-file", help="Optional path for security audit logs."),
    ] = None,
    llm_judge: Annotated[
        bool,
        typer.Option("--llm-judge", help="Enable optional semantic LLM-as-a-judge inspection."),
    ] = False,
    ui_port: Annotated[
        int | None,
        typer.Option(
            "--ui-port",
            min=0,
            max=65535,
            help="Optional loopback port for the embedded SecOps Web UI (0 for ephemeral).",
        ),
    ] = None,
    ui_host: Annotated[
        str,
        typer.Option("--ui-host", help="Loopback bind host for the embedded SecOps Web UI."),
    ] = "127.0.0.1",
) -> None:
    """Start an HTTP/SSE security proxy in front of a remote MCP server."""
    validated_ui_host = _validate_ui_host_or_exit(ui_host) if ui_port is not None else ui_host
    cfg = _load_effective_policy(
        policy=policy,
        mode=mode,
        pin_file=pin_file,
        server_id=server_id,
        log_file=log_file,
        llm_judge=llm_judge,
    )
    log_path = Path(cfg.log_file) if cfg.log_file else None
    logger = configure_logger("mcp_guard.proxy.http", log_file=log_path)
    logger.info("Starting MCP-Guard HTTP proxy on http://%s:%d -> %s", host, port, target)
    if ui_port is not None:
        run_http_proxy(
            target,
            cfg,
            host=host,
            port=port,
            logger=logger,
            ui_port=ui_port,
            ui_host=validated_ui_host,
        )
    else:
        run_http_proxy(target, cfg, host=host, port=port, logger=logger)


@app.command("ui")
def ui_command(
    host: Annotated[
        str,
        typer.Option("--host", help="Loopback bind host for the Web UI."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", min=0, max=65535, help="Loopback bind port for the Web UI."),
    ] = 8766,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to YAML policy file."),
    ] = None,
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", help="Override normalized server ID."),
    ] = None,
    allow_exec: Annotated[
        bool,
        typer.Option("--allow-exec", help="Allow STDIO subprocess scans from the Web UI."),
    ] = False,
    no_open: Annotated[
        bool,
        typer.Option("--no-open", help="Do not open the Web UI URL in the default browser."),
    ] = False,
) -> None:
    """Launch the standalone MCP-Guard SecOps Web UI dashboard."""
    validated_host = _validate_ui_host_or_exit(host)
    cfg = _load_effective_policy(
        policy=policy,
        pin_file=pin_file,
        server_id=server_id,
    )
    log_path = Path(cfg.log_file) if cfg.log_file else None
    logger = configure_logger("mcp_guard.ui", log_file=log_path)

    def _on_ready(url: str) -> None:
        typer.echo(f"MCP-Guard Web UI: {url}", err=True)
        if not no_open:
            webbrowser.open(url)

    run_ui_server(
        policy=cfg,
        pin_file=pin_file,
        server_id=server_id or cfg.server_id,
        host=validated_host,
        port=port,
        allow_exec=allow_exec,
        logger=logger,
        on_ready=_on_ready,
    )


@pins_app.command("list")
def pins_list(
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", "--server", help="Filter pins by server ID."),
    ] = None,
) -> None:
    """List pinned and pending MCP tool schemas."""
    store = PinStore(_resolve_pin_file(pin_file))
    try:
        records = store.list_pins(server_id=server_id)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    console = Console()
    if not records:
        console.print("No pinned or pending tool schemas found.")
        return

    table = Table(title="MCP-Guard Tool Schema Pins", show_lines=False)
    table.add_column("Server ID", style="bold")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("SHA-256 Hash")
    table.add_column("Timestamp")

    for sid, entry in sorted(records.items()):
        if not isinstance(entry, dict):
            continue
        tools = entry.get("tools", {})
        pending = entry.get("pending", {})
        if isinstance(tools, dict):
            for tool_name, rec in sorted(tools.items()):
                if not isinstance(rec, dict):
                    continue
                table.add_row(
                    escape(sid),
                    escape(tool_name),
                    "[green]pinned[/green]",
                    escape(str(rec.get("hash", ""))[:16]),
                    escape(str(rec.get("pinned_at", ""))),
                )
        if isinstance(pending, dict):
            for tool_name, rec in sorted(pending.items()):
                if not isinstance(rec, dict):
                    continue
                table.add_row(
                    escape(sid),
                    escape(tool_name),
                    "[yellow]pending[/yellow]",
                    escape(str(rec.get("hash", ""))[:16]),
                    escape(str(rec.get("seen_at", ""))),
                )

    console.print(table)


@pins_app.command("approve")
def pins_approve(
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", "--server", help="Server ID to approve pending tools for."),
    ] = None,
    tool: Annotated[
        str | None,
        typer.Option("--tool", help="Specific pending tool name to approve."),
    ] = None,
) -> None:
    """Promote pending tool schemas to approved pins."""
    store = PinStore(_resolve_pin_file(pin_file))
    try:
        approved = store.approve(server_id=server_id, tool_name=tool)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Approved {approved} pending tool(s).")


@pins_app.command("reset")
def pins_reset(
    pin_file: Annotated[
        str | None,
        typer.Option("--pin-file", help="Path to tool schema pin store JSON file."),
    ] = None,
    server_id: Annotated[
        str | None,
        typer.Option("--server-id", "--server", help="Server ID to clear pins for."),
    ] = None,
) -> None:
    """Clear pinned and pending tool records for a server or all servers."""
    store = PinStore(_resolve_pin_file(pin_file))
    try:
        cleared = store.reset(server_id=server_id)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Cleared {cleared} pin record(s).")


@app.command()
def init(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination path for the generated policy YAML."),
    ] = Path("mcp-guard.yaml"),
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite an existing policy file."),
    ] = False,
) -> None:
    """Generate a commented default mcp-guard.yaml security policy file."""
    if output.exists() and not force:
        typer.echo(
            f"Error: {output} already exists. Pass --force to overwrite.",
            err=True,
        )
        raise typer.Exit(code=1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(default_policy_yaml(), encoding="utf-8")
    typer.echo(f"Wrote default policy to {output}")


def _load_run_live_demo() -> Any:
    """Locate and return `run_live_demo` from `demo.run_demo` or disk fallback paths."""
    try:
        mod = importlib.import_module("demo.run_demo")
        fn = getattr(mod, "run_live_demo", None)
        if callable(fn):
            return fn
    except ModuleNotFoundError:
        pass

    candidate_roots = [
        Path.cwd(),
        *Path(__file__).resolve().parents,
        Path("/app"),
    ]
    for root in candidate_roots:
        demo_path = root / "demo" / "run_demo.py"
        if demo_path.is_file():
            spec = importlib.util.spec_from_file_location("mcp_guard_demo_runner", demo_path)
            if spec is not None and spec.loader is not None:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                fn = getattr(module, "run_live_demo", None)
                if callable(fn):
                    return fn
    return None


@app.command()
def demo() -> None:
    """Run the self-contained live MCP-Guard security demo against vulnerable_server.py."""
    run_live_demo = _load_run_live_demo()
    if run_live_demo is None:
        typer.echo(
            "Error: Could not locate demo/run_demo.py. Run from the repository root.",
            err=True,
        )
        raise typer.Exit(code=1)

    result = run_live_demo()
    if isinstance(result, int) and result != 0:
        raise typer.Exit(code=result)
