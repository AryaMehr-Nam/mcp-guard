"""Rich console reporter for MCP-Guard ScanReport output."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_guard.models.findings import ScanReport, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _summarize_report(report: ScanReport) -> tuple[dict[str, int], Severity | None]:
    counts: dict[str, int] = {
        "total": len(report.findings),
        Severity.INFO.value: 0,
        Severity.LOW.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.HIGH.value: 0,
        Severity.CRITICAL.value: 0,
    }
    max_sev: Severity | None = None
    for finding in report.findings:
        counts[finding.severity.value] += 1
        if max_sev is None or finding.severity.rank > max_sev.rank:
            max_sev = finding.severity
    return counts, max_sev


def _truncate(text: str, limit: int = 160) -> str:
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def render_console_report(
    report: ScanReport,
    *,
    console: Console | None = None,
    stderr: bool = False,
) -> None:
    """Render a ScanReport as Rich panels and tables to stdout or stderr."""
    target_console = console if console is not None else Console(stderr=stderr)
    counts, max_sev = _summarize_report(report)
    max_sev_label = max_sev.value.upper() if max_sev is not None else "NONE"
    max_sev_style = _SEVERITY_STYLES.get(max_sev, "green") if max_sev is not None else "green"

    server_name = str(report.server_info.get("name", "")).strip()
    server_version = str(report.server_info.get("version", "")).strip()
    server_display = (
        f"{server_name} {server_version}".strip() if (server_name or server_version) else "unknown"
    )

    header_lines = [
        f"[bold]Target:[/bold] {escape(report.target)}",
        f"[bold]Server ID:[/bold] {escape(report.server_id)}",
        f"[bold]Server Info:[/bold] {escape(server_display)}",
        f"[bold]Timestamp:[/bold] {report.timestamp.isoformat()}",
        (
            "[bold]Catalog Scanned:[/bold] "
            f"{report.tools_scanned} tools, "
            f"{report.prompts_scanned} prompts, "
            f"{report.resources_scanned} resources"
        ),
        (
            "[bold]Findings:[/bold] "
            f"total={counts['total']} "
            f"(critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}, info={counts['info']}) | "
            f"[bold]Max Severity:[/bold] [{max_sev_style}]{max_sev_label}[/{max_sev_style}]"
        ),
    ]

    target_console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold]MCP-Guard Security Scan Report[/bold]",
            border_style="blue",
        )
    )

    if report.errors:
        error_body = "\n".join(f"- {escape(err)}" for err in report.errors)
        target_console.print(
            Panel(
                error_body,
                title="[bold red]Scanner Errors[/bold red]",
                border_style="red",
            )
        )

    if not report.findings:
        target_console.print(
            Panel(
                "[bold green]No security findings detected.[/bold green]",
                border_style="green",
            )
        )
        return

    table = Table(title="Security Findings", show_lines=True, expand=True)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Rule ID", no_wrap=True)
    table.add_column("Detector")
    table.add_column("Target", overflow="fold")
    table.add_column("Details", ratio=1, min_width=24)
    table.add_column("Action", no_wrap=True)

    for finding in report.findings:
        sev_style = _SEVERITY_STYLES.get(finding.severity, "white")
        sev_text = Text(finding.severity.value.upper(), style=sev_style)

        detail_parts = [f"[bold]{escape(finding.title)}[/bold]"]
        if finding.description:
            detail_parts.append(escape(_truncate(finding.description, 200)))
        if finding.evidence:
            detail_parts.append(f"[dim]Evidence:[/dim] {escape(_truncate(finding.evidence, 160))}")
        if finding.remediation:
            detail_parts.append(
                f"[dim]Remediation:[/dim] {escape(_truncate(finding.remediation, 160))}"
            )

        table.add_row(
            sev_text,
            escape(finding.rule_id),
            escape(finding.detector),
            escape(finding.target or "-"),
            "\n".join(detail_parts),
            escape(finding.action_taken.value),
        )

    target_console.print(table)
