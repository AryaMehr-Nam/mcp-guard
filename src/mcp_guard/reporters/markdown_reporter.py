"""Markdown reporter for PR-ready MCP-Guard security audit reports."""

from __future__ import annotations

from mcp_guard.models.findings import ScanReport, Severity
from mcp_guard.reporters.console import _summarize_report


def _escape_table_cell(text: str) -> str:
    return " ".join(text.replace("|", "\\|").splitlines())


def _code_fence(text: str) -> str:
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}text\n{text}\n{fence}"


def render_markdown_report(report: ScanReport) -> str:
    """Render a ScanReport as a clean, PR-ready Markdown audit report."""
    counts, max_sev_val = _summarize_report(report)
    max_sev = max_sev_val.value.upper() if max_sev_val is not None else "NONE"
    server_name = str(report.server_info.get("name", "")).strip()
    server_version = str(report.server_info.get("version", "")).strip()
    server_display = (
        f"{server_name} {server_version}".strip() if (server_name or server_version) else "unknown"
    )

    lines: list[str] = [
        "# MCP-Guard Security Audit Report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Server ID:** `{report.server_id}`",
        f"- **Server Info:** `{server_display}`",
        f"- **Timestamp:** `{report.timestamp.isoformat()}`",
        (
            f"- **Scanned:** {report.tools_scanned} tools, "
            f"{report.prompts_scanned} prompts, {report.resources_scanned} resources"
        ),
        f"- **Max Severity:** **{max_sev}**",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        f"| Critical | {counts[Severity.CRITICAL.value]} |",
        f"| High | {counts[Severity.HIGH.value]} |",
        f"| Medium | {counts[Severity.MEDIUM.value]} |",
        f"| Low | {counts[Severity.LOW.value]} |",
        f"| Info | {counts[Severity.INFO.value]} |",
        f"| **Total** | **{counts['total']}** |",
    ]

    if report.errors:
        lines.extend(["", "## Errors", ""])
        for err in report.errors:
            lines.append(f"- `{err}`")

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No security findings detected.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Severity | Rule ID | Detector | Target | Title | Action |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in report.findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    finding.severity.value.upper(),
                    f"`{finding.rule_id}`",
                    f"`{finding.detector}`",
                    f"`{_escape_table_cell(finding.target or '-')}`",
                    _escape_table_cell(finding.title),
                    f"`{finding.action_taken.value}`",
                ]
            )
            + " |"
        )

    lines.extend(["", "## Finding Details", ""])
    for idx, finding in enumerate(report.findings, start=1):
        sev_label = finding.severity.value.upper()
        lines.extend(
            [
                f"### {idx}. [{sev_label}] {finding.rule_id} — {finding.title}",
                "",
                f"- **Detector:** `{finding.detector}`",
                f"- **Target:** `{finding.target or '-'}`",
                f"- **Action:** `{finding.action_taken.value}`",
                "",
                finding.description,
                "",
            ]
        )
        if finding.evidence:
            lines.extend(["**Evidence:**", "", _code_fence(finding.evidence), ""])
        if finding.remediation:
            lines.extend([f"**Remediation:** {finding.remediation}", ""])

    return "\n".join(lines).rstrip() + "\n"
