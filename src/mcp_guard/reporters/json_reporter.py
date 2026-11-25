"""JSON reporter for MCP-Guard ScanReport output."""

from __future__ import annotations

import json

from mcp_guard.models.findings import ScanReport


def render_json_report(report: ScanReport) -> str:
    """Serialize a ScanReport to pretty-printed UTF-8 JSON."""
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)
