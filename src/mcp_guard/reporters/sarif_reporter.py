"""SARIF 2.1.0 reporter for GitHub Code Scanning and CI security integrations."""

from __future__ import annotations

import json
from typing import Any

from mcp_guard import __version__
from mcp_guard.models.findings import ScanReport, SecurityFinding, Severity

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_INFO_URI = "https://github.com/mcp-guard/mcp-guard"

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _severity_to_sarif_level(severity: Severity) -> str:
    return _SEVERITY_TO_SARIF_LEVEL.get(severity, "note")


def _artifact_uri(finding: SecurityFinding, report: ScanReport) -> str:
    """Return a non-empty URI-reference string identifying the affected target."""
    candidate = finding.target.strip() or report.target.strip() or report.server_id.strip()
    if not candidate:
        return "mcp://unknown"
    return candidate.replace(" ", "%20")


def _build_rule_entry(finding: SecurityFinding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {"text": finding.remediation or finding.description or finding.title},
        "defaultConfiguration": {"level": _severity_to_sarif_level(finding.severity)},
        "properties": {
            "detector": finding.detector,
            "severity": finding.severity.value,
        },
    }


def render_sarif_report(report: ScanReport) -> str:
    """Serialize a ScanReport to a strict SARIF 2.1.0 JSON document."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    rule_max_severity: dict[str, Severity] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = _build_rule_entry(finding)
            rule_max_severity[finding.rule_id] = finding.severity
        elif finding.severity.rank > rule_max_severity[finding.rule_id].rank:
            rule_max_severity[finding.rule_id] = finding.severity
            rules_by_id[finding.rule_id]["defaultConfiguration"]["level"] = (
                _severity_to_sarif_level(finding.severity)
            )
            rules_by_id[finding.rule_id]["properties"]["severity"] = finding.severity.value

        message_text = finding.description.strip() or finding.title
        if finding.title and finding.title not in message_text:
            message_text = f"{finding.title}: {message_text}"

        result_entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _artifact_uri(finding, report),
                        }
                    }
                }
            ],
            "properties": {
                "detector": finding.detector,
                "severity": finding.severity.value,
                "action_taken": finding.action_taken.value,
            },
        }
        if finding.evidence:
            result_entry["properties"]["evidence"] = finding.evidence
        results.append(result_entry)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-guard",
                        "version": __version__,
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "server_id": report.server_id,
                    "tools_scanned": report.tools_scanned,
                    "prompts_scanned": report.prompts_scanned,
                    "resources_scanned": report.resources_scanned,
                },
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
