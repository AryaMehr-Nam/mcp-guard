"""Security finding, action, and scan report models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(StrEnum):
    """Finding severity levels ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank (0..4) for threshold comparisons."""
        return _SEVERITY_RANK[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        """Return True if this severity is greater than or equal to threshold."""
        return self.rank >= threshold.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Action(StrEnum):
    """Enforcement action taken for a finding or message."""

    ALLOW = "allow"
    LOG = "log"
    REDACT = "redact"
    BLOCK = "block"
    STRIP_TOOL = "strip_tool"


class SecurityFinding(BaseModel):
    """Structured security finding emitted by a scanner or runtime detector."""

    rule_id: str
    detector: str
    severity: Severity
    title: str
    description: str
    target: str = ""
    evidence: str = ""
    remediation: str = ""
    action_taken: Action = Action.LOG
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanReport(BaseModel):
    """Aggregated static scan report for an MCP server."""

    target: str
    server_id: str
    server_info: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tools_scanned: int = 0
    prompts_scanned: int = 0
    resources_scanned: int = 0
    findings: list[SecurityFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @computed_field
    def summary_counts(self) -> dict[str, int]:
        """Count of findings by severity plus total."""
        counts: dict[str, int] = {
            "total": len(self.findings),
            Severity.INFO.value: 0,
            Severity.LOW.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.HIGH.value: 0,
            Severity.CRITICAL.value: 0,
        }
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @computed_field
    def max_severity(self) -> Severity | None:
        """Highest severity among findings, or None if no findings exist."""
        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=lambda sev: sev.rank)
