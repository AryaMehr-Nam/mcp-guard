"""Response inspection engine for Indirect Prompt Injection (IPI) and DLP secret redaction."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, ResponseGuardConfig

_IPI_PATTERNS: tuple[tuple[str, Severity, re.Pattern[str]], ...] = (
    (
        "instruction override phrase",
        Severity.CRITICAL,
        re.compile(
            r"(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions\b"
        ),
    ),
    (
        "rule disregard phrase",
        Severity.CRITICAL,
        re.compile(
            r"(?i)\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts?)\b"
        ),
    ),
    (
        "injected new instructions directive",
        Severity.CRITICAL,
        re.compile(r"(?i)\bnew\s+instructions\s*:"),
    ),
    (
        "injected system prompt marker",
        Severity.HIGH,
        re.compile(r"(?i)\bsystem\s+prompt\s*:"),
    ),
    (
        "smuggled XML instruction tag",
        Severity.CRITICAL,
        re.compile(r"(?i)<\s*/?\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS|HIDDEN)\s*>"),
    ),
    (
        "role hijack phrase",
        Severity.HIGH,
        re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|in|operating)\b"),
    ),
    (
        "stealth suppression directive",
        Severity.CRITICAL,
        re.compile(r"(?i)\bdo\s+not\s+(?:tell|inform|alert|notify)\s+(?:the\s+)?user\b"),
    ),
    (
        "exfiltration directive",
        Severity.HIGH,
        re.compile(r"(?i)\bexfiltrate\b"),
    ),
)


@dataclass(frozen=True)
class _SecretRule:
    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    require_entropy: bool = True
    group: int = 0


_SECRET_RULES: tuple[_SecretRule, ...] = (
    _SecretRule(
        rule_id="MCP-DLP-001",
        title="AWS access key ID detected",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ),
    _SecretRule(
        rule_id="MCP-DLP-002",
        title="GitHub personal or OAuth access token detected",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"\b(?:ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
            r"gho_[A-Za-z0-9_]{20,}|ghu_[A-Za-z0-9_]{20,}|ghs_[A-Za-z0-9_]{20,})\b"
        ),
    ),
    _SecretRule(
        rule_id="MCP-DLP-003",
        title="OpenAI or Anthropic API key detected",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
    ),
    _SecretRule(
        rule_id="MCP-DLP-004",
        title="Cloud or SaaS API secret token detected",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|"
            r"sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,})\b"
        ),
    ),
    _SecretRule(
        rule_id="MCP-DLP-005",
        title="PEM private key block detected",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
            r"(?:[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)?"
        ),
        require_entropy=False,
    ),
    _SecretRule(
        rule_id="MCP-DLP-006",
        title="JSON Web Token (JWT) detected",
        severity=Severity.HIGH,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    _SecretRule(
        rule_id="MCP-DLP-007",
        title="High-entropy Bearer token detected",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{20,})"),
        group=1,
    ),
)


def shannon_entropy(value: str) -> float:
    """Calculate the Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _mask_secret(secret: str) -> str:
    compact = secret.replace("\n", " ").strip()
    if len(compact) <= 10:
        return f"{compact[:2]}***"
    return f"{compact[:6]}...{compact[-4:]}"


class ResponseGuard:
    """Inspects upstream MCP responses for Indirect Prompt Injection and leaked secrets."""

    def __init__(self, config: ResponseGuardConfig | None = None) -> None:
        self.config = config or ResponseGuardConfig()

    def inspect_result(
        self,
        result: Any,
        *,
        target: str = "tools/call",
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> tuple[list[SecurityFinding], Any]:
        """Inspect and optionally redact an MCP response payload."""
        if not self.config.enabled:
            return [], result

        findings: list[SecurityFinding] = []
        processed = self._walk_and_inspect(result, target=target, mode=mode, findings=findings)
        if mode == GuardMode.AUDIT:
            return findings, result
        return findings, processed

    def _walk_and_inspect(
        self,
        value: Any,
        *,
        target: str,
        mode: GuardMode,
        findings: list[SecurityFinding],
    ) -> Any:
        if isinstance(value, str):
            return self._inspect_string(value, target=target, mode=mode, findings=findings)
        if isinstance(value, dict):
            return {
                key: self._walk_and_inspect(
                    item,
                    target=f"{target}.{key}",
                    mode=mode,
                    findings=findings,
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._walk_and_inspect(
                    item,
                    target=f"{target}[{idx}]",
                    mode=mode,
                    findings=findings,
                )
                for idx, item in enumerate(value)
            ]
        return value

    def _inspect_string(
        self,
        text: str,
        *,
        target: str,
        mode: GuardMode,
        findings: list[SecurityFinding],
    ) -> str:
        if self.config.detect_indirect_injection:
            ipi_action = Action.BLOCK if mode == GuardMode.ENFORCE else Action.LOG
            for label, severity, pattern in _IPI_PATTERNS:
                match = pattern.search(text)
                if match is not None:
                    findings.append(
                        SecurityFinding(
                            rule_id="MCP-IPI-001",
                            detector="response_guard",
                            severity=severity,
                            title="Indirect prompt injection detected in tool output",
                            description=f"Response payload contains {label}.",
                            target=target,
                            evidence=match.group(0)[:160],
                            remediation=(
                                "Treat external tool output as untrusted data and block or "
                                "sanitize injected instructions."
                            ),
                            action_taken=ipi_action,
                            metadata={"indicator": label},
                        )
                    )
                    break

        if not self.config.detect_secrets:
            return text

        redact_action = (
            Action.REDACT if mode in (GuardMode.ENFORCE, GuardMode.REDACT) else Action.LOG
        )
        redacted_text = text

        for rule in _SECRET_RULES:
            spans_to_replace: list[tuple[int, int]] = []
            for match in rule.pattern.finditer(redacted_text):
                secret_val = match.group(rule.group)
                entropy = shannon_entropy(secret_val)
                if rule.require_entropy and entropy < self.config.entropy_threshold:
                    continue
                findings.append(
                    SecurityFinding(
                        rule_id=rule.rule_id,
                        detector="response_guard",
                        severity=rule.severity,
                        title=rule.title,
                        description="Sensitive credential or secret material detected in response.",
                        target=target,
                        evidence=_mask_secret(secret_val),
                        remediation="Remove or redact credentials from tool and resource outputs.",
                        action_taken=redact_action,
                        metadata={
                            "rule_id": rule.rule_id,
                            "entropy": round(shannon_entropy(secret_val), 3),
                        },
                    )
                )
                if mode in (GuardMode.ENFORCE, GuardMode.REDACT):
                    spans_to_replace.append((match.start(rule.group), match.end(rule.group)))

            if spans_to_replace:
                placeholder = f"[REDACTED:{rule.rule_id}]"
                pieces: list[str] = []
                cursor = 0
                for start, end in spans_to_replace:
                    pieces.append(redacted_text[cursor:start])
                    pieces.append(placeholder)
                    cursor = end
                pieces.append(redacted_text[cursor:])
                redacted_text = "".join(pieces)

        return redacted_text
