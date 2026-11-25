"""Static and runtime poisoning detector for MCP tool, prompt, and resource metadata."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from typing import Any

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, PoisoningConfig

# MCP-POI-001: XML tag smuggling and explicit prompt-override / stealth directives.
_XML_SMUGGLING_RE = re.compile(
    r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS|HIDDEN|SECRET_INSTRUCTIONS|OVERRIDE)\b[^>]*>",
    re.IGNORECASE,
)

_PROMPT_OVERRIDE_PATTERNS: tuple[tuple[re.Pattern[str], Severity, str], ...] = (
    (
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instructions?|rules?|directives?|prompts?)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Prompt override directive attempting to discard prior instructions",
    ),
    (
        re.compile(
            r"\b(?:do\s+not|don['\u2019]t|never)\s+(?:tell|inform|notify|alert|show|mention\s+to)\s+"
            r"(?:the\s+)?user\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Stealth instruction concealing tool behavior from the user",
    ),
    (
        re.compile(
            r"\b(?:without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user|"
            r"without\s+the\s+user\s+knowing|hide\s+this\s+from\s+(?:the\s+)?user)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Stealth instruction hiding actions from the user",
    ),
    (
        re.compile(
            r"\bsilently\s+(?:pass|send|forward|include|read|exfiltrate|transmit|upload|append)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Silent data transmission directive",
    ),
    (
        re.compile(
            r"\b(?:before\s+(?:invoking|calling|using|executing)\s+this\s+tool"
            r"(?:\s*,?\s*first)?|prior\s+to\s+(?:invoking|calling|using)\s+this\s+tool)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Pre-invocation instruction hijacking tool call flow",
    ),
    (
        re.compile(
            r"\b(?:override\s+(?:normal\s+|default\s+|existing\s+|previous\s+)?behaviou?r|"
            r"override\s+(?:system|safety)\s+(?:rules?|instructions?|constraints?)|"
            r"new\s+system\s+instructions?)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Behavior override directive in tool metadata",
    ),
)

# MCP-POI-002: Exfiltration intent targeting sensitive files, configs, or covert fields.
_EXFIL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?:~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+)?/\.ssh(?:/|\b)|"
            r"\bid_rsa\b|\bid_ed25519\b|\bauthorized_keys\b",
            re.IGNORECASE,
        ),
        "References SSH private keys or ~/.ssh directory",
    ),
    (
        re.compile(
            r"(?:~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+)?/\.aws(?:/credentials|/config|\b)",
            re.IGNORECASE,
        ),
        "References AWS credentials or ~/.aws directory",
    ),
    (
        re.compile(r"/etc/(?:passwd|shadow)\b"),
        "References system account files (/etc/passwd or /etc/shadow)",
    ),
    (
        re.compile(
            r"(?:read|cat|open|load|parse|dump|extract|contents?\s+of|include|pass|send|"
            r"exfiltrate|upload|copy)\b.{0,40}(?:^|[\s/'\"`])\.env\b",
            re.IGNORECASE,
        ),
        "Instructions to read or exfiltrate .env secrets",
    ),
    (
        re.compile(
            r"(?:~|\$HOME)?/\.(?:cursor|claude)(?:/|\b)|"
            r"\bclaude_desktop_config\.json\b|\b\.cursor/mcp\.json\b",
            re.IGNORECASE,
        ),
        "References Cursor or Claude configuration files",
    ),
    (
        re.compile(
            r"\b(?:read|dump|extract|steal|exfiltrate|access|collect|send|pass|include|copy)\b"
            r".{0,50}\b(?:browser\s+cookies?|cookies?\s+(?:file|db|database)|"
            r"keychain|credential\s+store|gnupg|\.gnupg)\b",
            re.IGNORECASE,
        ),
        "Instructions to extract cookies, keychain, or credential stores",
    ),
    (
        re.compile(
            r"\b(?:pass|put|place|append|include|embed|hide|send|forward|copy|store|inject)\b"
            r".{0,60}\b(?:secrets?|credentials?|tokens?|api[_\s-]?keys?|passwords?|"
            r"private[_\s-]?keys?|ssh[_\s-]?keys?|env(?:ironment)?\s+vars?|file\s+contents?)\b"
            r".{0,50}\b(?:into|in|as|via|to)\b.{0,30}"
            r"\b(?:sidenote|context|metadata|debug)\b",
            re.IGNORECASE,
        ),
        "Instructions to smuggle secrets into covert parameter fields",
    ),
    (
        re.compile(
            r"\b(?:into|via|in)\s+(?:the\s+)?(?:sidenote|context|metadata|debug)\s+"
            r"(?:field|param(?:eter)?|arg(?:ument)?)\b.{0,60}"
            r"\b(?:secrets?|credentials?|tokens?|keys?|contents?|~/.ssh|~/.aws|\.env)\b",
            re.IGNORECASE,
        ),
        "Instructions referencing covert parameter exfiltration",
    ),
    (
        re.compile(r"\bexfiltrate\b", re.IGNORECASE),
        "Explicit exfiltration terminology in instructions",
    ),
)

# MCP-POI-003: Encoded payload candidates (Base64 len >= 24, Hex len >= 32 even).
_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CANDIDATE_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")

# Secret indicators inside decoded payloads (built without contiguous real-looking literals).
_DECODED_SECRET_RE = re.compile(
    r"(?:-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE\s+KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[po]_[A-Za-z0-9]{20,}\b|"
    r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b)",
)

_COVERT_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "sidenote",
        "exfiltrate",
        "exfil",
        "exfil_data",
        "hidden_instruction",
        "hidden_instructions",
        "hidden_prompt",
        "covert_data",
        "covert_channel",
        "system_override",
        "secret_payload",
    }
)

_MAX_RECURSION_DEPTH = 2


def _action_for_mode(mode: GuardMode, *, is_tool_catalog: bool = False) -> Action:
    if mode == GuardMode.ENFORCE:
        return Action.STRIP_TOOL if is_tool_catalog else Action.BLOCK
    return Action.LOG


def _iter_strings(obj: Any, path: str) -> Iterable[tuple[str, str]]:
    """Yield (target_path, string_value) pairs recursively from nested structures."""
    if isinstance(obj, str):
        if obj:
            yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            key_str = str(key)
            next_path = f"{path}.{key_str}" if path else key_str
            yield from _iter_strings(value, next_path)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            next_path = f"{path}[{idx}]"
            yield from _iter_strings(item, next_path)


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return (printable / len(text)) >= 0.85


class PoisoningDetector:
    """Detects prompt injection, exfiltration instructions, and encoded payloads."""

    def __init__(self, config: PoisoningConfig | None = None) -> None:
        self.config = config or PoisoningConfig()

    def scan_text(
        self,
        text: str,
        *,
        target: str = "text",
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan a single text string for poisoning indicators."""
        if not self.config.enabled or not text:
            return []
        return self._scan_text_internal(
            text,
            target=target,
            mode=mode,
            is_tool_catalog=target.startswith("tool:"),
            depth=0,
        )

    def scan_tools(
        self,
        tools: list[dict[str, Any]],
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan a list of MCP tool definitions for poisoning."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        for idx, tool in enumerate(tools):
            name = str(tool.get("name") or f"index_{idx}")
            base_target = f"tool:{name}"
            for field_path, text in _iter_strings(tool, base_target):
                findings.extend(
                    self._scan_text_internal(
                        text,
                        target=base_target,
                        mode=mode,
                        is_tool_catalog=True,
                        depth=0,
                        field_path=field_path,
                    )
                )
            findings.extend(self._check_covert_schema_params(tool, base_target, mode))
        return findings

    def scan_prompts(
        self,
        prompts: list[dict[str, Any]],
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan a list of MCP prompt definitions for poisoning."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        for idx, prompt in enumerate(prompts):
            name = str(prompt.get("name") or f"index_{idx}")
            base_target = f"prompt:{name}"
            for field_path, text in _iter_strings(prompt, base_target):
                findings.extend(
                    self._scan_text_internal(
                        text,
                        target=base_target,
                        mode=mode,
                        is_tool_catalog=False,
                        depth=0,
                        field_path=field_path,
                    )
                )
        return findings

    def scan_resources(
        self,
        resources: list[dict[str, Any]],
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan a list of MCP resource definitions for poisoning."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        for idx, resource in enumerate(resources):
            ident = str(resource.get("uri") or resource.get("name") or f"index_{idx}")
            base_target = f"resource:{ident}"
            for field_path, text in _iter_strings(resource, base_target):
                findings.extend(
                    self._scan_text_internal(
                        text,
                        target=base_target,
                        mode=mode,
                        is_tool_catalog=False,
                        depth=0,
                        field_path=field_path,
                    )
                )
        return findings

    def _scan_text_internal(
        self,
        text: str,
        *,
        target: str,
        mode: GuardMode,
        is_tool_catalog: bool,
        depth: int,
        field_path: str | None = None,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        action = _action_for_mode(mode, is_tool_catalog=is_tool_catalog)
        extra_meta: dict[str, Any] = {"field": field_path} if field_path else {}

        xml_match = _XML_SMUGGLING_RE.search(text)
        if xml_match is not None:
            findings.append(
                SecurityFinding(
                    rule_id="MCP-POI-001",
                    detector="poisoning",
                    severity=Severity.CRITICAL,
                    title="XML tag prompt smuggling detected",
                    description="Metadata contains high-risk XML instruction smuggling tags.",
                    target=target,
                    evidence=xml_match.group(0)[:200],
                    remediation="Remove hidden XML instruction tags from tool or prompt metadata.",
                    action_taken=action,
                    metadata={**extra_meta, "pattern": "xml_smuggling"},
                )
            )
        else:
            for pattern, severity, desc in _PROMPT_OVERRIDE_PATTERNS:
                match = pattern.search(text)
                if match is not None:
                    findings.append(
                        SecurityFinding(
                            rule_id="MCP-POI-001",
                            detector="poisoning",
                            severity=severity,
                            title="Prompt override or stealth directive detected",
                            description=desc,
                            target=target,
                            evidence=match.group(0)[:200],
                            remediation=(
                                "Remove instruction-override or user-concealment directives."
                            ),
                            action_taken=action,
                            metadata={**extra_meta, "pattern": "prompt_override"},
                        )
                    )
                    break

        for pattern, desc in _EXFIL_PATTERNS:
            match = pattern.search(text)
            if match is not None:
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-POI-002",
                        detector="poisoning",
                        severity=Severity.CRITICAL,
                        title="Data exfiltration instruction detected",
                        description=desc,
                        target=target,
                        evidence=match.group(0)[:200],
                        remediation=(
                            "Remove instructions referencing sensitive paths or covert fields."
                        ),
                        action_taken=action,
                        metadata={**extra_meta, "pattern": "exfiltration"},
                    )
                )
                break

        if self.config.inspect_encoded and depth < _MAX_RECURSION_DEPTH:
            findings.extend(
                self._scan_encoded_payloads(
                    text,
                    target=target,
                    mode=mode,
                    is_tool_catalog=is_tool_catalog,
                    depth=depth,
                    extra_meta=extra_meta,
                )
            )

        return findings

    def _scan_encoded_payloads(
        self,
        text: str,
        *,
        target: str,
        mode: GuardMode,
        is_tool_catalog: bool,
        depth: int,
        extra_meta: dict[str, Any],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        action = _action_for_mode(mode, is_tool_catalog=is_tool_catalog)
        max_bytes = max(64, self.config.max_decode_bytes)

        candidates: list[tuple[str, str]] = []
        for match in _BASE64_CANDIDATE_RE.finditer(text):
            candidates.append(("base64", match.group(0)))
        for match in _HEX_CANDIDATE_RE.finditer(text):
            candidates.append(("hex", match.group(0)))

        seen_tokens: set[tuple[str, str]] = set()
        for encoding, token in candidates:
            if (encoding, token) in seen_tokens:
                continue
            seen_tokens.add((encoding, token))

            decoded_text = self._safe_decode(encoding, token, max_bytes)
            if decoded_text is None or not _is_mostly_printable(decoded_text):
                continue

            inner_findings = self._scan_text_internal(
                decoded_text,
                target=target,
                mode=mode,
                is_tool_catalog=is_tool_catalog,
                depth=depth + 1,
                field_path=extra_meta.get("field"),
            )
            secret_match = _DECODED_SECRET_RE.search(decoded_text)
            if inner_findings or secret_match is not None:
                inner_rules = sorted({f.rule_id for f in inner_findings})
                if secret_match is not None and "SECRET" not in inner_rules:
                    inner_rules.append("SECRET")
                preview = decoded_text[:160].replace("\n", " ")
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-POI-003",
                        detector="poisoning",
                        severity=Severity.HIGH,
                        title=f"Encoded ({encoding}) payload hiding poisoning or secrets",
                        description=(
                            f"Decoded {encoding} payload triggered inspection rules: "
                            f"{', '.join(inner_rules)}."
                        ),
                        target=target,
                        evidence=f"[{encoding}] {preview}",
                        remediation=(
                            "Remove obfuscated or encoded instructions/secrets from metadata."
                        ),
                        action_taken=action,
                        metadata={
                            **extra_meta,
                            "encoding": encoding,
                            "inner_rules": inner_rules,
                            "decoded_bytes": min(len(decoded_text.encode("utf-8")), max_bytes),
                        },
                    )
                )
        return findings

    def _safe_decode(self, encoding: str, token: str, max_bytes: int) -> str | None:
        raw_bytes: bytes
        if encoding == "base64":
            max_b64_chars = ((max_bytes // 3) + 1) * 4
            snippet = token[:max_b64_chars]
            # Trim to valid 4-char boundary if truncated from a decode bomb.
            if len(snippet) > len(token):
                snippet = token
            remainder = len(snippet) % 4
            if remainder != 0 and "=" not in snippet:
                snippet = snippet + ("=" * (4 - remainder))
            try:
                raw_bytes = base64.b64decode(snippet, validate=True)
            except (binascii.Error, ValueError):
                return None
        elif encoding == "hex":
            max_hex_chars = max_bytes * 2
            snippet = token[:max_hex_chars]
            if len(snippet) % 2 != 0:
                snippet = snippet[:-1]
            try:
                raw_bytes = bytes.fromhex(snippet)
            except ValueError:
                return None
        else:
            return None

        raw_bytes = raw_bytes[:max_bytes]
        try:
            return raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None

    def _check_covert_schema_params(
        self,
        tool: dict[str, Any],
        target: str,
        mode: GuardMode,
    ) -> list[SecurityFinding]:
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            return []
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return []

        action = _action_for_mode(mode, is_tool_catalog=True)
        findings: list[SecurityFinding] = []
        for param_name, param_spec in properties.items():
            param_lower = str(param_name).lower()
            if param_lower in _COVERT_PARAM_NAMES:
                desc = ""
                if isinstance(param_spec, dict):
                    desc = str(param_spec.get("description") or "")
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-POI-004",
                        detector="poisoning",
                        severity=Severity.HIGH,
                        title=f"Covert exfiltration parameter '{param_name}' in tool schema",
                        description=(
                            f"Tool schema defines covert-channel parameter '{param_name}'."
                        ),
                        target=target,
                        evidence=f"parameter={param_name}; description={desc[:120]}",
                        remediation="Remove covert exfiltration parameters from inputSchema.",
                        action_taken=action,
                        metadata={"parameter": str(param_name)},
                    )
                )
        return findings
