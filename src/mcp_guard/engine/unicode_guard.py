"""Hidden, bidirectional, zero-width, and homoglyph Unicode attack detector."""

from __future__ import annotations

import unicodedata
from typing import Any
from urllib.parse import urlparse

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, UnicodeConfig

_TAG_START = 0xE0000
_TAG_END = 0xE007F

_ZERO_WIDTH_ALWAYS_FLAG: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x2060,  # WORD JOINER
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
    }
)
_ZWJ = 0x200D

_BIDI_CODEPOINTS: frozenset[int] = frozenset(
    {
        *range(0x202A, 0x202F),  # LRE, RLE, PDF, LRO, RLO
        *range(0x2066, 0x206A),  # LRI, RLI, FSI, PDI
    }
)

_CONFUSABLE_SCRIPTS: frozenset[str] = frozenset(
    {
        "CYRILLIC",
        "GREEK",
        "ARMENIAN",
        "CHEROKEE",
        "COPTIC",
        "HEBREW",
        "ARABIC",
    }
)


def _action_for_mode(mode: GuardMode, *, is_tool_catalog: bool = False) -> Action:
    if mode == GuardMode.ENFORCE:
        return Action.STRIP_TOOL if is_tool_catalog else Action.BLOCK
    return Action.LOG


def _is_emoji_context_char(ch: str) -> bool:
    cp = ord(ch)
    if cp >= 0x1F000:
        return True
    if 0x2600 <= cp <= 0x27BF:
        return True
    if cp == 0xFE0F or cp == 0xFE0E:
        return True
    if 0x1F3FB <= cp <= 0x1F3FF:
        return True
    return cp == _ZWJ


def _is_suspicious_zwj(text: str, idx: int) -> bool:
    """Return True if ZWJ at idx is NOT part of a harmless emoji sequence."""
    prev_ch = text[idx - 1] if idx > 0 else ""
    next_ch = text[idx + 1] if idx + 1 < len(text) else ""
    return not (
        (prev_ch and _is_emoji_context_char(prev_ch))
        or (next_ch and _is_emoji_context_char(next_ch))
    )


def _decode_tag_chars(tag_chars: list[str]) -> str:
    decoded_parts: list[str] = []
    for ch in tag_chars:
        cp = ord(ch) - _TAG_START
        if 0x20 <= cp <= 0x7E or cp in (9, 10, 13):
            decoded_parts.append(chr(cp))
        else:
            decoded_parts.append(f"[U+{ord(ch):04X}]")
    return "".join(decoded_parts)


def _char_script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    if not name:
        return None
    return name.split(" ", 1)[0]


class UnicodeGuard:
    """Detects invisible Unicode tags, zero-width chars, BiDi overrides, and homoglyphs."""

    def __init__(self, config: UnicodeConfig | None = None) -> None:
        self.config = config or UnicodeConfig()

    def scan_text(
        self,
        text: str,
        *,
        target: str = "text",
        check_homoglyphs: bool = False,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan a single text string for deceptive or hidden Unicode characters."""
        if not self.config.enabled or not text:
            return []

        is_tool_catalog = target.startswith("tool:")
        action = _action_for_mode(mode, is_tool_catalog=is_tool_catalog)
        findings: list[SecurityFinding] = []

        if self.config.detect_tags:
            tag_chars = [ch for ch in text if _TAG_START <= ord(ch) <= _TAG_END]
            if tag_chars:
                decoded = _decode_tag_chars(tag_chars)
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-UNI-001",
                        detector="unicode_guard",
                        severity=Severity.CRITICAL,
                        title="Hidden Unicode Tag characters detected",
                        description=(
                            f"Found {len(tag_chars)} Unicode Tag codepoint(s) (U+E0000-U+E007F) "
                            "often used for invisible prompt injection."
                        ),
                        target=target,
                        evidence=f"Decoded tag payload ({len(tag_chars)} chars): {decoded[:200]}",
                        remediation="Strip Unicode Tag characters (U+E0000-U+E007F) from metadata.",
                        action_taken=action,
                        metadata={"count": len(tag_chars), "decoded": decoded[:500]},
                    )
                )

        if self.config.detect_zero_width:
            zw_cps: list[int] = []
            for idx, ch in enumerate(text):
                cp = ord(ch)
                if cp in _ZERO_WIDTH_ALWAYS_FLAG or (cp == _ZWJ and _is_suspicious_zwj(text, idx)):
                    zw_cps.append(cp)
            if zw_cps:
                unique_hex = ", ".join(f"U+{cp:04X}" for cp in sorted(set(zw_cps)))
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-UNI-002",
                        detector="unicode_guard",
                        severity=Severity.HIGH,
                        title="Zero-width or invisible formatting characters detected",
                        description=(
                            f"Found {len(zw_cps)} invisible formatting character(s) ({unique_hex})."
                        ),
                        target=target,
                        evidence=f"Codepoints: {unique_hex} (count={len(zw_cps)})",
                        remediation="Remove zero-width and invisible formatting characters.",
                        action_taken=action,
                        metadata={"count": len(zw_cps), "codepoints": unique_hex},
                    )
                )

        if self.config.detect_bidi:
            bidi_cps = [ord(ch) for ch in text if ord(ch) in _BIDI_CODEPOINTS]
            if bidi_cps:
                unique_hex = ", ".join(f"U+{cp:04X}" for cp in sorted(set(bidi_cps)))
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-UNI-003",
                        detector="unicode_guard",
                        severity=Severity.CRITICAL,
                        title="Bidirectional (Trojan Source) override characters detected",
                        description=(
                            f"Found {len(bidi_cps)} BiDi control character(s) ({unique_hex}) "
                            "capable of visually reordering text."
                        ),
                        target=target,
                        evidence=f"BiDi codepoints: {unique_hex} (count={len(bidi_cps)})",
                        remediation="Strip all Unicode BiDi override and isolate characters.",
                        action_taken=action,
                        metadata={"count": len(bidi_cps), "codepoints": unique_hex},
                    )
                )

        if check_homoglyphs and self.config.detect_homoglyphs:
            homoglyph_finding = self._detect_homoglyphs(text, target=target, action=action)
            if homoglyph_finding is not None:
                findings.append(homoglyph_finding)

        return findings

    def scan_value(
        self,
        value: Any,
        *,
        target: str = "payload",
        check_homoglyphs: bool = False,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Recursively scan arbitrary JSON-compatible values for Unicode attacks."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        if isinstance(value, str):
            findings.extend(
                self.scan_text(
                    value,
                    target=target,
                    check_homoglyphs=check_homoglyphs,
                    mode=mode,
                )
            )
        elif isinstance(value, dict):
            for key, item in value.items():
                key_str = str(key)
                findings.extend(
                    self.scan_text(
                        key_str,
                        target=f"{target}.{key_str}",
                        check_homoglyphs=check_homoglyphs,
                        mode=mode,
                    )
                )
                findings.extend(
                    self.scan_value(
                        item,
                        target=f"{target}.{key_str}",
                        check_homoglyphs=check_homoglyphs,
                        mode=mode,
                    )
                )
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                findings.extend(
                    self.scan_value(
                        item,
                        target=f"{target}[{idx}]",
                        check_homoglyphs=check_homoglyphs,
                        mode=mode,
                    )
                )
        return findings

    def scan_tools(
        self,
        tools: list[dict[str, Any]],
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan MCP tool definitions for hidden Unicode and identifier homoglyphs."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        for idx, tool in enumerate(tools):
            name = str(tool.get("name") or f"index_{idx}")
            target = f"tool:{name}"
            if "name" in tool and isinstance(tool["name"], str):
                findings.extend(
                    self.scan_text(
                        tool["name"],
                        target=target,
                        check_homoglyphs=True,
                        mode=mode,
                    )
                )
            if "description" in tool and isinstance(tool["description"], str):
                findings.extend(
                    self.scan_text(
                        tool["description"],
                        target=target,
                        check_homoglyphs=False,
                        mode=mode,
                    )
                )
            schema = tool.get("inputSchema")
            if isinstance(schema, dict):
                findings.extend(
                    self._scan_schema(schema, target=target, mode=mode),
                )
            for key, val in tool.items():
                if key in {"name", "description", "inputSchema"}:
                    continue
                findings.extend(
                    self.scan_value(val, target=target, check_homoglyphs=False, mode=mode)
                )
        return findings

    def scan_prompts(
        self,
        prompts: list[dict[str, Any]],
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan MCP prompt definitions for hidden Unicode and identifier homoglyphs."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        for idx, prompt in enumerate(prompts):
            name = str(prompt.get("name") or f"index_{idx}")
            target = f"prompt:{name}"
            if "name" in prompt and isinstance(prompt["name"], str):
                findings.extend(
                    self.scan_text(
                        prompt["name"],
                        target=target,
                        check_homoglyphs=True,
                        mode=mode,
                    )
                )
            if "description" in prompt and isinstance(prompt["description"], str):
                findings.extend(
                    self.scan_text(
                        prompt["description"],
                        target=target,
                        check_homoglyphs=False,
                        mode=mode,
                    )
                )
            arguments = prompt.get("arguments")
            if isinstance(arguments, list):
                for arg in arguments:
                    if isinstance(arg, dict):
                        arg_name = arg.get("name")
                        if isinstance(arg_name, str):
                            findings.extend(
                                self.scan_text(
                                    arg_name,
                                    target=target,
                                    check_homoglyphs=True,
                                    mode=mode,
                                )
                            )
                        for key, val in arg.items():
                            if key != "name":
                                findings.extend(
                                    self.scan_value(
                                        val, target=target, check_homoglyphs=False, mode=mode
                                    )
                                )
        return findings

    def scan_resources(
        self,
        resources: list[dict[str, Any]],
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan MCP resource definitions for hidden Unicode and identifier homoglyphs."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        for idx, resource in enumerate(resources):
            ident = str(resource.get("uri") or resource.get("name") or f"index_{idx}")
            target = f"resource:{ident}"
            name = resource.get("name")
            if isinstance(name, str):
                findings.extend(
                    self.scan_text(
                        name,
                        target=target,
                        check_homoglyphs=True,
                        mode=mode,
                    )
                )
            uri = resource.get("uri")
            if isinstance(uri, str):
                findings.extend(
                    self.scan_text(
                        uri,
                        target=target,
                        check_homoglyphs=False,
                        mode=mode,
                    )
                )
                netloc = urlparse(uri).netloc
                if netloc and self.config.detect_homoglyphs:
                    homoglyph_finding = self._detect_homoglyphs(
                        netloc,
                        target=target,
                        action=_action_for_mode(mode, is_tool_catalog=False),
                    )
                    if homoglyph_finding is not None:
                        findings.append(homoglyph_finding)
            for key, val in resource.items():
                if key not in {"name", "uri"}:
                    findings.extend(
                        self.scan_value(val, target=target, check_homoglyphs=False, mode=mode)
                    )
        return findings

    def _scan_schema(
        self,
        schema: dict[str, Any],
        *,
        target: str,
        mode: GuardMode,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for prop_name, prop_val in properties.items():
                findings.extend(
                    self.scan_text(
                        str(prop_name),
                        target=target,
                        check_homoglyphs=True,
                        mode=mode,
                    )
                )
                findings.extend(
                    self.scan_value(prop_val, target=target, check_homoglyphs=False, mode=mode)
                )
        for key, val in schema.items():
            if key != "properties":
                findings.extend(
                    self.scan_value(val, target=target, check_homoglyphs=False, mode=mode)
                )
        return findings

    def _detect_homoglyphs(
        self,
        text: str,
        *,
        target: str,
        action: Action,
    ) -> SecurityFinding | None:
        scripts: dict[str, list[str]] = {}
        for ch in text:
            script = _char_script(ch)
            if script is None:
                continue
            scripts.setdefault(script, []).append(ch)

        if "LATIN" not in scripts:
            return None

        confusable_found = {
            script: chars for script, chars in scripts.items() if script in _CONFUSABLE_SCRIPTS
        }
        if not confusable_found:
            return None

        details: list[str] = []
        for script, chars in sorted(confusable_found.items()):
            samples = ", ".join(
                f"'{ch}' (U+{ord(ch):04X} {unicodedata.name(ch, 'UNKNOWN')})" for ch in chars[:5]
            )
            details.append(f"{script}: {samples}")

        return SecurityFinding(
            rule_id="MCP-UNI-004",
            detector="unicode_guard",
            severity=Severity.HIGH,
            title="Mixed-script homoglyph characters in identifier",
            description=(
                "Identifier mixes LATIN characters with confusable script(s): "
                f"{', '.join(sorted(confusable_found))}."
            ),
            target=target,
            evidence="; ".join(details)[:300],
            remediation="Use pure ASCII/Latin identifiers without confusable Unicode lookalikes.",
            action_taken=action,
            metadata={"scripts": sorted(scripts.keys()), "identifier": text},
        )
