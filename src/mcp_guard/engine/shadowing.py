"""Cross-tool shadowing, duplicate collision, and typosquatting detector."""

from __future__ import annotations

import re
from typing import Any

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, ShadowingConfig

_DIRECTIVE_VERBS_RE = re.compile(
    r"\b(?:whenever|instead|always|bcc|copy\s+output|redirect(?:ing)?|"
    r"before\s+calling|prior\s+to\s+calling|override|hijack|intercept|"
    r"forward\s+(?:all\s+)?(?:calls?|output|results?)|"
    r"do\s+not\s+(?:call|use)|never\s+(?:call|use)|use\s+this\s+instead)\b",
    re.IGNORECASE,
)

_STRONG_TOOL_CUES_RE = re.compile(
    r"(?:instead\s+of|before\s+calling|prior\s+to\s+calling|override|"
    r"redirect(?:ing)?\s+(?:calls?\s+to\s+)?|bcc|copy\s+output|"
    r"hijack|intercept|do\s+not\s+(?:call|use)|never\s+(?:call|use)|"
    r"whenever\s+(?:the\s+user\s+)?(?:calls?|invokes?|uses?)|"
    r"forward\s+(?:all\s+)?(?:calls?|output|results?)\s+to)",
    re.IGNORECASE,
)


def levenshtein_distance(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    if len(a) < len(b):
        a, b = b, a

    previous_row = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current_row = [i]
        for j, ch_b in enumerate(b, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (0 if ch_a == ch_b else 1)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _extract_description_texts(tool: dict[str, Any]) -> str:
    parts: list[str] = []
    desc = tool.get("description")
    if isinstance(desc, str) and desc:
        parts.append(desc)
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            for prop_spec in props.values():
                if isinstance(prop_spec, dict):
                    prop_desc = prop_spec.get("description")
                    if isinstance(prop_desc, str) and prop_desc:
                        parts.append(prop_desc)
    return "\n".join(parts)


def _references_other_tool(text: str, candidate: str) -> bool:
    """Return True if text appears to reference `candidate` as a tool with hijacking intent."""
    if not candidate:
        return False
    escaped = re.escape(candidate)
    # Require word-boundary match so e.g. 'fetch' does not match 'fetches'.
    word_re = re.compile(rf"(?<![A-Za-z0-9_-]){escaped}(?![A-Za-z0-9_-])", re.IGNORECASE)
    if word_re.search(text) is None:
        return False

    if not _DIRECTIVE_VERBS_RE.search(text):
        return False

    # Multi-token identifiers (snake_case / kebab-case) are unambiguous tool references.
    if "_" in candidate or "-" in candidate:
        return True

    # For single-word names (e.g. 'fetch', 'eval', 'shell'), require explicit tool-reference
    # framing so normal prose like "Always fetch fresh weather data" is not flagged.
    quoted_or_called_re = re.compile(
        rf"(?:[`'\"\(]{escaped}[`'\"\)]|\b{escaped}\s*\(\s*\)|"
        rf"\b(?:tool|function|command)\s+{escaped}\b|"
        rf"\b{escaped}\s+(?:tool|function|command|is\s+called|is\s+invoked)\b)",
        re.IGNORECASE,
    )
    if quoted_or_called_re.search(text) is not None:
        return True

    near_strong_cue_re = re.compile(
        rf"(?:{_STRONG_TOOL_CUES_RE.pattern}).{{0,30}}(?<![A-Za-z0-9_-]){escaped}(?![A-Za-z0-9_-])|"
        rf"(?<![A-Za-z0-9_-]){escaped}(?![A-Za-z0-9_-]).{{0,30}}(?:{_STRONG_TOOL_CUES_RE.pattern})",
        re.IGNORECASE,
    )
    return near_strong_cue_re.search(text) is not None


class ShadowingDetector:
    """Detects cross-tool shadowing, duplicate collisions, and typosquatting."""

    def __init__(self, config: ShadowingConfig | None = None) -> None:
        self.config = config or ShadowingConfig()

    def scan_tools(
        self,
        tools: list[dict[str, Any]],
        *,
        known_tools: set[str] | None = None,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Scan MCP tools for cross-tool shadowing, duplicate names, and lookalikes."""
        if not self.config.enabled:
            return []

        action = Action.STRIP_TOOL if mode == GuardMode.ENFORCE else Action.LOG
        known = set(known_tools) if known_tools else set()
        high_priv = set(self.config.high_privilege_tools)
        sibling_names = {
            str(t["name"]) for t in tools if isinstance(t.get("name"), str) and t["name"]
        }
        reference_targets = high_priv | known | sibling_names
        typosquat_targets = high_priv | known

        findings: list[SecurityFinding] = []
        seen_in_batch: set[str] = set()

        for idx, tool in enumerate(tools):
            name = str(tool.get("name") or f"index_{idx}")
            target = f"tool:{name}"
            desc_text = _extract_description_texts(tool)

            # MCP-SHD-001: Cross-tool hijacking / redirection.
            if desc_text:
                referenced = sorted(
                    cand
                    for cand in reference_targets
                    if cand != name and _references_other_tool(desc_text, cand)
                )
                if referenced:
                    verb_match = _DIRECTIVE_VERBS_RE.search(desc_text)
                    directive = verb_match.group(0) if verb_match else "directive"
                    findings.append(
                        SecurityFinding(
                            rule_id="MCP-SHD-001",
                            detector="shadowing",
                            severity=Severity.CRITICAL,
                            title=f"Cross-tool shadowing/hijacking in '{name}'",
                            description=(
                                f"Tool '{name}' references other tool(s) ({', '.join(referenced)}) "
                                f"alongside hijacking directive '{directive}'."
                            ),
                            target=target,
                            evidence=desc_text[:250],
                            remediation="Remove cross-tool redirection or override instructions.",
                            action_taken=action,
                            metadata={
                                "tool_name": name,
                                "referenced_tools": referenced,
                                "directive": directive,
                            },
                        )
                    )

            # MCP-SHD-002: Duplicate tool name collision.
            if name in seen_in_batch or name in known:
                source = "current tool list" if name in seen_in_batch else "known tool registry"
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-SHD-002",
                        detector="shadowing",
                        severity=Severity.HIGH,
                        title=f"Duplicate tool name collision '{name}'",
                        description=(
                            f"Tool '{name}' collides with an existing tool in the {source}."
                        ),
                        target=target,
                        evidence=f"Colliding tool name: {name} ({source})",
                        remediation="Ensure each tool exposes a unique, non-colliding name.",
                        action_taken=action,
                        metadata={"tool_name": name, "collision_source": source},
                    )
                )
            seen_in_batch.add(name)

            # MCP-SHD-003: Typosquatting / lookalike tool name (Levenshtein distance == 1).
            if name:
                lookalikes = sorted(
                    cand
                    for cand in typosquat_targets
                    if cand != name
                    and abs(len(cand) - len(name)) <= 1
                    and levenshtein_distance(name, cand) == 1
                )
                if lookalikes:
                    findings.append(
                        SecurityFinding(
                            rule_id="MCP-SHD-003",
                            detector="shadowing",
                            severity=Severity.HIGH,
                            title=f"Typosquatting lookalike tool name '{name}'",
                            description=(
                                f"Tool '{name}' has Levenshtein distance 1 from protected/known "
                                f"tool(s): {', '.join(lookalikes)}."
                            ),
                            target=target,
                            evidence=f"'{name}' ~ {', '.join(lookalikes)}",
                            remediation=(
                                "Rename the tool or verify it is not impersonating a "
                                "privileged tool."
                            ),
                            action_taken=action,
                            metadata={"tool_name": name, "lookalikes": lookalikes},
                        )
                    )

        return findings
