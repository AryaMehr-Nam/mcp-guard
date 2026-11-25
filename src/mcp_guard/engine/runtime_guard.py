"""Runtime argument, path, command-injection, SSRF, and allow/deny inspection."""

from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import unquote, urlparse

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, RuntimeGuardConfig

_URL_SCHEME_RE = re.compile(r"(?i)\b(?:https?|file|gopher)://\S+")

_SENSITIVE_FILENAMES: tuple[str, ...] = (
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
)

_SENSITIVE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?:^|/)\.ssh(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.aws(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.kube(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.gnupg(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.env(?:\.[^/]+)?$"),
    re.compile(r"(?i)(?:^|/)etc/shadow(?:/|$)"),
    re.compile(r"(?i)(?:^|/)etc/passwd(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.git/config$"),
)

_HOME_PATH_RE = re.compile(r"(?:^|/)~(?:[a-zA-Z0-9._-]*)?(?:/|$)")

_PATH_ARG_KEYS: frozenset[str] = frozenset(
    {
        "path",
        "file",
        "filepath",
        "file_path",
        "filename",
        "dir",
        "directory",
        "folder",
        "target",
        "uri",
        "src",
        "dest",
        "source",
        "destination",
        "root",
        "cwd",
        "location",
    }
)

_WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:[\\/]")

_CMD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("command substitution $(...)", re.compile(r"\$\([^)]*\)")),
    ("backtick command substitution", re.compile(r"`[^`]+`")),
    ("logical AND chain (&&)", re.compile(r"&&")),
    ("logical OR chain (||)", re.compile(r"\|\|")),
    ("pipe operator (|)", re.compile(r"\|\s*[A-Za-z0-9_./~$-]")),
    (
        "semicolon command separator (;)",
        re.compile(r";\s*(?!charset\s*=|base64,)[A-Za-z0-9_./~$\"'\-]"),
    ),
    ("/dev/tcp network redirection", re.compile(r"/dev/tcp/")),
    ("netcat -e reverse shell", re.compile(r"(?i)\bnc(?:at)?\b[^\r\n]*\s-e\b")),
    ("interactive bash shell (bash -i)", re.compile(r"(?i)\bbash\s+-i\b")),
    (
        "newline-chained shell command",
        re.compile(
            r"(?i)[\r\n]+\s*(?:bash|sh|zsh|dash|curl|wget|nc|ncat|python\d*|perl|ruby|php|"
            r"rm|cat|ls|id|whoami|uname|chmod|chown|touch|mkdir|cp|mv|echo|printf|kill|env|"
            r"export|eval|exec|/bin/|/usr/bin/)\b"
        ),
    ),
)

_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

_LOOPBACK_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)

_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def _action_for_mode(mode: GuardMode) -> Action:
    return Action.BLOCK if mode == GuardMode.ENFORCE else Action.LOG


def _decode_url_passes(value: str, passes: int = 3) -> str:
    current = value
    for _ in range(passes):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _iter_strings(value: Any, prefix: str = "arguments") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, dict):
        for key, item in value.items():
            key_str = str(key)
            next_prefix = f"{prefix}.{key_str}" if prefix else key_str
            yield from _iter_strings(item, next_prefix)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            next_prefix = f"{prefix}[{idx}]"
            yield from _iter_strings(item, next_prefix)


def _normalize_fs_path(raw_path: str) -> str:
    decoded = _decode_url_passes(raw_path).strip()
    if decoded.lower().startswith("file://"):
        parsed = urlparse(decoded)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            decoded = f"//{parsed.netloc}{parsed.path}"
        else:
            decoded = parsed.path
    normalized = decoded.replace("\\", "/")
    if (
        len(normalized) >= 3
        and normalized[0] == "/"
        and normalized[2] == ":"
        and normalized[1].isalpha()
    ):
        # Strip leading slash from file:///C:/... style URIs
        normalized = normalized[1:]
    return normalized


def _looks_like_path(arg_path: str, raw_value: str) -> bool:
    leaf_key = arg_path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
    if leaf_key in _PATH_ARG_KEYS:
        return True
    stripped = raw_value.strip()
    if stripped.lower().startswith(("http://", "https://", "gopher://")):
        return False
    if stripped.lower().startswith("file://"):
        return True
    if stripped.startswith(("/", "./", "../", "~/", "~\\", "\\")):
        return True
    return bool(_WINDOWS_DRIVE_RE.match(stripped))


def _canonical_compare_path(path_str: str) -> str:
    normalized = _normalize_fs_path(path_str)
    if _WINDOWS_DRIVE_RE.match(normalized):
        drive = normalized[:2].lower()
        rest = posixpath.normpath(normalized[2:])
        return f"{drive}{rest}"
    return posixpath.normpath(normalized)


def _is_under_allowed_path(candidate: str, allowed_paths: list[str]) -> bool:
    cand_norm = _canonical_compare_path(candidate)
    for allowed in allowed_paths:
        allowed_norm = _canonical_compare_path(allowed)
        if allowed_norm == "/":
            if cand_norm.startswith("/"):
                return True
            continue
        if cand_norm == allowed_norm or cand_norm.startswith(allowed_norm.rstrip("/") + "/"):
            return True
    return False


def _parse_int_part(part: str) -> int | None:
    if not part:
        return None
    try:
        if part.lower().startswith("0x"):
            return int(part, 16)
        if len(part) > 1 and part.startswith("0"):
            if any(ch not in "01234567" for ch in part):
                return None
            return int(part, 8)
        if not part.isdigit():
            return None
        return int(part, 10)
    except ValueError:
        return None


def _parse_obfuscated_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    cleaned = host.strip().rstrip(".")
    if not cleaned:
        return None
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]

    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass

    parts = cleaned.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    parsed_parts: list[int] = []
    for part in parts:
        val = _parse_int_part(part)
        if val is None or val < 0:
            return None
        parsed_parts.append(val)

    addr_int: int
    if len(parsed_parts) == 1:
        if parsed_parts[0] > 0xFFFFFFFF:
            return None
        addr_int = parsed_parts[0]
    elif len(parsed_parts) == 2:
        a, b = parsed_parts
        if a > 0xFF or b > 0xFFFFFF:
            return None
        addr_int = (a << 24) | b
    elif len(parsed_parts) == 3:
        a, b, c = parsed_parts
        if a > 0xFF or b > 0xFF or c > 0xFFFF:
            return None
        addr_int = (a << 24) | (b << 16) | c
    else:
        a, b, c, d = parsed_parts
        if max(a, b, c, d) > 0xFF:
            return None
        addr_int = (a << 24) | (b << 16) | (c << 8) | d

    return ipaddress.IPv4Address(addr_int)


def _is_metadata_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return _is_metadata_ip(ip_obj.ipv4_mapped)
    return str(ip_obj) in {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}


def _is_private_or_restricted_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return _is_private_or_restricted_ip(ip_obj.ipv4_mapped)
    if (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or ip_obj.is_reserved
    ):
        return True
    return bool(isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _CGNAT_NETWORK)


class RuntimeGuard:
    """Inspects MCP tool-call arguments and resource read URIs at runtime."""

    def __init__(self, config: RuntimeGuardConfig | None = None) -> None:
        self.config = config or RuntimeGuardConfig()

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Inspect a tool invocation's name and arguments for runtime policy violations."""
        if not self.config.enabled:
            return []

        findings: list[SecurityFinding] = []
        target = f"tools/call:{tool_name}"
        action = _action_for_mode(mode)

        findings.extend(self._check_tool_access(tool_name, target=target, action=action))

        if not arguments:
            return findings

        is_allowed_shell = any(
            fnmatch.fnmatchcase(tool_name, pattern) for pattern in self.config.allowed_shell_tools
        )

        for arg_path, raw_val in _iter_strings(arguments, prefix="arguments"):
            arg_target = f"{target}.{arg_path}"
            findings.extend(
                self._check_path_safety(
                    raw_val,
                    arg_path=arg_path,
                    target=arg_target,
                    action=action,
                    enforce_allowed_paths=_looks_like_path(arg_path, raw_val),
                )
            )
            if not is_allowed_shell:
                findings.extend(
                    self._check_command_injection(raw_val, target=arg_target, action=action)
                )
            findings.extend(
                self._check_ssrf(raw_val, target=arg_target, action=action, allow_file_scheme=False)
            )

        return findings

    def inspect_resource_read(
        self,
        uri: str,
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Inspect a resources/read URI for path traversal, sensitive paths, and SSRF."""
        if not self.config.enabled:
            return []

        action = _action_for_mode(mode)
        target = f"resources/read:{uri}"
        findings: list[SecurityFinding] = []

        parsed = urlparse(uri.strip())
        scheme = parsed.scheme.lower()
        is_local_resource = scheme in ("", "file")

        findings.extend(
            self._check_path_safety(
                uri,
                arg_path="uri",
                target=target,
                action=action,
                enforce_allowed_paths=is_local_resource,
            )
        )
        findings.extend(self._check_ssrf(uri, target=target, action=action, allow_file_scheme=True))
        return findings

    def _check_tool_access(
        self,
        tool_name: str,
        *,
        target: str,
        action: Action,
    ) -> list[SecurityFinding]:
        for pattern in self.config.denied_tools:
            if fnmatch.fnmatchcase(tool_name, pattern):
                return [
                    SecurityFinding(
                        rule_id="MCP-ARG-004",
                        detector="runtime_guard",
                        severity=Severity.HIGH,
                        title="Tool denied by policy denylist",
                        description=(
                            f"Tool '{tool_name}' matched denied_tools pattern '{pattern}'."
                        ),
                        target=target,
                        evidence=f"tool={tool_name}, pattern={pattern}",
                        remediation="Remove the tool call or update runtime_guard.denied_tools.",
                        action_taken=action,
                        metadata={"tool_name": tool_name, "pattern": pattern, "list": "denied"},
                    )
                ]

        if self.config.allowed_tools and not any(
            fnmatch.fnmatchcase(tool_name, pattern) for pattern in self.config.allowed_tools
        ):
            return [
                SecurityFinding(
                    rule_id="MCP-ARG-004",
                    detector="runtime_guard",
                    severity=Severity.HIGH,
                    title="Tool not permitted by policy allowlist",
                    description=(
                        f"Tool '{tool_name}' does not match any pattern in allowed_tools."
                    ),
                    target=target,
                    evidence=f"tool={tool_name}",
                    remediation="Call an allowed tool or add it to runtime_guard.allowed_tools.",
                    action_taken=action,
                    metadata={"tool_name": tool_name, "list": "allowed"},
                )
            ]

        return []

    def _check_path_safety(
        self,
        raw_value: str,
        *,
        arg_path: str,
        target: str,
        action: Action,
        enforce_allowed_paths: bool,
    ) -> list[SecurityFinding]:
        stripped = raw_value.strip()
        if not stripped:
            return []

        normalized = _normalize_fs_path(stripped)
        lowered = normalized.lower()
        findings: list[SecurityFinding] = []

        # 1. Path traversal ('..' segments)
        segments = [seg for seg in normalized.split("/") if seg]
        if ".." in segments:
            findings.append(
                SecurityFinding(
                    rule_id="MCP-ARG-001",
                    detector="runtime_guard",
                    severity=Severity.CRITICAL,
                    title="Path traversal detected in argument",
                    description="Argument contains parent directory traversal ('..') segments.",
                    target=target,
                    evidence=normalized[:200],
                    remediation="Use canonical paths confined within approved directories.",
                    action_taken=action,
                    metadata={"arg_path": arg_path, "reason": "traversal"},
                )
            )
            return findings

        # 2. Home directory expansion (~ / ~/)
        if _HOME_PATH_RE.search(normalized):
            findings.append(
                SecurityFinding(
                    rule_id="MCP-ARG-001",
                    detector="runtime_guard",
                    severity=Severity.CRITICAL,
                    title="Home-relative sensitive path access detected",
                    description="Argument references a tilde (~) home directory path.",
                    target=target,
                    evidence=normalized[:200],
                    remediation="Avoid '~' paths; restrict file access to approved workspaces.",
                    action_taken=action,
                    metadata={"arg_path": arg_path, "reason": "home_path"},
                )
            )
            return findings

        # 3. Sensitive target paths / filenames
        basename = segments[-1].lower() if segments else ""
        if basename in _SENSITIVE_FILENAMES or any(
            pattern.search(lowered) for pattern in _SENSITIVE_PATH_PATTERNS
        ):
            findings.append(
                SecurityFinding(
                    rule_id="MCP-ARG-001",
                    detector="runtime_guard",
                    severity=Severity.CRITICAL,
                    title="Sensitive credential or system path access detected",
                    description=(
                        "Argument targets a sensitive credential, configuration, or system file."
                    ),
                    target=target,
                    evidence=normalized[:200],
                    remediation="Block access to sensitive system files, keys, and dotfiles.",
                    action_taken=action,
                    metadata={"arg_path": arg_path, "reason": "sensitive_target"},
                )
            )
            return findings

        # 4. Configured blocked_paths
        for blocked in self.config.blocked_paths:
            blocked_norm = _canonical_compare_path(blocked)
            cand_norm = _canonical_compare_path(normalized)
            if (
                cand_norm == blocked_norm
                or cand_norm.startswith(blocked_norm.rstrip("/") + "/")
                or fnmatch.fnmatchcase(cand_norm, blocked_norm)
            ):
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-ARG-001",
                        detector="runtime_guard",
                        severity=Severity.CRITICAL,
                        title="Access to blocked path denied",
                        description=f"Argument path matches blocked_paths entry '{blocked}'.",
                        target=target,
                        evidence=normalized[:200],
                        remediation="Remove references to blocked filesystem paths.",
                        action_taken=action,
                        metadata={
                            "arg_path": arg_path,
                            "reason": "blocked_path",
                            "blocked": blocked,
                        },
                    )
                )
                return findings

        # 5. Configured allowed_paths
        if (
            self.config.allowed_paths
            and enforce_allowed_paths
            and not _is_under_allowed_path(normalized, self.config.allowed_paths)
        ):
            findings.append(
                SecurityFinding(
                    rule_id="MCP-ARG-001",
                    detector="runtime_guard",
                    severity=Severity.CRITICAL,
                    title="Path outside configured allowed_paths",
                    description="Path argument is outside all configured allowed_paths.",
                    target=target,
                    evidence=normalized[:200],
                    remediation="Restrict path arguments to directories listed in allowed_paths.",
                    action_taken=action,
                    metadata={"arg_path": arg_path, "reason": "outside_allowed_paths"},
                )
            )

        return findings

    def _check_command_injection(
        self,
        raw_value: str,
        *,
        target: str,
        action: Action,
    ) -> list[SecurityFinding]:
        for label, pattern in _CMD_PATTERNS:
            match = pattern.search(raw_value)
            if match is not None:
                return [
                    SecurityFinding(
                        rule_id="MCP-ARG-002",
                        detector="runtime_guard",
                        severity=Severity.CRITICAL,
                        title="Potential command injection in tool argument",
                        description=f"Detected {label} in tool argument.",
                        target=target,
                        evidence=match.group(0)[:120],
                        remediation=(
                            "Reject shell metacharacters in tool arguments or add trusted tools "
                            "explicitly to runtime_guard.allowed_shell_tools."
                        ),
                        action_taken=action,
                        metadata={"indicator": label},
                    )
                ]
        return []

    def _check_ssrf(
        self,
        raw_value: str,
        *,
        target: str,
        action: Action,
        allow_file_scheme: bool,
    ) -> list[SecurityFinding]:
        urls: list[str] = []
        stripped = raw_value.strip()
        if stripped.lower().startswith(("http://", "https://", "file://", "gopher://")):
            urls.append(stripped)
        else:
            urls.extend(_URL_SCHEME_RE.findall(raw_value))

        findings: list[SecurityFinding] = []
        seen_urls: set[str] = set()
        for url in urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            if scheme == "gopher" or (scheme == "file" and not allow_file_scheme):
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-ARG-003",
                        detector="runtime_guard",
                        severity=Severity.CRITICAL,
                        title=f"Disallowed URL scheme '{scheme}://' in argument",
                        description=(
                            f"Scheme '{scheme}://' is blocked to prevent SSRF "
                            "and local file access."
                        ),
                        target=target,
                        evidence=url[:200],
                        remediation="Permit only public http:// or https:// URLs.",
                        action_taken=action,
                        metadata={"scheme": scheme, "reason": "disallowed_scheme"},
                    )
                )
                continue

            if scheme not in ("http", "https"):
                continue

            hostname = (parsed.hostname or "").strip().lower().rstrip(".")
            if not hostname:
                continue

            if hostname in _METADATA_HOSTNAMES:
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-ARG-003",
                        detector="runtime_guard",
                        severity=Severity.CRITICAL,
                        title="Cloud metadata endpoint SSRF attempt blocked",
                        description=f"URL targets cloud metadata host '{hostname}'.",
                        target=target,
                        evidence=url[:200],
                        remediation="Block access to instance metadata endpoints.",
                        action_taken=action,
                        metadata={"hostname": hostname, "reason": "metadata"},
                    )
                )
                continue

            ip_obj = _parse_obfuscated_ip(hostname)
            if ip_obj is not None and _is_metadata_ip(ip_obj):
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-ARG-003",
                        detector="runtime_guard",
                        severity=Severity.CRITICAL,
                        title="Cloud metadata IP SSRF attempt blocked",
                        description=f"URL resolves syntactically to metadata IP '{ip_obj}'.",
                        target=target,
                        evidence=url[:200],
                        remediation="Block access to instance metadata IPs.",
                        action_taken=action,
                        metadata={"hostname": hostname, "ip": str(ip_obj), "reason": "metadata"},
                    )
                )
                continue

            if self.config.allow_private_urls:
                continue

            if hostname in _LOOPBACK_HOSTNAMES or hostname.endswith(".localhost"):
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-ARG-003",
                        detector="runtime_guard",
                        severity=Severity.HIGH,
                        title="Loopback URL SSRF attempt blocked",
                        description=f"URL targets loopback hostname '{hostname}'.",
                        target=target,
                        evidence=url[:200],
                        remediation="Disallow localhost URLs unless allow_private_urls is enabled.",
                        action_taken=action,
                        metadata={"hostname": hostname, "reason": "loopback"},
                    )
                )
                continue

            if ip_obj is not None and _is_private_or_restricted_ip(ip_obj):
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-ARG-003",
                        detector="runtime_guard",
                        severity=Severity.HIGH,
                        title="Private or restricted IP SSRF attempt blocked",
                        description=(f"URL host '{hostname}' parses to non-public IP '{ip_obj}'."),
                        target=target,
                        evidence=url[:200],
                        remediation="Disallow private/loopback/link-local IP targets.",
                        action_taken=action,
                        metadata={"hostname": hostname, "ip": str(ip_obj), "reason": "private_ip"},
                    )
                )

        return findings
