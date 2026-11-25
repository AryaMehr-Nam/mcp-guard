"""YAML policy loader, validator, and default policy template generator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_guard.models.policy import GuardMode, PinningMode, PolicyConfig


def _read_yaml_mapping(path: Path) -> dict[str, Any]:
    """Read a YAML file via yaml.safe_load and validate it produces a mapping."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Failed to read policy file {path}: {exc}") from exc

    try:
        loaded: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in policy file {path}: {exc}") from exc

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Policy file {path} must contain a YAML mapping at top level")
    return loaded


def load_policy(
    policy_path: Path | None = None,
    *,
    mode: str | None = None,
    pin_file: str | None = None,
    server_id: str | None = None,
    log_file: str | None = None,
    llm_judge: bool | None = None,
) -> PolicyConfig:
    """Load, validate, and apply CLI overrides to a PolicyConfig."""
    raw_data: dict[str, Any] = {}
    if policy_path is not None:
        if not policy_path.is_file():
            raise ValueError(f"Policy file does not exist: {policy_path}")
        raw_data = _read_yaml_mapping(policy_path)

    try:
        config = PolicyConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ValueError(f"Invalid policy configuration: {exc}") from exc

    updates: dict[str, Any] = {}
    if mode is not None:
        try:
            updates["mode"] = GuardMode(mode)
        except ValueError as exc:
            valid = ", ".join(m.value for m in GuardMode)
            raise ValueError(f"Invalid guard mode {mode!r}; expected one of: {valid}") from exc

    if server_id is not None:
        updates["server_id"] = server_id

    if log_file is not None:
        updates["log_file"] = log_file

    if pin_file is not None:
        updates["pinning"] = config.pinning.model_copy(update={"pin_file": pin_file})

    if llm_judge is not None:
        updates["llm_judge"] = config.llm_judge.model_copy(update={"enabled": llm_judge})

    if updates:
        merged = config.model_copy(update=updates)
        try:
            config = PolicyConfig.model_validate(merged.model_dump())
        except ValidationError as exc:
            raise ValueError(f"Invalid policy configuration after overrides: {exc}") from exc

    return config


def default_policy_yaml() -> str:
    """Return a clean, commented default policy YAML string for `mcp-guard init`."""
    defaults = PolicyConfig()
    high_priv_lines = "\n".join(f"    - {tool}" for tool in defaults.shadowing.high_privilege_tools)
    return (
        "# MCP-Guard Default Security Policy\n"
        "# Operating modes: enforce | audit | redact\n"
        f"mode: {GuardMode.ENFORCE.value}\n"
        "server_id: null\n"
        "log_file: null\n"
        "\n"
        "# Tool, prompt, and resource poisoning inspection\n"
        "poisoning:\n"
        f"  enabled: {str(defaults.poisoning.enabled).lower()}\n"
        f"  inspect_encoded: {str(defaults.poisoning.inspect_encoded).lower()}\n"
        f"  max_decode_bytes: {defaults.poisoning.max_decode_bytes}\n"
        "\n"
        "# Hidden and deceptive Unicode detection\n"
        "unicode:\n"
        f"  enabled: {str(defaults.unicode.enabled).lower()}\n"
        f"  detect_tags: {str(defaults.unicode.detect_tags).lower()}\n"
        f"  detect_zero_width: {str(defaults.unicode.detect_zero_width).lower()}\n"
        f"  detect_bidi: {str(defaults.unicode.detect_bidi).lower()}\n"
        f"  detect_homoglyphs: {str(defaults.unicode.detect_homoglyphs).lower()}\n"
        "\n"
        "# Tool schema cryptographic pinning (modes: tofu | strict | disabled)\n"
        "pinning:\n"
        f"  enabled: {str(defaults.pinning.enabled).lower()}\n"
        f"  mode: {PinningMode.TOFU.value}\n"
        f'  pin_file: "{defaults.pinning.pin_file}"\n'
        "\n"
        "# Tool shadowing and high-privilege override detection\n"
        "shadowing:\n"
        f"  enabled: {str(defaults.shadowing.enabled).lower()}\n"
        "  high_privilege_tools:\n"
        f"{high_priv_lines}\n"
        "\n"
        "# Runtime tool-call argument, path, URL, and allow/deny enforcement\n"
        "runtime_guard:\n"
        f"  enabled: {str(defaults.runtime_guard.enabled).lower()}\n"
        "  allowed_paths: []\n"
        "  blocked_paths: []\n"
        f"  allow_private_urls: {str(defaults.runtime_guard.allow_private_urls).lower()}\n"
        "  allowed_shell_tools: []\n"
        "  allowed_tools: []\n"
        "  denied_tools: []\n"
        "\n"
        "# Server response inspection and secret redaction\n"
        "response_guard:\n"
        f"  enabled: {str(defaults.response_guard.enabled).lower()}\n"
        "  detect_indirect_injection: "
        f"{str(defaults.response_guard.detect_indirect_injection).lower()}\n"
        f"  detect_secrets: {str(defaults.response_guard.detect_secrets).lower()}\n"
        f"  entropy_threshold: {defaults.response_guard.entropy_threshold}\n"
        "\n"
        "# Token-bucket rate limiting\n"
        "rate_limit:\n"
        f"  enabled: {str(defaults.rate_limit.enabled).lower()}\n"
        f"  requests_per_minute: {defaults.rate_limit.requests_per_minute}\n"
        f"  burst: {defaults.rate_limit.burst}\n"
        f"  per_tool: {str(defaults.rate_limit.per_tool).lower()}\n"
        "\n"
        "# Optional semantic LLM-as-a-judge inspection (disabled by default)\n"
        "llm_judge:\n"
        f"  enabled: {str(defaults.llm_judge.enabled).lower()}\n"
        f'  endpoint: "{defaults.llm_judge.endpoint}"\n'
        f'  model: "{defaults.llm_judge.model}"\n'
        f"  timeout_seconds: {defaults.llm_judge.timeout_seconds}\n"
        f"  cache_size: {defaults.llm_judge.cache_size}\n"
    )
