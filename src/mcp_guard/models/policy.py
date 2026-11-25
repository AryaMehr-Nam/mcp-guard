"""Security policy configuration models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class GuardMode(StrEnum):
    """Operating mode for MCP-Guard enforcement."""

    AUDIT = "audit"
    ENFORCE = "enforce"
    REDACT = "redact"


class PinningMode(StrEnum):
    """Tool schema pinning mode."""

    TOFU = "tofu"
    STRICT = "strict"
    DISABLED = "disabled"


class PoisoningConfig(BaseModel):
    """Configuration for tool/prompt/resource poisoning detection."""

    enabled: bool = True
    inspect_encoded: bool = True
    max_decode_bytes: int = 16384


class UnicodeConfig(BaseModel):
    """Configuration for hidden and deceptive Unicode character detection."""

    enabled: bool = True
    detect_tags: bool = True
    detect_zero_width: bool = True
    detect_bidi: bool = True
    detect_homoglyphs: bool = True


class PinningConfig(BaseModel):
    """Configuration for tool schema rug-pull detection via cryptographic pinning."""

    enabled: bool = True
    mode: PinningMode = PinningMode.TOFU
    pin_file: str = "~/.mcp-guard/pins.json"


_DEFAULT_HIGH_PRIVILEGE_TOOLS: list[str] = [
    "execute_command",
    "run_command",
    "shell",
    "bash",
    "exec",
    "eval",
    "write_file",
    "edit_file",
    "delete_file",
    "remove_file",
    "http_request",
    "fetch",
    "send_email",
]


class ShadowingConfig(BaseModel):
    """Configuration for tool shadowing and high-privilege override detection."""

    enabled: bool = True
    high_privilege_tools: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_HIGH_PRIVILEGE_TOOLS)
    )


class RuntimeGuardConfig(BaseModel):
    """Configuration for runtime tool-call argument and access validation."""

    enabled: bool = True
    allowed_paths: list[str] = Field(default_factory=list)
    blocked_paths: list[str] = Field(default_factory=list)
    allow_private_urls: bool = False
    allowed_shell_tools: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)


class ResponseGuardConfig(BaseModel):
    """Configuration for server response inspection and secret redaction."""

    enabled: bool = True
    detect_indirect_injection: bool = True
    detect_secrets: bool = True
    entropy_threshold: float = 3.5


class RateLimitConfig(BaseModel):
    """Configuration for token-bucket rate limiting."""

    enabled: bool = True
    requests_per_minute: int = 60
    burst: int = 15
    per_tool: bool = True


class LlmJudgeConfig(BaseModel):
    """Configuration for optional semantic LLM-as-a-judge inspection."""

    enabled: bool = False
    endpoint: str = "http://localhost:11434/api/generate"
    model: str = "qwen2.5:7b"
    timeout_seconds: float = 5.0
    cache_size: int = 512


class PolicyConfig(BaseModel):
    """Top-level MCP-Guard security policy."""

    mode: GuardMode = GuardMode.ENFORCE
    server_id: str | None = None
    log_file: str | None = None
    poisoning: PoisoningConfig = Field(default_factory=PoisoningConfig)
    unicode: UnicodeConfig = Field(default_factory=UnicodeConfig)
    pinning: PinningConfig = Field(default_factory=PinningConfig)
    shadowing: ShadowingConfig = Field(default_factory=ShadowingConfig)
    runtime_guard: RuntimeGuardConfig = Field(default_factory=RuntimeGuardConfig)
    response_guard: ResponseGuardConfig = Field(default_factory=ResponseGuardConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    llm_judge: LlmJudgeConfig = Field(default_factory=LlmJudgeConfig)
