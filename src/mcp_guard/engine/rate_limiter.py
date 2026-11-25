"""Async token-bucket rate limiter for MCP tool invocations."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, RateLimitConfig


@dataclass
class _BucketState:
    tokens: float
    last_refill: float


class RateLimiter:
    """Async token-bucket rate limiter supporting per-tool or global quotas."""

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self.config = config or RateLimitConfig()
        self._lock = asyncio.Lock()
        self._buckets: dict[str, _BucketState] = {}

    async def check(
        self,
        tool_name: str,
        *,
        mode: GuardMode = GuardMode.ENFORCE,
    ) -> list[SecurityFinding]:
        """Consume one token for the tool (or global bucket) and return finding if exhausted."""
        if not self.config.enabled:
            return []

        key = tool_name if self.config.per_tool else "__global__"
        capacity = float(max(0, self.config.burst))
        refill_per_sec = max(0.0, self.config.requests_per_minute / 60.0)

        async with self._lock:
            now = time.monotonic()
            state = self._buckets.get(key)
            if state is None:
                state = _BucketState(tokens=capacity, last_refill=now)
                self._buckets[key] = state
            else:
                elapsed = max(0.0, now - state.last_refill)
                state.tokens = min(capacity, state.tokens + elapsed * refill_per_sec)
                state.last_refill = now

            if state.tokens >= 1.0:
                state.tokens -= 1.0
                return []

            action = Action.BLOCK if mode == GuardMode.ENFORCE else Action.LOG
            return [
                SecurityFinding(
                    rule_id="MCP-RAT-001",
                    detector="rate_limiter",
                    severity=Severity.MEDIUM,
                    title="Tool invocation rate limit exceeded",
                    description=(
                        f"Rate limit exhausted for '{tool_name}' "
                        f"(burst={self.config.burst}, rpm={self.config.requests_per_minute}, "
                        f"per_tool={self.config.per_tool})."
                    ),
                    target=f"tools/call:{tool_name}",
                    evidence=f"bucket={key}, available_tokens={state.tokens:.2f}",
                    remediation=(
                        "Slow down tool call frequency or adjust rate_limit policy settings."
                    ),
                    action_taken=action,
                    metadata={
                        "tool_name": tool_name,
                        "bucket": key,
                        "burst": self.config.burst,
                        "requests_per_minute": self.config.requests_per_minute,
                        "per_tool": self.config.per_tool,
                    },
                )
            ]
