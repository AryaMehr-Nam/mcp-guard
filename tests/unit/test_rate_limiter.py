"""Unit tests for RateLimiter (MCP-RAT-001)."""

from __future__ import annotations

import pytest

from mcp_guard.engine import rate_limiter as rate_limiter_mod
from mcp_guard.engine.rate_limiter import RateLimiter
from mcp_guard.models.findings import Action, Severity
from mcp_guard.models.policy import GuardMode, RateLimitConfig


class TestRateLimiter:
    """Tests for async token-bucket rate limiting."""

    async def test_per_tool_burst_and_exhaustion(self) -> None:
        limiter = RateLimiter(
            RateLimitConfig(enabled=True, requests_per_minute=60, burst=3, per_tool=True)
        )
        for _ in range(3):
            assert await limiter.check("get_weather") == []

        exhausted = await limiter.check("get_weather")
        assert len(exhausted) == 1
        assert exhausted[0].rule_id == "MCP-RAT-001"
        assert exhausted[0].severity == Severity.MEDIUM
        assert exhausted[0].action_taken == Action.BLOCK

        # Another tool has its own independent bucket when per_tool=True
        assert await limiter.check("add_numbers") == []

    async def test_global_bucket_shares_across_tools(self) -> None:
        limiter = RateLimiter(
            RateLimitConfig(enabled=True, requests_per_minute=60, burst=2, per_tool=False)
        )
        assert await limiter.check("tool_a") == []
        assert await limiter.check("tool_b") == []
        blocked = await limiter.check("tool_c")
        assert len(blocked) == 1
        assert blocked[0].rule_id == "MCP-RAT-001"

    async def test_token_refill_over_monotonic_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        now = 100.0
        monkeypatch.setattr(rate_limiter_mod.time, "monotonic", lambda: now)

        limiter = RateLimiter(
            RateLimitConfig(enabled=True, requests_per_minute=60, burst=2, per_tool=True)
        )
        assert await limiter.check("ping") == []
        assert await limiter.check("ping") == []
        assert len(await limiter.check("ping")) == 1

        # Advance 1.5 seconds -> 1.5 tokens refilled (at 60 rpm = 1 token/sec)
        now += 1.5
        assert await limiter.check("ping") == []
        assert len(await limiter.check("ping")) == 1

    async def test_audit_mode_logs_and_disabled_allows(self) -> None:
        limiter = RateLimiter(
            RateLimitConfig(enabled=True, requests_per_minute=0, burst=0, per_tool=True)
        )
        findings = await limiter.check("ping", mode=GuardMode.AUDIT)
        assert len(findings) == 1
        assert findings[0].action_taken == Action.LOG

        disabled = RateLimiter(RateLimitConfig(enabled=False, burst=0))
        assert await disabled.check("ping") == []
