"""Shared pytest fixtures for MCP-Guard unit and integration tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_guard.models.policy import GuardMode, PinningConfig, PinningMode, PolicyConfig


@pytest.fixture
def tmp_pin_file(tmp_path: Path) -> Path:
    """Return an isolated temporary pin store file path."""
    return tmp_path / "pins.json"


@pytest.fixture
def enforce_policy(tmp_pin_file: Path) -> PolicyConfig:
    """Return a default enforce-mode PolicyConfig with an isolated pin file."""
    return PolicyConfig(
        mode=GuardMode.ENFORCE,
        server_id="test-server",
        pinning=PinningConfig(enabled=True, mode=PinningMode.TOFU, pin_file=str(tmp_pin_file)),
    )


@pytest.fixture
def audit_policy(tmp_pin_file: Path) -> PolicyConfig:
    """Return an audit-mode PolicyConfig with an isolated pin file."""
    return PolicyConfig(
        mode=GuardMode.AUDIT,
        server_id="test-server",
        pinning=PinningConfig(enabled=True, mode=PinningMode.TOFU, pin_file=str(tmp_pin_file)),
    )


@pytest.fixture
def redact_policy(tmp_pin_file: Path) -> PolicyConfig:
    """Return a redact-mode PolicyConfig with an isolated pin file."""
    return PolicyConfig(
        mode=GuardMode.REDACT,
        server_id="test-server",
        pinning=PinningConfig(enabled=True, mode=PinningMode.TOFU, pin_file=str(tmp_pin_file)),
    )


@pytest.fixture
def benign_tools() -> list[dict[str, Any]]:
    """Return a list of clean, benign MCP tool definitions."""
    return [
        {
            "name": "get_weather",
            "description": "Retrieve the current weather forecast for a given city.",
            "inputSchema": {
                "type": "object",
                "properties": {"city": {"type": "string", "description": "City name"}},
                "required": ["city"],
            },
        },
        {
            "name": "add_numbers",
            "description": "Add two integers and return their sum.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer"},
                    "b": {"type": "integer"},
                },
                "required": ["a", "b"],
            },
        },
    ]
