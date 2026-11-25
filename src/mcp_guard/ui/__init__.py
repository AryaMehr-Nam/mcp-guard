"""Embedded and standalone loopback Web UI server for MCP-Guard."""

from __future__ import annotations

from mcp_guard.ui.events import EventBus, SecurityEvent
from mcp_guard.ui.server import (
    EmbeddedUiHandle,
    create_ui_app,
    run_ui_server,
    start_embedded_ui_server,
    validate_loopback_host,
)

__all__ = [
    "EmbeddedUiHandle",
    "EventBus",
    "SecurityEvent",
    "create_ui_app",
    "run_ui_server",
    "start_embedded_ui_server",
    "validate_loopback_host",
]
