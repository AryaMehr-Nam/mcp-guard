"""In-memory bounded event bus and telemetry schema for the MCP-Guard Web UI."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityEvent(BaseModel):
    """Structured security telemetry event emitted by SecurityPipeline or ActiveScanner."""

    model_config = ConfigDict(extra="allow")

    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    direction: str = "request"
    method: str = ""
    tool_name: str | None = None
    uri: str | None = None
    allowed: bool = True
    action: str = "allow"
    max_severity: str | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    server_id: str = "default"


class _Subscriber:
    """Tracks a subscriber queue and its owning event loop."""

    __slots__ = ("loop", "queue")

    def __init__(
        self,
        queue: asyncio.Queue[dict[str, Any]],
        loop: asyncio.AbstractEventLoop | None,
    ) -> None:
        self.queue = queue
        self.loop = loop


def _enqueue_drop_oldest(queue: asyncio.Queue[dict[str, Any]], payload: dict[str, Any]) -> None:
    """Push payload onto a bounded asyncio.Queue, dropping the oldest item if full."""
    try:
        queue.put_nowait(payload)
    except asyncio.QueueFull:
        with contextlib.suppress(asyncio.QueueEmpty):
            queue.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(payload)


class EventBus:
    """Bounded ring-buffer telemetry bus with non-blocking per-subscriber asyncio queues."""

    def __init__(self, maxlen: int = 500, subscriber_queue_size: int = 128) -> None:
        if maxlen < 1:
            raise ValueError("maxlen must be >= 1")
        if subscriber_queue_size < 1:
            raise ValueError("subscriber_queue_size must be >= 1")
        self._buffer: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._subscriber_queue_size = subscriber_queue_size
        self._subscribers: dict[int, _Subscriber] = {}
        self._lock = threading.Lock()

    def publish(self, event: dict[str, Any] | SecurityEvent) -> None:
        """Append an event to the ring buffer and fan out without blocking."""
        payload = event.model_dump(mode="json") if isinstance(event, SecurityEvent) else dict(event)
        with self._lock:
            self._buffer.append(payload)
            subscribers = list(self._subscribers.values())

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        for sub in subscribers:
            if sub.loop is not None and running_loop is not sub.loop and not sub.loop.is_closed():
                with contextlib.suppress(RuntimeError):
                    sub.loop.call_soon_threadsafe(_enqueue_drop_oldest, sub.queue, payload)
            else:
                _enqueue_drop_oldest(sub.queue, payload)

    def history(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return up to `limit` most recent buffered events in chronological order."""
        if limit <= 0:
            return []
        with self._lock:
            items = list(self._buffer)
        return items[-limit:]

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Create and register a bounded subscriber queue."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._subscriber_queue_size)
        try:
            loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        sub = _Subscriber(queue=queue, loop=loop)
        with self._lock:
            self._subscribers[id(queue)] = sub
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Remove a previously registered subscriber queue."""
        with self._lock:
            self._subscribers.pop(id(queue), None)
