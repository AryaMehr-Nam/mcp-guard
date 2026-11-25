"""Logging configuration strictly bound to stderr to preserve STDIO JSON-RPC purity."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from mcp_guard.utils.canonical import canonical_json

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def configure_logger(
    name: str = "mcp_guard",
    log_file: Path | None = None,
    level: str = "INFO",
) -> logging.Logger:
    """Configure and return a logger writing exclusively to sys.stderr (and optional log_file).

    Never attaches a handler to sys.stdout so STDIO MCP framing remains uncorrupted.
    """
    level_name = level.upper()
    level_map = logging.getLevelNamesMapping()
    if level_name not in level_map:
        raise ValueError(f"Unsupported log level: {level!r}")

    logger = logging.getLogger(name)
    logger.setLevel(level_map[level_name])
    logger.propagate = False

    for existing_handler in list(logger.handlers):
        logger.removeHandler(existing_handler)
        existing_handler.close()

    formatter = logging.Formatter(_LOG_FORMAT)

    stderr_handler = logging.StreamHandler(stream=sys.stderr)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_security_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a structured JSON security event record to the given logger."""
    payload: dict[str, Any] = {"event": event, **fields}
    logger.info(canonical_json(payload))
