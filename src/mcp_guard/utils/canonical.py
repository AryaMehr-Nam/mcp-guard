"""Canonical JSON serialization and deterministic fingerprinting utilities."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any

_SAFE_ID_CHARS_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def canonical_json(obj: Any) -> str:
    """Serialize an object to deterministic canonical JSON."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_canonical(obj: Any) -> str:
    """Compute the SHA-256 hex digest of an object's canonical JSON representation."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 fingerprint for an MCP tool definition."""
    input_schema = tool.get("inputSchema")
    payload: dict[str, Any] = {
        "name": tool.get("name") if tool.get("name") is not None else "",
        "description": tool.get("description") if tool.get("description") is not None else "",
        "inputSchema": input_schema if input_schema is not None else {},
    }
    return sha256_canonical(payload)


def normalize_server_id(target: str | Sequence[str]) -> str:
    """Return a deterministic, storage-safe server identifier with a SHA-256 hash suffix."""
    if isinstance(target, str):
        tokens = target.strip().split()
    else:
        tokens = [" ".join(str(part).strip().split()) for part in target if str(part).strip()]

    raw_text = " ".join(tokens)
    slug = _SAFE_ID_CHARS_RE.sub("-", raw_text.lower()).strip(".-_")
    slug = slug[:48].rstrip(".-_") or "server"

    digest = sha256_canonical(tokens)[:12]
    return f"{slug}-{digest}"
