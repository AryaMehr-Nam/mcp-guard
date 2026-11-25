"""JSON-RPC 2.0 and MCP schema models and framing helpers."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt, StrictStr


def _reject_bool_id(value: Any) -> int | str:
    """Reject boolean values for JSON-RPC id (since bool subclasses int in Python)."""
    if isinstance(value, bool):
        raise ValueError("JSON-RPC id must not be a boolean")
    if not isinstance(value, (int, str)):
        raise ValueError("JSON-RPC id must be an integer or string")
    return value


JsonRpcId: TypeAlias = Annotated[StrictInt | StrictStr, BeforeValidator(_reject_bool_id)]


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 error object."""

    model_config = ConfigDict(extra="allow")

    code: int
    message: str
    data: Any = None


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request object."""

    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    id: JsonRpcId
    method: str
    params: dict[str, Any] | list[Any] | None = None


class JsonRpcNotification(BaseModel):
    """JSON-RPC 2.0 notification object (no id)."""

    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: dict[str, Any] | list[Any] | None = None


class JsonRpcResponse(BaseModel):
    """JSON-RPC 2.0 response object."""

    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"] = "2.0"
    id: JsonRpcId | None = None
    result: Any = None
    error: JsonRpcError | None = None


class MCPTool(BaseModel):
    """MCP tool definition schema."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str | None = None
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None


class MCPPromptArgument(BaseModel):
    """MCP prompt argument descriptor."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str | None = None
    required: bool | None = None


class MCPPrompt(BaseModel):
    """MCP prompt definition schema."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str | None = None
    arguments: list[MCPPromptArgument] | None = None


class MCPResource(BaseModel):
    """MCP resource definition schema."""

    model_config = ConfigDict(extra="allow")

    uri: str
    name: str | None = None
    description: str | None = None
    mimeType: str | None = None


def parse_jsonrpc_frame(raw: bytes | str) -> dict[str, Any] | list[dict[str, Any]]:
    """Decode a raw UTF-8 JSON-RPC frame into a message dict or non-empty batch list.

    Raises ValueError on invalid UTF-8, invalid JSON, or invalid JSON-RPC frame shape.
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Invalid UTF-8 in JSON-RPC frame: {exc}") from exc
    else:
        text = raw

    stripped = text.strip()
    if not stripped:
        raise ValueError("Empty JSON-RPC frame")

    try:
        parsed: Any = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in JSON-RPC frame: {exc}") from exc

    if isinstance(parsed, dict):
        return parsed

    if isinstance(parsed, list):
        if not parsed:
            raise ValueError("JSON-RPC batch array must not be empty")
        if not all(isinstance(item, dict) for item in parsed):
            raise ValueError("Every item in a JSON-RPC batch array must be a JSON object")
        return parsed

    raise ValueError("JSON-RPC frame must be a JSON object or non-empty array of objects")


def make_error_response(
    req_id: JsonRpcId | None,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a JSON-RPC 2.0 error response dictionary."""
    if isinstance(req_id, bool):
        raise ValueError("JSON-RPC id must not be a boolean")

    error_obj: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        error_obj["data"] = data

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": error_obj,
    }


def is_notification(msg: dict[str, Any]) -> bool:
    """Return True if the JSON-RPC message dict is a notification (has 'method' and lacks 'id')."""
    return "id" not in msg and "method" in msg
