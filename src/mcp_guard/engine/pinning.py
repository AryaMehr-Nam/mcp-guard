"""Cryptographic tool schema pinning and rug-pull detection."""

from __future__ import annotations

import copy
import difflib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_guard.models.findings import Action, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, PinningConfig, PinningMode
from mcp_guard.utils.canonical import tool_fingerprint


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _normalized_tool_snapshot(tool: dict[str, Any]) -> dict[str, Any]:
    input_schema = tool.get("inputSchema")
    return {
        "name": tool.get("name") if tool.get("name") is not None else "",
        "description": tool.get("description") if tool.get("description") is not None else "",
        "inputSchema": input_schema if input_schema is not None else {},
    }


def _unified_tool_diff(
    tool_name: str,
    expected_tool: dict[str, Any],
    current_tool: dict[str, Any],
) -> str:
    expected_lines = json.dumps(
        _normalized_tool_snapshot(expected_tool),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).splitlines()
    current_lines = json.dumps(
        _normalized_tool_snapshot(current_tool),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).splitlines()
    diff_lines = list(
        difflib.unified_diff(
            expected_lines,
            current_lines,
            fromfile=f"{tool_name} (pinned)",
            tofile=f"{tool_name} (current)",
            lineterm="",
        )
    )
    return "\n".join(diff_lines) if diff_lines else "(schema hash changed)"


class PinStore:
    """Atomic JSON persistence store for pinned and pending MCP tool schemas."""

    def __init__(self, pin_file: str | Path = "~/.mcp-guard/pins.json") -> None:
        self.pin_file = Path(pin_file).expanduser()

    def _load(self) -> dict[str, Any]:
        if not self.pin_file.exists():
            return {"version": 1, "servers": {}}

        raw_text = self.pin_file.read_text(encoding="utf-8")
        if not raw_text.strip():
            return {"version": 1, "servers": {}}

        try:
            data: Any = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in pin file '{self.pin_file}': {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"Pin file '{self.pin_file}' must contain a JSON object")

        servers = data.get("servers")
        if servers is None:
            servers = {}
        elif not isinstance(servers, dict):
            raise ValueError(f"Pin file '{self.pin_file}' has invalid 'servers' mapping")

        return {
            "version": int(data.get("version", 1)),
            "servers": servers,
        }

    def _save(self, data: dict[str, Any]) -> None:
        self.pin_file.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.pin_file.parent,
                prefix=f".{self.pin_file.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp_file:
                tmp_path = Path(tmp_file.name)
                tmp_file.write(payload)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_path, self.pin_file)
        except OSError:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _ensure_server(data: dict[str, Any], server_id: str) -> dict[str, Any]:
        servers: dict[str, Any] = data.setdefault("servers", {})
        entry = servers.get(server_id)
        if not isinstance(entry, dict):
            entry = {"tools": {}, "pending": {}}
            servers[server_id] = entry
        entry.setdefault("tools", {})
        entry.setdefault("pending", {})
        return entry

    def list_pins(self, server_id: str | None = None) -> dict[str, Any]:
        """Return pinned and pending tool records, optionally filtered to one server."""
        data = self._load()
        servers: dict[str, Any] = data["servers"]
        if server_id is not None:
            entry = servers.get(server_id)
            if not isinstance(entry, dict):
                return {}
            return {server_id: copy.deepcopy(entry)}
        return copy.deepcopy(servers)

    def approve(self, server_id: str | None = None, tool_name: str | None = None) -> int:
        """Promote pending tools to approved pins and return the number approved."""
        data = self._load()
        servers: dict[str, Any] = data["servers"]
        target_ids = [server_id] if server_id is not None else list(servers.keys())

        approved_count = 0
        now_iso = _utc_now_iso()
        for sid in target_ids:
            entry = servers.get(sid)
            if not isinstance(entry, dict):
                continue
            pending = entry.get("pending")
            tools = entry.setdefault("tools", {})
            if not isinstance(pending, dict) or not pending:
                continue

            names_to_approve = [tool_name] if tool_name is not None and tool_name in pending else []
            if tool_name is None:
                names_to_approve = list(pending.keys())

            for name in names_to_approve:
                record = pending.pop(name)
                if not isinstance(record, dict):
                    continue
                tools[name] = {
                    "hash": record["hash"],
                    "tool": record["tool"],
                    "pinned_at": now_iso,
                }
                approved_count += 1

        if approved_count > 0:
            self._save(data)
        return approved_count

    def reset(self, server_id: str | None = None) -> int:
        """Clear pinned and pending entries for a server or all servers, returning count cleared."""
        data = self._load()
        servers: dict[str, Any] = data["servers"]
        cleared = 0

        if server_id is not None:
            entry = servers.pop(server_id, None)
            if isinstance(entry, dict):
                tools = entry.get("tools", {})
                pending = entry.get("pending", {})
                cleared += (len(tools) if isinstance(tools, dict) else 0) + (
                    len(pending) if isinstance(pending, dict) else 0
                )
                self._save(data)
            return cleared

        for entry in servers.values():
            if isinstance(entry, dict):
                tools = entry.get("tools", {})
                pending = entry.get("pending", {})
                cleared += (len(tools) if isinstance(tools, dict) else 0) + (
                    len(pending) if isinstance(pending, dict) else 0
                )
        if servers:
            data["servers"] = {}
            self._save(data)
        return cleared


class SchemaPinner:
    """Verifies MCP tool definitions against persistent pins and in-session snapshots."""

    def __init__(
        self,
        config: PinningConfig | None = None,
        *,
        pin_file: str | Path | None = None,
    ) -> None:
        self.config = config or PinningConfig()
        resolved_pin_file = pin_file if pin_file is not None else self.config.pin_file
        self.store = PinStore(resolved_pin_file)
        self._session_tools: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {}

    def reset_session(self, server_id: str | None = None) -> None:
        """Clear cached in-session tool fingerprints for one server or all servers."""
        if server_id is not None:
            self._session_tools.pop(server_id, None)
        else:
            self._session_tools.clear()

    def verify_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
        *,
        guard_mode: GuardMode = GuardMode.ENFORCE,
    ) -> tuple[list[SecurityFinding], set[str]]:
        """Verify tools against stored pins and session snapshots.

        Returns (findings, blocked_tools).
        """
        if not self.config.enabled or self.config.mode == PinningMode.DISABLED:
            return [], set()

        data = self.store._load()
        server_entry = self.store._ensure_server(data, server_id)
        pinned_tools: dict[str, Any] = server_entry["tools"]
        pending_tools: dict[str, Any] = server_entry["pending"]
        session_map = self._session_tools.setdefault(server_id, {})

        findings: list[SecurityFinding] = []
        blocked_tools: set[str] = set()
        store_dirty = False
        now_iso = _utc_now_iso()

        for idx, tool in enumerate(tools):
            name = str(tool.get("name") or f"index_{idx}")
            current_hash = tool_fingerprint(tool)
            snapshot = _normalized_tool_snapshot(tool)

            pinned_rec = pinned_tools.get(name)
            session_rec = session_map.get(name)

            baseline_hash: str | None = None
            baseline_tool: dict[str, Any] | None = None
            if isinstance(pinned_rec, dict) and isinstance(pinned_rec.get("hash"), str):
                baseline_hash = pinned_rec["hash"]
                raw_tool = pinned_rec.get("tool")
                baseline_tool = raw_tool if isinstance(raw_tool, dict) else {}
            elif session_rec is not None:
                baseline_hash, baseline_tool = session_rec

            if baseline_hash is not None and baseline_hash != current_hash:
                diff_text = _unified_tool_diff(name, baseline_tool or {}, snapshot)
                action = Action.STRIP_TOOL if guard_mode == GuardMode.ENFORCE else Action.LOG
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-RUG-001",
                        detector="pinning",
                        severity=Severity.CRITICAL,
                        title=f"Tool schema rug-pull detected for '{name}'",
                        description=(
                            f"Tool '{name}' changed schema fingerprint from {baseline_hash[:12]} "
                            f"to {current_hash[:12]}.\n{diff_text}"
                        ),
                        target=f"tool:{name}",
                        evidence=diff_text[:1000],
                        remediation=(
                            f"Inspect changes to '{name}' and run "
                            f"'mcp-guard pins reset --server {server_id}' if intentional."
                        ),
                        action_taken=action,
                        metadata={
                            "server_id": server_id,
                            "tool_name": name,
                            "expected_hash": baseline_hash,
                            "current_hash": current_hash,
                        },
                    )
                )
                if guard_mode == GuardMode.ENFORCE:
                    blocked_tools.add(name)
                continue

            if baseline_hash == current_hash and isinstance(pinned_rec, dict):
                session_map[name] = (current_hash, copy.deepcopy(snapshot))
                continue

            # Unpinned tool (first seen persistently, or unapproved in strict mode).
            if self.config.mode == PinningMode.TOFU:
                pinned_tools[name] = {
                    "hash": current_hash,
                    "tool": copy.deepcopy(snapshot),
                    "pinned_at": now_iso,
                }
                pending_tools.pop(name, None)
                session_map[name] = (current_hash, copy.deepcopy(snapshot))
                store_dirty = True
            elif self.config.mode == PinningMode.STRICT:
                existing_pending = pending_tools.get(name)
                if (
                    not isinstance(existing_pending, dict)
                    or existing_pending.get("hash") != current_hash
                ):
                    pending_tools[name] = {
                        "hash": current_hash,
                        "tool": copy.deepcopy(snapshot),
                        "seen_at": now_iso,
                    }
                    store_dirty = True
                session_map[name] = (current_hash, copy.deepcopy(snapshot))
                action = Action.STRIP_TOOL if guard_mode == GuardMode.ENFORCE else Action.LOG
                findings.append(
                    SecurityFinding(
                        rule_id="MCP-PIN-001",
                        detector="pinning",
                        severity=Severity.HIGH,
                        title=f"Unapproved tool '{name}' requires approval under strict pinning",
                        description=(
                            f"Tool '{name}' (fingerprint {current_hash[:12]}) is pending approval "
                            f"for server '{server_id}'."
                        ),
                        target=f"tool:{name}",
                        evidence=f"hash={current_hash}",
                        remediation=(
                            f"Run 'mcp-guard pins approve --server {server_id} --tool {name}' "
                            "to trust this tool."
                        ),
                        action_taken=action,
                        metadata={
                            "server_id": server_id,
                            "tool_name": name,
                            "hash": current_hash,
                        },
                    )
                )
                if guard_mode == GuardMode.ENFORCE:
                    blocked_tools.add(name)

        if store_dirty:
            self.store._save(data)

        return findings, blocked_tools
