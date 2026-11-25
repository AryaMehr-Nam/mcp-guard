"""Unified security inspection pipeline for MCP requests, responses, and static catalogs."""

from __future__ import annotations

import copy
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_guard.engine.llm_judge import LlmJudge
from mcp_guard.engine.pinning import SchemaPinner
from mcp_guard.engine.poisoning import PoisoningDetector
from mcp_guard.engine.rate_limiter import RateLimiter
from mcp_guard.engine.response_guard import ResponseGuard
from mcp_guard.engine.runtime_guard import RuntimeGuard
from mcp_guard.engine.shadowing import ShadowingDetector
from mcp_guard.engine.unicode_guard import UnicodeGuard
from mcp_guard.models.findings import Action, SecurityFinding
from mcp_guard.models.jsonrpc import is_notification, make_error_response
from mcp_guard.models.policy import GuardMode, PolicyConfig
from mcp_guard.utils.canonical import canonical_json
from mcp_guard.utils.logging import configure_logger, log_security_event

SECURITY_ERROR_CODE = -32001
RATE_LIMIT_ERROR_CODE = -32002


class PipelineDecision(BaseModel):
    """Result of running SecurityPipeline over a single or batch JSON-RPC frame."""

    allowed: bool = True
    findings: list[SecurityFinding] = Field(default_factory=list)
    message: dict[str, Any] | list[dict[str, Any]] | None = None
    error_code: int | None = None
    error_message: str | None = None
    blocked_tools: list[str] = Field(default_factory=list)


def _extract_tool_name(finding: SecurityFinding) -> str | None:
    meta_name = finding.metadata.get("tool_name")
    if isinstance(meta_name, str) and meta_name:
        return meta_name
    if finding.target.startswith("tool:"):
        rest = finding.target[len("tool:") :]
        return rest.split(".", 1)[0] or None
    return None


def _extract_prompt_name(finding: SecurityFinding) -> str | None:
    meta_name = finding.metadata.get("prompt_name")
    if isinstance(meta_name, str) and meta_name:
        return meta_name
    if finding.target.startswith("prompt:"):
        rest = finding.target[len("prompt:") :]
        return rest.split(".", 1)[0] or None
    return None


def _infer_response_method(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    if isinstance(result.get("tools"), list):
        return "tools/list"
    if isinstance(result.get("prompts"), list):
        return "prompts/list"
    if isinstance(result.get("resources"), list):
        return "resources/list"
    if isinstance(result.get("contents"), list):
        return "resources/read"
    if isinstance(result.get("content"), list):
        return "tools/call"
    return None


def _unique_rule_ids(findings: list[SecurityFinding]) -> list[str]:
    return list(dict.fromkeys(finding.rule_id for finding in findings))


def _resolve_event_action(decision: PipelineDecision) -> str:
    if not decision.allowed:
        return Action.BLOCK.value
    if decision.blocked_tools or any(
        f.action_taken == Action.STRIP_TOOL for f in decision.findings
    ):
        return Action.STRIP_TOOL.value
    if any(f.action_taken == Action.BLOCK for f in decision.findings):
        return Action.BLOCK.value
    if any(f.action_taken == Action.REDACT for f in decision.findings):
        return Action.REDACT.value
    if any(f.action_taken == Action.LOG for f in decision.findings):
        return Action.LOG.value
    return Action.ALLOW.value


def _extract_request_event_fields(
    frame: dict[str, Any] | list[dict[str, Any]],
) -> tuple[str, str | None, str | None]:
    if isinstance(frame, list):
        methods = [
            str(item.get("method", ""))
            for item in frame
            if isinstance(item, dict) and item.get("method")
        ]
        method = ", ".join(dict.fromkeys(methods)) if methods else "batch"
        tool_names = [
            str(item["params"]["name"])
            for item in frame
            if isinstance(item, dict)
            and item.get("method") == "tools/call"
            and isinstance(item.get("params"), dict)
            and isinstance(item["params"].get("name"), str)
            and item["params"]["name"]
        ]
        uris = [
            str(item["params"]["uri"])
            for item in frame
            if isinstance(item, dict)
            and item.get("method") == "resources/read"
            and isinstance(item.get("params"), dict)
            and isinstance(item["params"].get("uri"), str)
            and item["params"]["uri"]
        ]
        return (
            method,
            tool_names[0] if len(tool_names) == 1 else None,
            uris[0] if len(uris) == 1 else None,
        )

    method = str(frame.get("method", ""))
    params = frame.get("params")
    tool_name: str | None = None
    uri: str | None = None
    if isinstance(params, dict):
        if method == "tools/call":
            raw_name = params.get("name")
            if isinstance(raw_name, str) and raw_name:
                tool_name = raw_name
        elif method == "resources/read":
            raw_uri = params.get("uri")
            if isinstance(raw_uri, str) and raw_uri:
                uri = raw_uri
    return method, tool_name, uri


class SecurityPipeline:
    """Orchestrates static and runtime MCP-Guard detectors across JSON-RPC traffic."""

    def __init__(
        self,
        policy: PolicyConfig,
        *,
        server_id: str | None = None,
        logger: logging.Logger | None = None,
        known_tools: set[str] | None = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.policy = policy
        self.server_id = server_id or policy.server_id or "default"
        log_path = Path(policy.log_file) if policy.log_file else None
        self._logger = logger or configure_logger("mcp_guard.pipeline", log_file=log_path)
        self._event_sink = event_sink

        self.poisoning = PoisoningDetector(policy.poisoning)
        self.unicode_guard = UnicodeGuard(policy.unicode)
        self.pinner = SchemaPinner(policy.pinning)
        self.shadowing = ShadowingDetector(policy.shadowing)
        self.runtime_guard = RuntimeGuard(policy.runtime_guard)
        self.response_guard = ResponseGuard(policy.response_guard)
        self.rate_limiter = RateLimiter(policy.rate_limit)
        self.llm_judge = LlmJudge(policy.llm_judge, logger=self._logger)

        self._external_known_tools: set[str] = set(known_tools) if known_tools else set()
        self._known_tools: set[str] = set()

    def update_policy(self, policy: PolicyConfig) -> None:
        """Update active policy and propagate sub-configs to all detectors."""
        self.policy = policy
        self.poisoning.config = policy.poisoning
        self.unicode_guard.config = policy.unicode
        self.pinner.config = policy.pinning
        self.shadowing.config = policy.shadowing
        self.runtime_guard.config = policy.runtime_guard
        self.response_guard.config = policy.response_guard
        self.rate_limiter.config = policy.rate_limit
        self.llm_judge.config = policy.llm_judge

    async def inspect_request(
        self,
        frame: dict[str, Any] | list[dict[str, Any]],
    ) -> PipelineDecision:
        """Inspect an incoming client-to-server JSON-RPC request or batch frame."""
        if isinstance(frame, list):
            decision = await self._inspect_request_batch(frame)
        else:
            decision = await self._inspect_single_request(frame)
        method, tool_name, uri = _extract_request_event_fields(frame)
        self._emit_event(
            direction="request",
            method=method,
            tool_name=tool_name,
            uri=uri,
            decision=decision,
        )
        return decision

    async def _inspect_request_batch(
        self,
        messages: list[dict[str, Any]],
    ) -> PipelineDecision:
        decisions = [await self._inspect_single_request(msg) for msg in messages]
        all_findings: list[SecurityFinding] = []
        blocked_tools: list[str] = []
        for dec in decisions:
            all_findings.extend(dec.findings)
            blocked_tools.extend(dec.blocked_tools)

        any_blocked = any(not dec.allowed for dec in decisions)
        if not any_blocked:
            forwarded: list[dict[str, Any]] = []
            for msg, dec in zip(messages, decisions, strict=True):
                if isinstance(dec.message, dict):
                    forwarded.append(dec.message)
                else:
                    forwarded.append(copy.deepcopy(msg))
            return PipelineDecision(
                allowed=True,
                findings=all_findings,
                message=forwarded,
                blocked_tools=blocked_tools,
            )

        error_responses: list[dict[str, Any]] = []
        first_code: int | None = None
        first_message: str | None = None

        for msg, dec in zip(messages, decisions, strict=True):
            if not dec.allowed:
                if first_code is None:
                    first_code = dec.error_code
                    first_message = dec.error_message
                if not is_notification(msg) and isinstance(dec.message, dict):
                    error_responses.append(dec.message)
            elif not is_notification(msg):
                error_responses.append(
                    make_error_response(
                        msg.get("id"),
                        SECURITY_ERROR_CODE,
                        "Batch rejected due to security policy violation in sibling request",
                    )
                )

        return PipelineDecision(
            allowed=False,
            findings=all_findings,
            message=error_responses or None,
            error_code=first_code or SECURITY_ERROR_CODE,
            error_message=first_message or "Batch blocked by MCP-Guard security policy",
            blocked_tools=blocked_tools,
        )

    async def _inspect_single_request(self, msg: dict[str, Any]) -> PipelineDecision:
        mode = self.policy.mode
        method = str(msg.get("method", ""))
        raw_params = msg.get("params")
        params: dict[str, Any] | None = raw_params if isinstance(raw_params, dict) else None

        findings: list[SecurityFinding] = []

        if method == "tools/call" and params is not None:
            tool_name = str(params.get("name", ""))
            raw_args = params.get("arguments")
            arguments: dict[str, Any] | None = raw_args if isinstance(raw_args, dict) else None

            findings.extend(await self.rate_limiter.check(tool_name, mode=mode))
            findings.extend(self.runtime_guard.inspect_tool_call(tool_name, arguments, mode=mode))
            if arguments is not None:
                findings.extend(
                    self.unicode_guard.scan_value(
                        arguments,
                        target=f"tools/call:{tool_name}",
                        check_homoglyphs=False,
                        mode=mode,
                    )
                )
                if self.policy.llm_judge.enabled:
                    findings.extend(
                        await self.llm_judge.evaluate(
                            "tool_call",
                            canonical_json(arguments),
                            target=f"tools/call:{tool_name}",
                            mode=mode,
                        )
                    )
        elif method == "resources/read" and params is not None:
            uri = str(params.get("uri", ""))
            findings.extend(self.runtime_guard.inspect_resource_read(uri, mode=mode))
            findings.extend(
                self.unicode_guard.scan_text(
                    uri,
                    target=f"resources/read:{uri}",
                    check_homoglyphs=False,
                    mode=mode,
                )
            )
        elif method == "prompts/get" and params is not None:
            prompt_args = params.get("arguments")
            if prompt_args is not None:
                findings.extend(
                    self.unicode_guard.scan_value(
                        prompt_args,
                        target=f"prompts/get:{params.get('name', '')}",
                        check_homoglyphs=False,
                        mode=mode,
                    )
                )

        self._log_findings("request_inspected", method=method, findings=findings)

        blocked_findings = [f for f in findings if f.action_taken == Action.BLOCK]
        if mode == GuardMode.ENFORCE and blocked_findings:
            rules = _unique_rule_ids(blocked_findings)
            has_security_block = any(f.rule_id != "MCP-RAT-001" for f in blocked_findings)
            if has_security_block:
                err_code = SECURITY_ERROR_CODE
                err_msg = f"Blocked by MCP-Guard security policy ({', '.join(rules)})"
            else:
                err_code = RATE_LIMIT_ERROR_CODE
                err_msg = "Rate limit exceeded (MCP-RAT-001)"

            if is_notification(msg):
                return PipelineDecision(
                    allowed=False,
                    findings=findings,
                    message=None,
                    error_code=err_code,
                    error_message=err_msg,
                )

            err_resp = make_error_response(
                msg.get("id"),
                err_code,
                err_msg,
                data={"rules": rules},
            )
            return PipelineDecision(
                allowed=False,
                findings=findings,
                message=err_resp,
                error_code=err_code,
                error_message=err_msg,
            )

        return PipelineDecision(
            allowed=True,
            findings=findings,
            message=copy.deepcopy(msg),
        )

    async def inspect_response(
        self,
        frame: dict[str, Any] | list[dict[str, Any]],
        *,
        method: str | None = None,
        tool_name: str | None = None,
        uri: str | None = None,
    ) -> PipelineDecision:
        """Inspect an upstream server-to-client JSON-RPC response or batch frame."""
        if isinstance(frame, list):
            decision = await self._inspect_response_batch(
                frame,
                method=method,
                tool_name=tool_name,
                uri=uri,
            )
            eff_method = method or "batch"
        else:
            decision = await self._inspect_single_response(
                frame,
                method=method,
                tool_name=tool_name,
                uri=uri,
            )
            eff_method = method or _infer_response_method(frame.get("result")) or "response"
        self._emit_event(
            direction="response",
            method=eff_method,
            tool_name=tool_name,
            uri=uri,
            decision=decision,
        )
        return decision

    async def _inspect_response_batch(
        self,
        messages: list[dict[str, Any]],
        *,
        method: str | None,
        tool_name: str | None,
        uri: str | None,
    ) -> PipelineDecision:
        decisions = [
            await self._inspect_single_response(
                msg,
                method=method,
                tool_name=tool_name,
                uri=uri,
            )
            for msg in messages
        ]
        all_findings: list[SecurityFinding] = []
        blocked_tools: list[str] = []
        out_messages: list[dict[str, Any]] = []
        any_blocked = False
        first_code: int | None = None
        first_msg: str | None = None

        for msg, dec in zip(messages, decisions, strict=True):
            all_findings.extend(dec.findings)
            blocked_tools.extend(dec.blocked_tools)
            if not dec.allowed:
                any_blocked = True
                if first_code is None:
                    first_code = dec.error_code
                    first_msg = dec.error_message
                if isinstance(dec.message, dict):
                    out_messages.append(dec.message)
            elif isinstance(dec.message, dict):
                out_messages.append(dec.message)
            else:
                out_messages.append(copy.deepcopy(msg))

        return PipelineDecision(
            allowed=not any_blocked,
            findings=all_findings,
            message=out_messages or None,
            error_code=first_code,
            error_message=first_msg,
            blocked_tools=blocked_tools,
        )

    async def _inspect_single_response(
        self,
        msg: dict[str, Any],
        *,
        method: str | None,
        tool_name: str | None,
        uri: str | None,
    ) -> PipelineDecision:
        if "error" in msg and msg.get("error") is not None and "result" not in msg:
            return PipelineDecision(allowed=True, message=copy.deepcopy(msg))

        result = msg.get("result")
        if result is None:
            return PipelineDecision(allowed=True, message=copy.deepcopy(msg))

        mode = self.policy.mode
        eff_method = method or _infer_response_method(result)

        if (
            eff_method == "tools/list"
            and isinstance(result, dict)
            and isinstance(result.get("tools"), list)
        ):
            return await self._inspect_tools_list_response(msg, result, mode=mode)

        if (
            eff_method == "prompts/list"
            and isinstance(result, dict)
            and isinstance(result.get("prompts"), list)
        ):
            return await self._inspect_prompts_list_response(msg, result, mode=mode)

        if (
            eff_method == "resources/list"
            and isinstance(result, dict)
            and isinstance(result.get("resources"), list)
        ):
            return await self._inspect_resources_list_response(msg, result, mode=mode)

        target = (
            f"tools/call:{tool_name}"
            if tool_name
            else (f"resources/read:{uri}" if uri else (eff_method or "response"))
        )
        findings, processed_result = self.response_guard.inspect_result(
            result,
            target=target,
            mode=mode,
        )
        findings.extend(
            self.unicode_guard.scan_value(
                result,
                target=target,
                check_homoglyphs=False,
                mode=mode,
            )
        )
        if self.policy.llm_judge.enabled:
            findings.extend(
                await self.llm_judge.evaluate(
                    "tool_result",
                    canonical_json(result),
                    target=target,
                    mode=mode,
                )
            )

        self._log_findings("response_inspected", method=eff_method or "response", findings=findings)

        blocked_findings = [f for f in findings if f.action_taken == Action.BLOCK]
        if mode == GuardMode.ENFORCE and blocked_findings:
            rules = _unique_rule_ids(blocked_findings)
            err_msg = f"Response blocked by MCP-Guard security policy ({', '.join(rules)})"
            if is_notification(msg):
                return PipelineDecision(
                    allowed=False,
                    findings=findings,
                    message=None,
                    error_code=SECURITY_ERROR_CODE,
                    error_message=err_msg,
                )
            err_resp = make_error_response(
                msg.get("id"),
                SECURITY_ERROR_CODE,
                err_msg,
                data={"rules": rules},
            )
            return PipelineDecision(
                allowed=False,
                findings=findings,
                message=err_resp,
                error_code=SECURITY_ERROR_CODE,
                error_message=err_msg,
            )

        out_msg = copy.deepcopy(msg)
        if mode in (GuardMode.ENFORCE, GuardMode.REDACT):
            out_msg["result"] = processed_result
        return PipelineDecision(
            allowed=True,
            findings=findings,
            message=out_msg,
        )

    async def _inspect_tools_list_response(
        self,
        msg: dict[str, Any],
        result: dict[str, Any],
        *,
        mode: GuardMode,
    ) -> PipelineDecision:
        tools = [item for item in result["tools"] if isinstance(item, dict)]
        findings: list[SecurityFinding] = []
        findings.extend(self.poisoning.scan_tools(tools, mode=mode))
        findings.extend(self.unicode_guard.scan_tools(tools, mode=mode))

        pin_findings, pin_blocked = self.pinner.verify_tools(
            self.server_id,
            tools,
            guard_mode=mode,
        )
        findings.extend(pin_findings)
        findings.extend(
            self.shadowing.scan_tools(
                tools,
                known_tools=self._external_known_tools or None,
                mode=mode,
            )
        )

        if self.policy.llm_judge.enabled:
            for tool in tools:
                tool_name = str(tool.get("name", ""))
                findings.extend(
                    await self.llm_judge.evaluate(
                        "tool_definition",
                        canonical_json(tool),
                        target=f"tool:{tool_name}",
                        mode=mode,
                    )
                )

        blocked_names: set[str] = set(pin_blocked)
        for finding in findings:
            if finding.action_taken in (Action.STRIP_TOOL, Action.BLOCK):
                extracted = _extract_tool_name(finding)
                if extracted:
                    blocked_names.add(extracted)

        for tool in tools:
            name = tool.get("name")
            if (
                isinstance(name, str)
                and name
                and (mode != GuardMode.ENFORCE or name not in blocked_names)
            ):
                self._known_tools.add(name)

        self._log_findings("tools_list_inspected", method="tools/list", findings=findings)

        out_msg = copy.deepcopy(msg)
        if mode == GuardMode.ENFORCE and blocked_names:
            out_msg["result"]["tools"] = [
                tool
                for tool in result["tools"]
                if not isinstance(tool, dict) or tool.get("name") not in blocked_names
            ]

        return PipelineDecision(
            allowed=True,
            findings=findings,
            message=out_msg,
            blocked_tools=sorted(blocked_names) if mode == GuardMode.ENFORCE else [],
        )

    async def _inspect_prompts_list_response(
        self,
        msg: dict[str, Any],
        result: dict[str, Any],
        *,
        mode: GuardMode,
    ) -> PipelineDecision:
        prompts = [item for item in result["prompts"] if isinstance(item, dict)]
        findings: list[SecurityFinding] = []
        findings.extend(self.poisoning.scan_prompts(prompts, mode=mode))
        findings.extend(self.unicode_guard.scan_prompts(prompts, mode=mode))

        blocked_prompts: set[str] = set()
        for finding in findings:
            if finding.action_taken in (Action.BLOCK, Action.STRIP_TOOL):
                extracted = _extract_prompt_name(finding)
                if extracted:
                    blocked_prompts.add(extracted)

        self._log_findings("prompts_list_inspected", method="prompts/list", findings=findings)

        out_msg = copy.deepcopy(msg)
        if mode == GuardMode.ENFORCE and blocked_prompts:
            out_msg["result"]["prompts"] = [
                item
                for item in result["prompts"]
                if not isinstance(item, dict) or item.get("name") not in blocked_prompts
            ]

        return PipelineDecision(
            allowed=True,
            findings=findings,
            message=out_msg,
        )

    async def _inspect_resources_list_response(
        self,
        msg: dict[str, Any],
        result: dict[str, Any],
        *,
        mode: GuardMode,
    ) -> PipelineDecision:
        resources = [item for item in result["resources"] if isinstance(item, dict)]
        findings: list[SecurityFinding] = []
        findings.extend(self.poisoning.scan_resources(resources, mode=mode))
        findings.extend(self.unicode_guard.scan_resources(resources, mode=mode))

        self._log_findings("resources_list_inspected", method="resources/list", findings=findings)

        blocked_findings = [f for f in findings if f.action_taken == Action.BLOCK]
        if mode == GuardMode.ENFORCE and blocked_findings:
            rules = _unique_rule_ids(blocked_findings)
            err_msg = f"Resource catalog blocked by MCP-Guard ({', '.join(rules)})"
            err_resp = make_error_response(
                msg.get("id"),
                SECURITY_ERROR_CODE,
                err_msg,
                data={"rules": rules},
            )
            return PipelineDecision(
                allowed=False,
                findings=findings,
                message=err_resp,
                error_code=SECURITY_ERROR_CODE,
                error_message=err_msg,
            )

        return PipelineDecision(
            allowed=True,
            findings=findings,
            message=copy.deepcopy(msg),
        )

    async def inspect_catalog(
        self,
        *,
        tools: list[dict[str, Any]] | None = None,
        prompts: list[dict[str, Any]] | None = None,
        resources: list[dict[str, Any]] | None = None,
    ) -> list[SecurityFinding]:
        """Run all static and optional LLM catalog checks for ActiveScanner."""
        mode = self.policy.mode
        findings: list[SecurityFinding] = []

        if tools is not None:
            findings.extend(self.poisoning.scan_tools(tools, mode=mode))
            findings.extend(self.unicode_guard.scan_tools(tools, mode=mode))
            pin_findings, _ = self.pinner.verify_tools(
                self.server_id,
                tools,
                guard_mode=mode,
            )
            findings.extend(pin_findings)
            findings.extend(
                self.shadowing.scan_tools(
                    tools,
                    known_tools=self._external_known_tools or None,
                    mode=mode,
                )
            )
            for tool in tools:
                name = tool.get("name")
                if isinstance(name, str) and name:
                    self._known_tools.add(name)
            if self.policy.llm_judge.enabled:
                for tool in tools:
                    tool_name = str(tool.get("name", ""))
                    findings.extend(
                        await self.llm_judge.evaluate(
                            "tool_definition",
                            canonical_json(tool),
                            target=f"tool:{tool_name}",
                            mode=mode,
                        )
                    )

        if prompts is not None:
            findings.extend(self.poisoning.scan_prompts(prompts, mode=mode))
            findings.extend(self.unicode_guard.scan_prompts(prompts, mode=mode))
            if self.policy.llm_judge.enabled:
                for prompt in prompts:
                    prompt_name = str(prompt.get("name", ""))
                    findings.extend(
                        await self.llm_judge.evaluate(
                            "prompt_definition",
                            canonical_json(prompt),
                            target=f"prompt:{prompt_name}",
                            mode=mode,
                        )
                    )

        if resources is not None:
            findings.extend(self.poisoning.scan_resources(resources, mode=mode))
            findings.extend(self.unicode_guard.scan_resources(resources, mode=mode))

        return findings

    def _log_findings(
        self,
        event: str,
        *,
        method: str,
        findings: list[SecurityFinding],
    ) -> None:
        if not findings:
            return
        log_security_event(
            self._logger,
            event,
            server_id=self.server_id,
            mode=self.policy.mode.value,
            method=method,
            finding_count=len(findings),
            rules=_unique_rule_ids(findings),
        )

    def _emit_event(
        self,
        *,
        direction: Literal["request", "response"],
        method: str,
        tool_name: str | None,
        uri: str | None,
        decision: PipelineDecision,
    ) -> None:
        if self._event_sink is None:
            return

        action = _resolve_event_action(decision)
        max_severity = (
            max(decision.findings, key=lambda f: f.severity.rank).severity.value
            if decision.findings
            else None
        )
        finding_dicts = [
            {
                "rule_id": finding.rule_id,
                "detector": finding.detector,
                "severity": finding.severity.value,
                "title": finding.title,
                "target": finding.target,
                "action_taken": finding.action_taken.value,
            }
            for finding in decision.findings
        ]

        label = method or direction
        if not decision.allowed:
            summary = (
                decision.error_message or f"Blocked {label} ({len(decision.findings)} finding(s))"
            )
        elif decision.blocked_tools:
            summary = (
                f"Stripped {len(decision.blocked_tools)} tool(s) from {label}: "
                f"{', '.join(decision.blocked_tools)}"
            )
        elif decision.findings:
            rules = ", ".join(_unique_rule_ids(decision.findings))
            summary = f"{action.upper()} on {label} ({len(decision.findings)} finding(s): {rules})"
        else:
            subject = tool_name or uri
            summary = f"Allowed {label}" + (f" ({subject})" if subject else "")

        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "direction": direction,
            "method": method,
            "tool_name": tool_name,
            "uri": uri,
            "allowed": decision.allowed,
            "action": action,
            "max_severity": max_severity,
            "findings": finding_dicts,
            "summary": summary,
            "server_id": self.server_id,
        }
        try:
            self._event_sink(event)
        except Exception as exc:
            self._logger.debug("Event sink failed: %s", exc)
