"""STDIO JSON-RPC 2.0 security proxy with strict stream purity and Windows binary framing."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from mcp_guard.engine.pipeline import SecurityPipeline
from mcp_guard.models.jsonrpc import make_error_response, parse_jsonrpc_frame
from mcp_guard.models.policy import PolicyConfig
from mcp_guard.policy.loader import load_policy
from mcp_guard.ui import (
    EmbeddedUiHandle,
    EventBus,
    start_embedded_ui_server,
    validate_loopback_host,
)
from mcp_guard.utils.canonical import normalize_server_id
from mcp_guard.utils.logging import configure_logger

MAX_FRAME_BYTES = 32 * 1024 * 1024
READ_CHUNK_BYTES = 65536
MAX_INFLIGHT_REQUESTS = 4096
PARSE_ERROR_CODE = -32700


@dataclass(frozen=True, slots=True)
class RequestMetadata:
    """In-flight JSON-RPC request metadata for correlating responses."""

    method: str
    tool_name: str | None = None
    uri: str | None = None


def _make_request_key(req_id: Any) -> tuple[str, int | str] | None:
    """Build a collision-free key distinguishing int 1 from str '1', rejecting bool/None."""
    if req_id is None or isinstance(req_id, bool):
        return None
    if not isinstance(req_id, (int, str)):
        return None
    return (type(req_id).__name__, req_id)


def _extract_request_metadata(msg: dict[str, Any]) -> RequestMetadata:
    method = str(msg.get("method", ""))
    params = msg.get("params")
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
    return RequestMetadata(method=method, tool_name=tool_name, uri=uri)


class BoundedRequestTracker:
    """Bounded FIFO-evicting OrderedDict tracking in-flight JSON-RPC request IDs."""

    def __init__(self, max_entries: int = MAX_INFLIGHT_REQUESTS) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, int | str], RequestMetadata] = OrderedDict()

    def record_frame(self, frame: dict[str, Any] | list[dict[str, Any]]) -> None:
        """Record any requests with an 'id' and 'method' from a single or batch frame."""
        items = frame if isinstance(frame, list) else [frame]
        for item in items:
            if "id" not in item or "method" not in item:
                continue
            key = _make_request_key(item.get("id"))
            if key is None:
                continue
            meta = _extract_request_metadata(item)
            self._entries[key] = meta
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def pop_for_id(self, req_id: Any) -> RequestMetadata | None:
        """Pop and return tracked request metadata for a response 'id', if present."""
        key = _make_request_key(req_id)
        if key is None:
            return None
        return self._entries.pop(key, None)


def _serialize_jsonrpc(frame: dict[str, Any] | list[dict[str, Any]]) -> bytes:
    """Serialize a JSON-RPC dict or batch list into compact single-line UTF-8 bytes."""
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class StdioProxy:
    """Bidirectional STDIO MCP security proxy around a child MCP server process."""

    def __init__(
        self,
        command: Sequence[str],
        policy: PolicyConfig,
        *,
        logger: logging.Logger | None = None,
        stdin_stream: BinaryIO | None = None,
        stdout_writer: Callable[[bytes], None] | None = None,
        stderr_writer: Callable[[bytes], None] | None = None,
        env: Mapping[str, str] | None = None,
        ui_port: int | None = None,
        ui_host: str = "127.0.0.1",
        event_bus: EventBus | None = None,
    ) -> None:
        if not command:
            raise ValueError("Target command must not be empty")
        self.command = list(command)
        self.policy = policy
        log_path = Path(policy.log_file) if policy.log_file else None
        self._logger = logger or configure_logger("mcp_guard.proxy.stdio", log_file=log_path)
        self.server_id = policy.server_id or normalize_server_id(self.command)
        self._ui_port = ui_port
        self._ui_host = validate_loopback_host(ui_host) if ui_port is not None else ui_host
        self._event_bus: EventBus | None = (
            event_bus or EventBus() if (ui_port is not None or event_bus is not None) else None
        )
        self.event_bus = self._event_bus
        self.pipeline = SecurityPipeline(
            policy,
            server_id=self.server_id,
            logger=self._logger,
            event_sink=self._event_bus.publish if self._event_bus is not None else None,
        )
        self._stdin_stream = stdin_stream
        self._stdout_writer = stdout_writer
        self._stderr_writer = stderr_writer
        self._extra_env = dict(env) if env else {}
        self._stdout_lock = threading.Lock()
        self._stderr_lock = threading.Lock()
        self._tracker = BoundedRequestTracker()

    def _write_stdout_frame(self, frame_bytes: bytes) -> None:
        """Write exactly one UTF-8 JSON-RPC frame terminated with LF to stdout."""
        with self._stdout_lock:
            if self._stdout_writer is not None:
                self._stdout_writer(frame_bytes)
                return
            sys.stdout.buffer.write(frame_bytes + b"\n")
            sys.stdout.buffer.flush()

    def _write_stderr_bytes(self, data: bytes) -> None:
        """Forward raw child stderr bytes to parent stderr."""
        if not data:
            return
        with self._stderr_lock:
            if self._stderr_writer is not None:
                self._stderr_writer(data)
                return
            sys.stderr.buffer.write(data)
            sys.stderr.buffer.flush()

    def _build_child_env(self) -> dict[str, str]:
        child_env = dict(os.environ)
        child_env.update(self._extra_env)
        child_env["PYTHONUTF8"] = "1"
        child_env["PYTHONIOENCODING"] = "utf-8"
        return child_env

    def _spawn_stdin_reader(
        self,
        loop: asyncio.AbstractEventLoop,
        queue: asyncio.Queue[bytes | None],
        stop_event: threading.Event,
    ) -> threading.Thread:
        stream = self._stdin_stream if self._stdin_stream is not None else sys.stdin.buffer

        def _put_item(item: bytes | None) -> None:
            if loop.is_closed():
                return
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(queue.put_nowait, item)

        def _reader_loop() -> None:
            try:
                while not stop_event.is_set():
                    raw_line = stream.readline()
                    if raw_line == b"":
                        _put_item(None)
                        break
                    stripped = raw_line.rstrip(b"\r\n")
                    if not stripped:
                        continue
                    _put_item(stripped)
            except (OSError, ValueError):
                _put_item(None)

        thread = threading.Thread(target=_reader_loop, name="mcp-guard-stdin-reader", daemon=True)
        thread.start()
        return thread

    async def _pump_client_to_server(
        self,
        stdin_queue: asyncio.Queue[bytes | None],
        proc_stdin: asyncio.StreamWriter,
    ) -> None:
        while True:
            frame_bytes = await stdin_queue.get()
            if frame_bytes is None:
                return

            if len(frame_bytes) > MAX_FRAME_BYTES:
                self._logger.warning(
                    "Client JSON-RPC frame exceeded %d bytes; rejecting",
                    MAX_FRAME_BYTES,
                )
                err = make_error_response(
                    None,
                    PARSE_ERROR_CODE,
                    f"Frame exceeds maximum allowed size of {MAX_FRAME_BYTES} bytes",
                )
                self._write_stdout_frame(_serialize_jsonrpc(err))
                continue

            try:
                parsed = parse_jsonrpc_frame(frame_bytes)
            except ValueError as exc:
                self._logger.warning("Malformed JSON-RPC frame from client: %s", exc)
                err = make_error_response(None, PARSE_ERROR_CODE, f"Parse error: {exc}")
                self._write_stdout_frame(_serialize_jsonrpc(err))
                continue

            decision = await self.pipeline.inspect_request(parsed)
            if not decision.allowed:
                if decision.message is not None:
                    self._write_stdout_frame(_serialize_jsonrpc(decision.message))
                continue

            outgoing = decision.message if decision.message is not None else parsed
            self._tracker.record_frame(outgoing)
            try:
                proc_stdin.write(_serialize_jsonrpc(outgoing) + b"\n")
                await proc_stdin.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

    async def _handle_server_frame(self, line: bytes) -> None:
        try:
            parsed = parse_jsonrpc_frame(line)
        except ValueError as exc:
            self._logger.warning("Malformed JSON-RPC frame from upstream server: %s", exc)
            return

        if isinstance(parsed, dict):
            meta = self._tracker.pop_for_id(parsed.get("id"))
            decision = await self.pipeline.inspect_response(
                parsed,
                method=meta.method if meta else None,
                tool_name=meta.tool_name if meta else None,
                uri=meta.uri if meta else None,
            )
            if decision.message is not None:
                self._write_stdout_frame(_serialize_jsonrpc(decision.message))
            return

        out_batch: list[dict[str, Any]] = []
        for item in parsed:
            meta = self._tracker.pop_for_id(item.get("id"))
            decision = await self.pipeline.inspect_response(
                item,
                method=meta.method if meta else None,
                tool_name=meta.tool_name if meta else None,
                uri=meta.uri if meta else None,
            )
            if isinstance(decision.message, dict):
                out_batch.append(decision.message)

        if out_batch:
            self._write_stdout_frame(_serialize_jsonrpc(out_batch))

    async def _pump_server_to_client(self, proc_stdout: asyncio.StreamReader) -> None:
        buffer = bytearray()
        dropping_oversized = False

        while True:
            chunk = await proc_stdout.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            buffer.extend(chunk)

            while True:
                nl_idx = buffer.find(b"\n")
                if nl_idx == -1:
                    break
                raw_line = bytes(buffer[:nl_idx]).rstrip(b"\r")
                del buffer[: nl_idx + 1]
                if dropping_oversized:
                    dropping_oversized = False
                    continue
                if len(raw_line) > MAX_FRAME_BYTES:
                    self._logger.warning(
                        "Server JSON-RPC frame exceeded %d bytes; dropping",
                        MAX_FRAME_BYTES,
                    )
                    continue
                if raw_line:
                    await self._handle_server_frame(raw_line)

            if len(buffer) > MAX_FRAME_BYTES:
                self._logger.warning(
                    "Server JSON-RPC line buffer exceeded %d bytes without newline; dropping",
                    MAX_FRAME_BYTES,
                )
                buffer.clear()
                dropping_oversized = True

        if buffer and not dropping_oversized:
            tail = bytes(buffer).rstrip(b"\r")
            if tail:
                await self._handle_server_frame(tail)

    async def _pump_server_stderr(self, proc_stderr: asyncio.StreamReader) -> None:
        while True:
            chunk = await proc_stderr.read(READ_CHUNK_BYTES)
            if not chunk:
                return
            self._write_stderr_bytes(chunk)

    @staticmethod
    async def _terminate_process(proc: asyncio.subprocess.Process) -> int:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
        else:
            await proc.wait()
        return proc.returncode if proc.returncode is not None else 0

    async def run(self) -> int:
        """Start the wrapped MCP server and proxy STDIO JSON-RPC traffic until shutdown."""
        loop = asyncio.get_running_loop()
        proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._build_child_env(),
        )
        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        stdin_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        stop_thread_event = threading.Event()
        shutdown_event = asyncio.Event()

        def _trigger_shutdown() -> None:
            if not loop.is_closed():
                shutdown_event.set()

        installed_loop_signals: list[signal.Signals] = []
        prev_signal_handlers: dict[signal.Signals, Any] = {}
        is_main_thread = threading.current_thread() is threading.main_thread()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _trigger_shutdown)
                installed_loop_signals.append(sig)
            except (NotImplementedError, RuntimeError):
                if is_main_thread:
                    with contextlib.suppress(ValueError, OSError):
                        prev_signal_handlers[sig] = signal.getsignal(sig)
                        signal.signal(
                            sig,
                            lambda _s, _f: loop.call_soon_threadsafe(_trigger_shutdown),
                        )

        self._spawn_stdin_reader(loop, stdin_queue, stop_thread_event)

        client_task = asyncio.create_task(
            self._pump_client_to_server(stdin_queue, proc.stdin),
            name="stdio-proxy-client-pump",
        )
        server_task = asyncio.create_task(
            self._pump_server_to_client(proc.stdout),
            name="stdio-proxy-server-pump",
        )
        stderr_task = asyncio.create_task(
            self._pump_server_stderr(proc.stderr),
            name="stdio-proxy-stderr-pump",
        )
        signal_task = asyncio.create_task(
            shutdown_event.wait(),
            name="stdio-proxy-shutdown-waiter",
        )

        exit_code = 0
        ui_handle: EmbeddedUiHandle | None = None
        try:
            if self._ui_port is not None:
                ui_handle = await start_embedded_ui_server(
                    policy=self.policy,
                    event_bus=self._event_bus,
                    pipeline=self.pipeline,
                    pin_file=self.policy.pinning.pin_file,
                    server_id=self.server_id,
                    host=self._ui_host,
                    port=self._ui_port,
                    logger=self._logger,
                )
                if ui_handle is not None:
                    self._logger.info("MCP-Guard Web UI listening at %s", ui_handle.url)

            done, _ = await asyncio.wait(
                {client_task, server_task, signal_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if client_task in done and server_task not in done and signal_task not in done:
                # Parent stdin reached EOF: close child stdin and allow buffered responses to drain.
                with contextlib.suppress(OSError):
                    proc.stdin.close()
                if hasattr(proc.stdin, "wait_closed"):
                    with contextlib.suppress(OSError, TimeoutError):
                        await asyncio.wait_for(proc.stdin.wait_closed(), timeout=0.5)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(server_task, timeout=1.5)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stderr_task, timeout=0.5)
            elif server_task in done and signal_task not in done:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stderr_task, timeout=0.5)
        finally:
            if ui_handle is not None:
                await ui_handle.stop()

            stop_thread_event.set()
            for sig in installed_loop_signals:
                with contextlib.suppress(NotImplementedError, RuntimeError):
                    loop.remove_signal_handler(sig)
            for sig, prev in prev_signal_handlers.items():
                with contextlib.suppress(ValueError, OSError):
                    signal.signal(sig, prev)

            for task in (client_task, server_task, stderr_task, signal_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(
                client_task,
                server_task,
                stderr_task,
                signal_task,
                return_exceptions=True,
            )
            exit_code = await self._terminate_process(proc)

        return exit_code


def run_stdio_proxy(
    command: Sequence[str],
    policy: PolicyConfig,
    *,
    logger: logging.Logger | None = None,
    ui_port: int | None = None,
    ui_host: str = "127.0.0.1",
    event_bus: EventBus | None = None,
) -> int:
    """Run the STDIO MCP security proxy synchronously and return child/proxy exit code."""
    proxy = StdioProxy(
        command,
        policy,
        logger=logger,
        ui_port=ui_port,
        ui_host=ui_host,
        event_bus=event_bus,
    )
    try:
        return asyncio.run(proxy.run())
    except KeyboardInterrupt:
        return 130


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m mcp_guard.proxy.stdio_proxy",
        description="Run MCP-Guard STDIO proxy wrapping an MCP server command.",
    )
    parser.add_argument("--policy", type=Path, default=None, help="Path to YAML policy file.")
    parser.add_argument("--mode", choices=["enforce", "audit", "redact"], default=None)
    parser.add_argument("--pin-file", type=str, default=None)
    parser.add_argument("--server-id", type=str, default=None)
    parser.add_argument("--log-file", type=str, default=None)
    parser.add_argument("--llm-judge", action="store_true", default=None)
    parser.add_argument("--ui-port", type=int, default=None)
    parser.add_argument("--ui-host", type=str, default="127.0.0.1")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Target command after --.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `python -m mcp_guard.proxy.stdio_proxy`."""
    parser = _build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("A target MCP server command is required (e.g. -- python server.py)")

    if args.ui_port is not None:
        try:
            validate_loopback_host(args.ui_host)
        except ValueError as exc:
            parser.error(str(exc))

    policy = load_policy(
        args.policy,
        mode=args.mode,
        pin_file=args.pin_file,
        server_id=args.server_id,
        log_file=args.log_file,
        llm_judge=args.llm_judge,
    )
    log_path = Path(policy.log_file) if policy.log_file else None
    logger = configure_logger("mcp_guard.proxy.stdio", log_file=log_path)
    return run_stdio_proxy(
        command,
        policy,
        logger=logger,
        ui_port=args.ui_port,
        ui_host=args.ui_host,
    )


if __name__ == "__main__":
    raise SystemExit(main())
