"""Unit and CLI tests for mcp_guard.cli."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mcp_guard.cli as cli_module
from mcp_guard.cli import app
from mcp_guard.engine.pinning import PinStore
from mcp_guard.models.findings import Action, ScanReport, SecurityFinding, Severity
from mcp_guard.models.policy import GuardMode, PinningConfig, PinningMode, PolicyConfig
from mcp_guard.policy.loader import load_policy

runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SERVER = REPO_ROOT / "demo" / "vulnerable_server.py"
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _strip_ansi(text: str) -> str:
    """Strip ANSI/VT escape sequences from CLI output."""
    return _ANSI_ESCAPE_RE.sub("", text)


def _make_report(severities: list[Severity], target: str = "python srv.py") -> ScanReport:
    findings = [
        SecurityFinding(
            rule_id=f"MCP-TEST-{idx}",
            detector="test",
            severity=sev,
            title=f"Finding {idx}",
            description=f"Test finding with severity {sev.value}.",
            target=f"tool:t{idx}",
            evidence="sample",
            remediation="fix it",
            action_taken=Action.LOG,
        )
        for idx, sev in enumerate(severities, start=1)
    ]
    return ScanReport(
        target=target,
        server_id="test-srv-123",
        tools_scanned=len(severities),
        findings=findings,
    )


def test_scan_child_flag_passthrough_preserves_all_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Child flags (-y, --port=3000, --custom-flag) after '--' are forwarded verbatim."""
    captured: dict[str, Any] = {}

    async def fake_scan_stdio(
        self: Any,
        command: list[str],
        *,
        rug_pull_probes: int = 2,
        timeout: float = 15.0,
    ) -> ScanReport:
        captured["command"] = list(command)
        captured["rug_pull_probes"] = rug_pull_probes
        captured["timeout"] = timeout
        return _make_report([], target=" ".join(command))

    monkeypatch.setattr(cli_module.ActiveScanner, "scan_stdio", fake_scan_stdio)
    pin_file = tmp_path / "pins.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "json",
            "--pin-file",
            str(pin_file),
            "--rug-pull-probes",
            "3",
            "--",
            "npx",
            "-y",
            "@modelcontextprotocol/server-everything",
            "--port=3000",
            "--custom-flag",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["command"] == [
        "npx",
        "-y",
        "@modelcontextprotocol/server-everything",
        "--port=3000",
        "--custom-flag",
    ]
    assert captured["rug_pull_probes"] == 3
    parsed = json.loads(result.output)
    assert parsed["server_id"] == "test-srv-123"


def test_scan_missing_child_command_exits_2() -> None:
    """Invoking scan with no child command exits with code 2."""
    result = runner.invoke(app, ["scan", "--format", "json"])
    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("severities", "fail_on", "expected_code"),
    [
        ([Severity.MEDIUM], "high", 0),
        ([Severity.HIGH], "high", 1),
        ([Severity.CRITICAL], "high", 1),
        ([Severity.CRITICAL], "none", 0),
        ([Severity.LOW], "low", 1),
    ],
)
def test_scan_fail_on_thresholds(
    monkeypatch: pytest.MonkeyPatch,
    severities: list[Severity],
    fail_on: str,
    expected_code: int,
) -> None:
    """`scan --fail-on` exits 1 iff a finding meets or exceeds threshold (unless none)."""

    async def fake_scan_stdio(
        self: Any,
        command: list[str],
        *,
        rug_pull_probes: int = 2,
        timeout: float = 15.0,
    ) -> ScanReport:
        return _make_report(severities)

    monkeypatch.setattr(cli_module.ActiveScanner, "scan_stdio", fake_scan_stdio)
    result = runner.invoke(
        app,
        ["scan", "--format", "json", "--fail-on", fail_on, "--", "python", "srv.py"],
    )
    assert result.exit_code == expected_code


def test_scan_formats_and_output_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`scan` writes SARIF, Markdown, JSON, and Console reports to UTF-8 --output files."""

    async def fake_scan_stdio(
        self: Any,
        command: list[str],
        *,
        rug_pull_probes: int = 2,
        timeout: float = 15.0,
    ) -> ScanReport:
        return _make_report([Severity.HIGH])

    monkeypatch.setattr(cli_module.ActiveScanner, "scan_stdio", fake_scan_stdio)

    sarif_path = tmp_path / "out.sarif"
    res_sarif = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "sarif",
            "--output",
            str(sarif_path),
            "--fail-on",
            "none",
            "--",
            "python",
            "srv.py",
        ],
    )
    assert res_sarif.exit_code == 0
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1

    md_path = tmp_path / "out.md"
    res_md = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "markdown",
            "--output",
            str(md_path),
            "--fail-on",
            "none",
            "--",
            "python",
            "srv.py",
        ],
    )
    assert res_md.exit_code == 0
    md_text = md_path.read_text(encoding="utf-8")
    assert "# MCP-Guard Security Audit Report" in md_text
    assert "MCP-TEST-1" in md_text

    console_path = tmp_path / "out.txt"
    res_console = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "console",
            "--output",
            str(console_path),
            "--fail-on",
            "none",
            "--",
            "python",
            "srv.py",
        ],
    )
    assert res_console.exit_code == 0
    assert "MCP-TEST-1" in console_path.read_text(encoding="utf-8")


def test_scan_http_command(monkeypatch: pytest.MonkeyPatch) -> None:
    """`scan-http` delegates to ActiveScanner.scan_http and honors --fail-on."""
    captured: dict[str, Any] = {}

    async def fake_scan_http(
        self: Any,
        url: str,
        *,
        rug_pull_probes: int = 2,
        timeout: float = 15.0,
    ) -> ScanReport:
        captured["url"] = url
        captured["probes"] = rug_pull_probes
        return _make_report([Severity.CRITICAL], target=url)

    monkeypatch.setattr(cli_module.ActiveScanner, "scan_http", fake_scan_http)
    res = runner.invoke(
        app,
        ["scan-http", "--url", "http://127.0.0.1:9000/mcp", "--format", "json"],
    )
    assert res.exit_code == 1
    assert captured["url"] == "http://127.0.0.1:9000/mcp"
    assert captured["probes"] == 2
    assert json.loads(res.output)["target"] == "http://127.0.0.1:9000/mcp"


def test_wrap_child_flag_passthrough_and_stdout_purity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`wrap` passes all child flags verbatim and emits zero bytes to stdout."""
    captured: dict[str, Any] = {}

    def fake_run_stdio_proxy(
        command: list[str],
        policy: PolicyConfig,
        *,
        logger: Any = None,
    ) -> int:
        captured["command"] = list(command)
        captured["mode"] = policy.mode
        captured["pin_file"] = policy.pinning.pin_file
        return 0

    monkeypatch.setattr(cli_module, "run_stdio_proxy", fake_run_stdio_proxy)
    pin_file = tmp_path / "pins.json"

    result = runner.invoke(
        app,
        [
            "wrap",
            "--mode",
            "redact",
            "--pin-file",
            str(pin_file),
            "--",
            "npx",
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/tmp",
            "--custom-flag",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    assert captured["command"] == [
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp",
        "--custom-flag",
    ]
    assert captured["mode"] == GuardMode.REDACT
    assert captured["pin_file"] == str(pin_file)


def test_wrap_missing_child_command_exits_2() -> None:
    """Invoking wrap without a target command exits with code 2 and emits no stdout."""
    result = runner.invoke(app, ["wrap", "--mode", "enforce"])
    assert result.exit_code == 2
    assert result.stdout == ""


def test_pins_list_approve_and_reset(tmp_path: Path) -> None:
    """`pins list`, `pins approve`, and `pins reset` manage pending and pinned tools."""
    pin_file = tmp_path / "pins.json"
    from mcp_guard.engine.pinning import SchemaPinner

    pinner = SchemaPinner(
        PinningConfig(enabled=True, mode=PinningMode.STRICT, pin_file=str(pin_file))
    )
    pinner.verify_tools(
        "srv-alpha",
        [
            {"name": "tool_a", "description": "A", "inputSchema": {"type": "object"}},
            {"name": "tool_b", "description": "B", "inputSchema": {"type": "object"}},
        ],
    )

    list_res = runner.invoke(
        app,
        ["pins", "list", "--pin-file", str(pin_file), "--server-id", "srv-alpha"],
        env={"COLUMNS": "120"},
    )
    assert list_res.exit_code == 0
    clean_list_output = _strip_ansi(list_res.output)
    assert "tool_a" in clean_list_output
    assert "pending" in clean_list_output

    approve_one = runner.invoke(
        app,
        [
            "pins",
            "approve",
            "--pin-file",
            str(pin_file),
            "--server-id",
            "srv-alpha",
            "--tool",
            "tool_a",
        ],
    )
    assert approve_one.exit_code == 0
    assert "Approved 1" in approve_one.output

    store = PinStore(pin_file)
    data = store.list_pins("srv-alpha")["srv-alpha"]
    assert "tool_a" in data["tools"]
    assert "tool_b" in data["pending"]

    reset_res = runner.invoke(
        app,
        ["pins", "reset", "--pin-file", str(pin_file), "--server-id", "srv-alpha"],
    )
    assert reset_res.exit_code == 0
    assert "Cleared 2" in reset_res.output
    assert store.list_pins() == {}


def test_init_writes_valid_policy_and_respects_force(tmp_path: Path) -> None:
    """`init` generates a valid YAML policy and refuses overwrite unless --force is passed."""
    out_file = tmp_path / "mcp-guard.yaml"

    first = runner.invoke(app, ["init", "--output", str(out_file)])
    assert first.exit_code == 0
    loaded = load_policy(out_file)
    assert loaded.mode == GuardMode.ENFORCE

    second = runner.invoke(app, ["init", "--output", str(out_file)])
    assert second.exit_code == 1

    third = runner.invoke(app, ["init", "--output", str(out_file), "--force"])
    assert third.exit_code == 0


def test_scan_against_vulnerable_demo_server(tmp_path: Path) -> None:
    """Real end-to-end CLI scan against demo/vulnerable_server.py exits 1 with findings."""
    sarif_path = tmp_path / "demo.sarif"
    res = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "sarif",
            "--output",
            str(sarif_path),
            "--pin-file",
            str(tmp_path / "pins.json"),
            "--",
            sys.executable,
            str(DEMO_SERVER),
        ],
    )
    assert res.exit_code == 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "MCP-UNI-001" in rule_ids
    assert "MCP-RUG-001" in rule_ids
    assert "MCP-SHD-001" in rule_ids
    assert any(rid.startswith("MCP-POI-") for rid in rule_ids)


def test_demo_command_smoke() -> None:
    """`mcp-guard demo` runs the full live demonstration and exits 0."""
    result = runner.invoke(app, ["demo"], env={"COLUMNS": "120"})
    assert result.exit_code == 0, result.output
    assert "MCP-Guard live demo completed successfully." in _strip_ansi(result.output)


def test_ui_help(monkeypatch: pytest.MonkeyPatch) -> None:
    """`mcp-guard ui --help` displays Web UI options."""
    monkeypatch.setattr("typer.rich_utils.MAX_WIDTH", 120, raising=False)
    result = runner.invoke(app, ["ui", "--help"], env={"COLUMNS": "120"})
    assert result.exit_code == 0
    clean_output = _strip_ansi(result.output)
    assert "--host" in clean_output
    assert "--port" in clean_output
    assert "--allow-exec" in clean_output
    assert "--no-open" in clean_output


def test_ui_rejects_non_loopback_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """`mcp-guard ui --host 0.0.0.0` is rejected with exit code 2."""
    called = False

    def fake_run_ui_server(**_kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(cli_module, "run_ui_server", fake_run_ui_server)
    result = runner.invoke(app, ["ui", "--host", "0.0.0.0"])
    assert result.exit_code == 2
    assert not called
    assert "loopback" in result.output.lower()


def test_ui_no_open_and_browser_launch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`mcp-guard ui` forwards options, respects --no-open, and opens browser when enabled."""
    captured: dict[str, Any] = {}
    opened_urls: list[str] = []

    def fake_run_ui_server(**kwargs: Any) -> None:
        captured.update(kwargs)
        on_ready = kwargs.get("on_ready")
        if callable(on_ready):
            on_ready("http://127.0.0.1:8766/?token=testtoken")

    monkeypatch.setattr(cli_module, "run_ui_server", fake_run_ui_server)
    monkeypatch.setattr(cli_module.webbrowser, "open", lambda url: opened_urls.append(url) or True)

    pin_file = tmp_path / "pins.json"
    res_no_open = runner.invoke(
        app,
        [
            "ui",
            "--host",
            "localhost",
            "--port",
            "0",
            "--pin-file",
            str(pin_file),
            "--server-id",
            "ui-test",
            "--allow-exec",
            "--no-open",
        ],
    )
    assert res_no_open.exit_code == 0, res_no_open.output
    assert captured["host"] == "localhost"
    assert captured["port"] == 0
    assert captured["allow_exec"] is True
    assert captured["server_id"] == "ui-test"
    assert opened_urls == []
    assert "http://127.0.0.1:8766/?token=testtoken" in res_no_open.output

    res_open = runner.invoke(app, ["ui", "--port", "8766"])
    assert res_open.exit_code == 0, res_open.output
    assert opened_urls == ["http://127.0.0.1:8766/?token=testtoken"]


def test_wrap_ui_port_forwarding_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """`wrap --ui-port` validates --ui-host and forwards UI options to run_stdio_proxy."""
    captured: dict[str, Any] = {}

    def fake_run_stdio_proxy(
        command: list[str],
        policy: PolicyConfig,
        *,
        logger: Any = None,
        ui_port: int | None = None,
        ui_host: str = "127.0.0.1",
    ) -> int:
        captured["command"] = list(command)
        captured["policy"] = policy
        captured["ui_port"] = ui_port
        captured["ui_host"] = ui_host
        return 0

    monkeypatch.setattr(cli_module, "run_stdio_proxy", fake_run_stdio_proxy)

    ok_res = runner.invoke(
        app,
        ["wrap", "--ui-port", "8777", "--ui-host", "localhost", "--", "python", "srv.py"],
    )
    assert ok_res.exit_code == 0
    assert ok_res.stdout == ""
    assert captured["ui_port"] == 8777
    assert captured["ui_host"] == "localhost"
    assert captured["command"] == ["python", "srv.py"]

    bad_res = runner.invoke(
        app,
        ["wrap", "--ui-port", "8777", "--ui-host", "0.0.0.0", "--", "python", "srv.py"],
    )
    assert bad_res.exit_code == 2
    assert bad_res.stdout == ""


def test_wrap_http_ui_port_forwarding_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """`wrap-http --ui-port` validates --ui-host and forwards UI options to run_http_proxy."""
    captured: dict[str, Any] = {}

    def fake_run_http_proxy(
        target: str,
        policy: PolicyConfig,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        logger: Any = None,
        ui_port: int | None = None,
        ui_host: str = "127.0.0.1",
    ) -> None:
        captured["target"] = target
        captured["host"] = host
        captured["port"] = port
        captured["ui_port"] = ui_port
        captured["ui_host"] = ui_host

    monkeypatch.setattr(cli_module, "run_http_proxy", fake_run_http_proxy)

    ok_res = runner.invoke(
        app,
        [
            "wrap-http",
            "--target",
            "http://127.0.0.1:9000/mcp",
            "--ui-port",
            "8778",
            "--ui-host",
            "::1",
        ],
    )
    assert ok_res.exit_code == 0
    assert captured["target"] == "http://127.0.0.1:9000/mcp"
    assert captured["ui_port"] == 8778
    assert captured["ui_host"] == "::1"

    bad_res = runner.invoke(
        app,
        [
            "wrap-http",
            "--target",
            "http://127.0.0.1:9000/mcp",
            "--ui-port",
            "8778",
            "--ui-host",
            "0.0.0.0",
        ],
    )
    assert bad_res.exit_code == 2
