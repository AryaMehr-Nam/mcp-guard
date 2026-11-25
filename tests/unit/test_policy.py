"""Unit tests for policy loading, defaults, overrides, and JSON-RPC ID validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_guard.models.jsonrpc import JsonRpcRequest, make_error_response, parse_jsonrpc_frame
from mcp_guard.models.policy import GuardMode, PinningMode, PolicyConfig
from mcp_guard.policy.loader import default_policy_yaml, load_policy


class TestPolicyLoader:
    """Tests for PolicyConfig defaults and YAML policy loading."""

    def test_load_default_policy_without_file(self) -> None:
        policy = load_policy()
        assert isinstance(policy, PolicyConfig)
        assert policy.mode == GuardMode.ENFORCE
        assert policy.pinning.mode == PinningMode.TOFU
        assert policy.llm_judge.enabled is False

    def test_default_policy_yaml_matches_config_file(self, tmp_path: Path) -> None:
        repo_default = Path(__file__).resolve().parents[2] / "config" / "default-policy.yaml"
        from_repo = load_policy(repo_default)

        generated_path = tmp_path / "generated.yaml"
        generated_path.write_text(default_policy_yaml(), encoding="utf-8")
        from_generated = load_policy(generated_path)

        assert from_repo.model_dump() == from_generated.model_dump()

    def test_cli_overrides_applied(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("mode: audit\nrate_limit:\n  burst: 5\n", encoding="utf-8")

        loaded = load_policy(
            policy_file,
            mode="redact",
            pin_file=str(tmp_path / "custom-pins.json"),
            server_id="srv-123",
            log_file=str(tmp_path / "guard.log"),
            llm_judge=True,
        )
        assert loaded.mode == GuardMode.REDACT
        assert loaded.rate_limit.burst == 5
        assert loaded.pinning.pin_file == str(tmp_path / "custom-pins.json")
        assert loaded.server_id == "srv-123"
        assert loaded.log_file == str(tmp_path / "guard.log")
        assert loaded.llm_judge.enabled is True

    def test_invalid_policy_inputs_raise_value_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            load_policy(tmp_path / "missing.yaml")

        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("mode: [unclosed", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_policy(bad_yaml)

        non_mapping = tmp_path / "list.yaml"
        non_mapping.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_policy(non_mapping)

        with pytest.raises(ValueError, match="Invalid guard mode"):
            load_policy(mode="invalid-mode")


class TestJsonRpcContracts:
    """Regression tests for JsonRpcId bool rejection and strict UTF-8 frame parsing."""

    @pytest.mark.parametrize("bad_id", [True, False])
    def test_jsonrpc_id_rejects_booleans(self, bad_id: bool) -> None:
        with pytest.raises(ValidationError):
            JsonRpcRequest(id=bad_id, method="tools/list")
        with pytest.raises(ValueError, match="boolean"):
            make_error_response(bad_id, -32001, "blocked")

    def test_parse_jsonrpc_frame_rejects_invalid_utf8_and_empty_batch(self) -> None:
        with pytest.raises(ValueError, match="Invalid UTF-8"):
            parse_jsonrpc_frame(b"\xff\xfe")
        with pytest.raises(ValueError, match="empty"):
            parse_jsonrpc_frame("[]")
