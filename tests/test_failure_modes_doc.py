import ast
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from sir_firewall import core


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "failure-modes.md"
REASON_CODES = {
    "systemic_reset_internal_error",
    "systemic_reset_domain_pack_invalid",
    "systemic_reset_domain_pack_load_failed",
    "friction_limit_exceeded",
    "structured_validation_failed",
    "tool_result_validation_failed",
}


def _load_runner():
    spec = importlib.util.spec_from_file_location("failure_modes_red_team_suite", ROOT / "red_team_suite.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _isc(payload="ordinary safe request"):
    checksum = hashlib.sha256(str(payload).encode()).hexdigest()
    return {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": payload,
        "checksum": checksum,
        "signature": "",
    }


def test_documented_reason_codes_exist_in_implementation():
    document = DOC.read_text(encoding="utf-8")
    implementation = (ROOT / "src" / "sir_firewall" / "core.py").read_text(encoding="utf-8")

    for reason in REASON_CODES:
        assert f"`{reason}`" in document
        assert reason in implementation


def test_unhandled_matching_exception_and_unprintable_payload_fail_closed(monkeypatch):
    monkeypatch.setattr(core, "find_rule_hits", lambda _text: (_ for _ in ()).throw(RuntimeError("rule failed")))
    matched = core.validate_sir({"isc": _isc()})
    assert matched["status"] == "BLOCKED"
    assert matched["reason"] == "systemic_reset_internal_error"
    assert matched["itgl_log"][-1]["output"]["exception_type"] == "RuntimeError"

    class BadString:
        def __str__(self):
            raise ValueError("cannot stringify")

    converted = core.validate_sir(
        {
            "isc": {
                "version": "1.0",
                "template_id": "EU-AI-Act-ISC-v1",
                "payload": BadString(),
                "checksum": "irrelevant",
                "signature": "",
            }
        }
    )
    assert converted["status"] == "BLOCKED"
    assert converted["reason"] == "systemic_reset_internal_error"
    assert converted["itgl_log"][-1]["output"]["exception_type"] == "ValueError"


def test_oversized_payload_is_blocked_before_checksum_validation():
    payload = "x" * (2000 * 4 + 1)
    result = core.validate_sir({"isc": {**_isc(payload), "checksum": "wrong"}})
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "friction_limit_exceeded"
    assert result["itgl_log"][-1]["component"] == "friction"


@pytest.mark.parametrize("error", [RecursionError("deep"), MemoryError("exhausted")])
def test_structured_parser_exhaustion_is_specific_validation_block(monkeypatch, error):
    pack = core.load_domain_pack("generic_safety")
    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: pack)
    monkeypatch.setattr(core.json, "loads", lambda *_args, **_kwargs: (_ for _ in ()).throw(error))
    result = core.validate_sir({"structured_request": '{"request_text":"safe"}'})
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "structured_validation_failed"
    assert result["type"] == "structured_invalid_json"


def test_malformed_and_schema_invalid_domain_packs_share_invalid_reason(monkeypatch, tmp_path):
    path = tmp_path / "generic_safety.json"
    path.write_text("{", encoding="utf-8")
    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: core._read_domain_pack(path, "generic_safety"))
    malformed = core.validate_sir({"isc": _isc()})
    assert malformed["reason"] == "systemic_reset_domain_pack_invalid"

    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: core._validate_domain_pack_schema({}, "generic_safety"))
    invalid = core.validate_sir({"isc": _isc()})
    assert invalid["reason"] == "systemic_reset_domain_pack_invalid"


def test_runner_registry_errors_escape_without_request_verdict(tmp_path):
    red_team_suite = _load_runner()
    with pytest.raises(FileNotFoundError):
        red_team_suite._load_pack_registry(str(tmp_path / "absent.json"))
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        red_team_suite._load_pack_registry(str(malformed))


def test_rule_compilation_is_import_time_and_public_boundary_catches_exception_only():
    rules_tree = ast.parse((ROOT / "src" / "sir_firewall" / "deterministic_rules.py").read_text(encoding="utf-8"))
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
        and node.func.attr == "compile"
        for node in rules_tree.body
        for node in ast.walk(node)
    )
    core_source = (ROOT / "src" / "sir_firewall" / "core.py").read_text(encoding="utf-8")
    assert core_source.index("from .deterministic_rules import") < core_source.index("def validate_sir(")
    assert "except Exception as exc:" in core_source[core_source.index("def validate_sir(") :]
