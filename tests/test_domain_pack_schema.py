import copy
import hashlib
import json
from pathlib import Path

import pytest

from sir_firewall import core


PACK_DIR = Path(core.__file__).resolve().parent / "policy" / "isc_packs"
PACK_IDS = tuple(sorted(path.stem for path in PACK_DIR.glob("*.json")))


def _isc(payload: str = "ordinary safe request") -> dict:
    return {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": payload,
        "checksum": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "signature": "",
    }


def _generic_pack() -> dict:
    return json.loads((PACK_DIR / "generic_safety.json").read_text(encoding="utf-8"))


def _validate_through_gate(monkeypatch: pytest.MonkeyPatch, candidate: dict) -> dict:
    def invalid_loader(pack_id=None):
        return core._validate_domain_pack_schema(candidate, pack_id or "generic_safety")

    monkeypatch.setattr(core, "load_domain_pack", invalid_loader)
    return core.validate_sir({"isc": _isc()}, enforcement_pack_id="generic_safety")


def test_empty_domain_pack_fails_closed_with_invalid_pack_reason(monkeypatch):
    out = _validate_through_gate(monkeypatch, {})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "systemic_reset_domain_pack_invalid"
    assert out["itgl_log"][0]["input"]["error"] == "domain_pack_invalid"


def test_malformed_and_missing_domain_packs_have_distinct_reasons(monkeypatch, tmp_path):
    malformed = tmp_path / "generic_safety.json"
    malformed.write_text("{", encoding="utf-8")

    monkeypatch.setattr(
        core,
        "load_domain_pack",
        lambda pack_id=None: core._read_domain_pack(malformed, pack_id or "generic_safety"),
    )
    invalid = core.validate_sir({"isc": _isc()}, enforcement_pack_id="generic_safety")

    monkeypatch.setattr(
        core,
        "load_domain_pack",
        lambda pack_id=None: (_ for _ in ()).throw(FileNotFoundError("missing pack")),
    )
    missing = core.validate_sir({"isc": _isc()}, enforcement_pack_id="generic_safety")

    assert invalid["reason"] == "systemic_reset_domain_pack_invalid"
    assert invalid["itgl_log"][0]["input"]["error"] == "domain_pack_invalid"
    assert missing["reason"] == "systemic_reset_domain_pack_load_failed"
    assert missing["itgl_log"][0]["input"]["error"] == "domain_pack_load_failed"


MISSING_REQUIRED_KEYS = [
    ("pack_id",),
    ("templates",),
    ("flags",),
    *(("templates", template_id) for template_id in sorted(core._BUILTIN_ALLOWED_TEMPLATES)),
    *(("templates", template_id, "max_tokens") for template_id in sorted(core._BUILTIN_ALLOWED_TEMPLATES)),
    *(("flags", flag) for flag in sorted(core.DOMAIN_PACK_REQUIRED_FLAGS)),
]


@pytest.mark.parametrize("key_path", MISSING_REQUIRED_KEYS)
def test_domain_pack_missing_each_required_key_fails_closed(monkeypatch, key_path):
    candidate = copy.deepcopy(_generic_pack())
    target = candidate
    for key in key_path[:-1]:
        target = target[key]
    del target[key_path[-1]]

    out = _validate_through_gate(monkeypatch, candidate)

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "systemic_reset_domain_pack_invalid"


@pytest.mark.parametrize("pack_id", PACK_IDS)
def test_existing_domain_packs_load_native_types_and_evaluate_normally(pack_id):
    pack = core.load_domain_pack(pack_id)

    assert isinstance(pack["pack_id"], str)
    assert set(core._BUILTIN_ALLOWED_TEMPLATES) <= set(pack["templates"])
    for template_id in core._BUILTIN_ALLOWED_TEMPLATES:
        max_tokens = pack["templates"][template_id]["max_tokens"]
        assert isinstance(max_tokens, int) and not isinstance(max_tokens, bool)
    for flag in core.DOMAIN_PACK_REQUIRED_FLAGS:
        assert isinstance(pack["flags"][flag], bool)

    out = core.validate_sir({"isc": _isc()}, enforcement_pack_id=pack_id)
    assert out["status"] == "PASS"
    assert out["domain_pack"] == pack_id


def test_legacy_strict_flag_is_not_required_or_behavioral():
    candidate = _generic_pack()
    candidate["flags"].pop("STRICT_ISC_ENFORCEMENT")
    validated = core._validate_domain_pack_schema(candidate, "generic_safety")
    assert "STRICT_ISC_ENFORCEMENT" not in validated["flags"]


def test_legacy_strict_flag_value_does_not_change_gate_decision(monkeypatch):
    outcomes = []
    for value in (False, True):
        candidate = _generic_pack()
        candidate["flags"]["STRICT_ISC_ENFORCEMENT"] = value
        monkeypatch.setattr(
            core,
            "load_domain_pack",
            lambda pack_id=None, pack=candidate: core._validate_domain_pack_schema(
                pack, pack_id or "generic_safety"
            ),
        )
        outcomes.append(core.validate_sir({"isc": _isc()}))

    assert outcomes[0]["status"] == outcomes[1]["status"] == "PASS"
    assert outcomes[0]["reason"] == outcomes[1]["reason"]


def test_mid_evaluation_exception_fails_closed_with_diagnostic_itgl(monkeypatch):
    def fail_jailbreak(*_args, **_kwargs):
        raise RuntimeError("injected evaluation failure")

    monkeypatch.setattr(core, "_check_jailbreak", fail_jailbreak)
    out = core.validate_sir({"isc": _isc()})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "systemic_reset_internal_error"
    assert out["sr"]["sr_triggered"] is True
    assert out["itgl_log"][-1]["component"] == "internal_error"
    assert out["itgl_log"][-1]["output"] == {
        "exception_type": "RuntimeError",
        "message": "injected evaluation failure",
    }


def test_structured_parse_memory_error_fails_closed(monkeypatch):
    pack = core.load_domain_pack("generic_safety")

    def exhaust_memory(*_args, **_kwargs):
        raise MemoryError("injected parser exhaustion")

    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: pack)
    monkeypatch.setattr(core.json, "loads", exhaust_memory)
    out = core.validate_sir({"structured_request": '{"request_text":"safe"}'})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "structured_validation_failed"
    assert out["type"] == "structured_invalid_json"


def test_tool_result_parse_memory_error_fails_closed_with_ingress_reason(monkeypatch):
    pack = core.load_domain_pack("generic_safety")

    def exhaust_memory(*_args, **_kwargs):
        raise MemoryError("injected parser exhaustion")

    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: pack)
    monkeypatch.setattr(core.json, "loads", exhaust_memory)
    out = core.validate_sir({"tool_result": '{"tool_name":"browser","content":"safe"}'})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "tool_result_validation_failed"
    assert out["type"] == "tool_result_invalid_json"
