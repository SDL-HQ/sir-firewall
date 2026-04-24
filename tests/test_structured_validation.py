from sir_firewall import core


def _structured(**overrides):
    payload = {
        "schema_version": "v1",
        "request_class": "account_recovery_challenge",
        "action": "password_reset",
        "channel": "chat",
        "request_text": "I need to reset my password.",
    }
    payload.update(overrides)
    return payload


def test_valid_structured_input_passes():
    out = core.validate_sir(
        {
            "structured_request": _structured(
                declared_auth_state="unknown",
                case_ref="case-123",
            )
        }
    )

    assert out["status"] == "PASS"
    assert out["reason"] == "clean"


def test_structured_schema_sourced_from_pack_declaration(monkeypatch):
    def _fake_pack(pack_id=None):
        return {
            "pack_id": "generic_safety",
            "templates": {
                "HIPAA-ISC-v1": {"max_tokens": 1500},
                "EU-AI-Act-ISC-v1": {"max_tokens": 2000},
                "PCI-DSS-ISC-v1": {"max_tokens": 1200},
            },
            "flags": {
                "STRICT_ISC_ENFORCEMENT": True,
                "CHECKSUM_ENFORCED": True,
                "CRYPTO_ENFORCED": False,
            },
            "structured_request_schema": {
                "schema_id": "account_recovery_challenge_request_v1",
                "template_id": "PCI-DSS-ISC-v1",
                "required_fields": [
                    "schema_version",
                    "request_class",
                    "action",
                    "channel",
                    "request_text",
                ],
                "optional_fields": [
                    "declared_auth_state",
                    "case_ref",
                ],
                "schema_version_const": "v1",
                "request_class_const": "account_recovery_challenge",
                "action_enum": [
                    "wire_transfer",
                ],
                "channel_enum": [
                    "chat",
                ],
                "declared_auth_state_enum": [
                    "unknown",
                ],
                "case_ref_pattern": "^[A-Za-z0-9._:-]{1,64}$",
                "request_text_min_length": 1,
                "request_text_max_length": 4000,
            },
        }

    monkeypatch.setattr(core, "load_domain_pack", _fake_pack)
    out = core.validate_sir(
        {
            "structured_request": _structured(
                action="wire_transfer",
                channel="chat",
                declared_auth_state="unknown",
            )
        }
    )

    assert out["status"] == "PASS"
    assert out["governance_context"]["isc_template"] == "PCI-DSS-ISC-v1"


def test_structured_schema_missing_declaration_fails_closed(monkeypatch):
    def _fake_pack(pack_id=None):
        return {
            "pack_id": "generic_safety",
            "templates": {
                "HIPAA-ISC-v1": {"max_tokens": 1500},
                "EU-AI-Act-ISC-v1": {"max_tokens": 2000},
                "PCI-DSS-ISC-v1": {"max_tokens": 1200},
            },
            "flags": {
                "STRICT_ISC_ENFORCEMENT": True,
                "CHECKSUM_ENFORCED": True,
                "CRYPTO_ENFORCED": False,
            },
        }

    monkeypatch.setattr(core, "load_domain_pack", _fake_pack)
    out = core.validate_sir({"structured_request": _structured()})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "structured_validation_failed"
    assert out["type"] == "structured_schema_declaration_missing"


def test_structured_schema_invalid_declaration_fails_closed(monkeypatch):
    def _fake_pack(pack_id=None):
        return {
            "pack_id": "generic_safety",
            "templates": {
                "HIPAA-ISC-v1": {"max_tokens": 1500},
                "EU-AI-Act-ISC-v1": {"max_tokens": 2000},
                "PCI-DSS-ISC-v1": {"max_tokens": 1200},
            },
            "flags": {
                "STRICT_ISC_ENFORCEMENT": True,
                "CHECKSUM_ENFORCED": True,
                "CRYPTO_ENFORCED": False,
            },
            "structured_request_schema": {
                "schema_id": "account_recovery_challenge_request_v1",
                "required_fields": "invalid-type",
            },
        }

    monkeypatch.setattr(core, "load_domain_pack", _fake_pack)
    out = core.validate_sir({"structured_request": _structured()})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "structured_validation_failed"
    assert out["type"] == "structured_schema_declaration_invalid"


def test_structured_schema_template_fallback_remains_compatible(monkeypatch):
    def _fake_pack(pack_id=None):
        return {
            "pack_id": "generic_safety",
            "templates": {
                "HIPAA-ISC-v1": {"max_tokens": 1500},
                "EU-AI-Act-ISC-v1": {"max_tokens": 2000},
                "PCI-DSS-ISC-v1": {"max_tokens": 1200},
            },
            "flags": {
                "STRICT_ISC_ENFORCEMENT": True,
                "CHECKSUM_ENFORCED": True,
                "CRYPTO_ENFORCED": False,
            },
            "structured_request_schema": {
                "schema_id": "account_recovery_challenge_request_v1",
                "template_id": "",
                "required_fields": [
                    "schema_version",
                    "request_class",
                    "action",
                    "channel",
                    "request_text",
                ],
                "optional_fields": [
                    "declared_auth_state",
                    "case_ref",
                ],
                "schema_version_const": "v1",
                "request_class_const": "account_recovery_challenge",
                "action_enum": [
                    "password_reset",
                    "mfa_reset",
                    "email_change",
                    "phone_change",
                ],
                "channel_enum": [
                    "chat",
                    "email",
                    "support_ticket",
                ],
                "declared_auth_state_enum": [
                    "verified",
                    "unverified",
                    "unknown",
                ],
                "case_ref_pattern": "^[A-Za-z0-9._:-]{1,64}$",
                "request_text_min_length": 1,
                "request_text_max_length": 4000,
            },
        }

    monkeypatch.setattr(core, "load_domain_pack", _fake_pack)
    out = core.validate_sir({"structured_request": _structured()})

    assert out["status"] == "PASS"
    assert out["governance_context"]["isc_template"] == "EU-AI-Act-ISC-v1"
    assert out["governance_context"]["structured_mode"] == "account_recovery_challenge_request_v1"


def test_missing_required_fields_fail_closed():
    payload = _structured()
    payload.pop("action")

    out = core.validate_sir({"structured_request": payload})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "structured_validation_failed"
    assert out["type"] == "structured_missing_required_field"


def test_unknown_fields_fail_closed():
    out = core.validate_sir({"structured_request": _structured(unexpected="x")})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "structured_validation_failed"
    assert out["type"] == "structured_unknown_field"


def test_enum_and_const_mismatch_fail_closed():
    enum_out = core.validate_sir({"structured_request": _structured(action="wire_transfer")})
    const_out = core.validate_sir({"structured_request": _structured(schema_version="v2")})

    assert enum_out["status"] == "BLOCKED"
    assert enum_out["type"] == "structured_action_enum_mismatch"
    assert const_out["status"] == "BLOCKED"
    assert const_out["type"] == "structured_schema_version_mismatch"


def test_nested_object_or_array_stuffing_fails_closed():
    nested_out = core.validate_sir({"structured_request": _structured(channel={"kind": "chat"})})
    array_out = core.validate_sir({"structured_request": _structured(action=["password_reset"])})

    assert nested_out["status"] == "BLOCKED"
    assert nested_out["type"] == "structured_nested_value"
    assert array_out["status"] == "BLOCKED"
    assert array_out["type"] == "structured_nested_value"


def test_oversize_request_text_fails_closed():
    out = core.validate_sir({"structured_request": _structured(request_text="a" * 4001)})

    assert out["status"] == "BLOCKED"
    assert out["type"] == "structured_request_text_length_out_of_bounds"


def test_invalid_case_ref_fails_closed():
    out = core.validate_sir({"structured_request": _structured(case_ref="bad value with spaces")})

    assert out["status"] == "BLOCKED"
    assert out["type"] == "structured_case_ref_pattern_mismatch"


def test_mixed_structured_and_unstructured_fails_closed():
    isc_payload = {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": "safe",
        "checksum": core._compute_checksum("safe"),
        "signature": "",
    }

    out = core.validate_sir({"isc": isc_payload, "structured_request": _structured()})

    assert out["status"] == "BLOCKED"
    assert out["type"] == "structured_mixed_mode_not_allowed"


def test_duplicate_keys_in_structured_json_string_fail_closed():
    raw = (
        '{"schema_version":"v1","request_class":"account_recovery_challenge",'
        '"action":"password_reset","action":"mfa_reset",'
        '"channel":"chat","request_text":"hello"}'
    )

    out = core.validate_sir({"structured_request": raw})

    assert out["status"] == "BLOCKED"
    assert out["type"] == "structured_duplicate_keys"


def test_text_first_path_remains_intact_when_structured_mode_absent():
    payload = "Safe request for audit."
    out = core.validate_sir(
        {
            "isc": {
                "version": "1.0",
                "template_id": "EU-AI-Act-ISC-v1",
                "payload": payload,
                "checksum": core._compute_checksum(payload),
                "signature": "",
            }
        }
    )

    assert out["status"] == "PASS"
    assert out["reason"] == "clean"
