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
