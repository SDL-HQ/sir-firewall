from sir_firewall import core


def _isc(payload: str, template_id: str = "EU-AI-Act-ISC-v1") -> dict:
    return {
        "version": "1.0",
        "template_id": template_id,
        "payload": payload,
        "checksum": core._compute_checksum(payload),
        "signature": "",
    }


def test_tool_result_valid_input_routes_through_isc_path():
    out = core.validate_sir(
        {
            "tool_result": {
                "tool_name": "browser",
                "content": "safe request",
            }
        }
    )

    assert out["status"] == "PASS"
    assert out["governance_context"]["tool_result_mode"] == "tool_result_v1"
    assert any(step.get("component") == "tool_result_validation" and step.get("outcome") == "pass" for step in out["itgl_log"])


def test_tool_result_malformed_input_fails_closed():
    out = core.validate_sir(
        {
            "tool_result": {
                "tool_name": "browser",
                "content": {"nested": "bad"},
            }
        }
    )

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "tool_result_validation_failed"
    assert out["type"] == "tool_result_nested_value"


def test_tool_result_mixed_mode_fails_closed():
    out = core.validate_sir(
        {
            "isc": _isc("safe request"),
            "tool_result": {"tool_name": "browser", "content": "safe request"},
        }
    )

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "tool_result_validation_failed"
    assert out["type"] == "tool_result_mixed_mode_not_allowed"


def test_existing_structured_mixed_mode_code_remains_unchanged():
    out = core.validate_sir(
        {
            "isc": _isc("safe request"),
            "structured_request": {
                "schema_version": "v1",
                "request_class": "account_recovery_challenge",
                "action": "password_reset",
                "channel": "chat",
                "request_text": "safe request",
            },
        }
    )

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "structured_validation_failed"
    assert out["type"] == "structured_mixed_mode_not_allowed"
