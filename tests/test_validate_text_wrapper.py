from sir_firewall import core


def _isc(payload: str, template_id: str = "EU-AI-Act-ISC-v1") -> dict:
    return {
        "version": "1.0",
        "template_id": template_id,
        "payload": payload,
        "checksum": core._compute_checksum(payload),
        "signature": "",
    }


def test_validate_text_delegates_with_matching_output(monkeypatch):
    payload = "Please provide account recovery guidance."
    monkeypatch.setattr(core.time, "time", lambda: 1700000000.0)

    via_wrapper = core.validate_text(
        payload,
        template_id="EU-AI-Act-ISC-v1",
        enforcement_pack_id="generic_safety",
        pack_identity_context={"pack_version": "v1", "pack_hash": "sha256:test"},
    )
    direct = core.validate_sir(
        {"isc": _isc(payload, template_id="EU-AI-Act-ISC-v1")},
        enforcement_pack_id="generic_safety",
        pack_identity_context={"pack_version": "v1", "pack_hash": "sha256:test"},
    )

    assert via_wrapper == direct


def test_validate_sir_direct_isc_path_remains_unchanged():
    payload = "safe request"
    out = core.validate_sir({"isc": _isc(payload)})

    assert out["status"] == "PASS"
