import json
from sir_firewall import validate_sir

def test_validate_sir_blocks_bad_checksum():
    # Minimal malformed envelope: checksum does NOT match payload (fails at step 4)
    payload_str = json.dumps({"purpose": "x"}, separators=(",", ":"), sort_keys=True)

    bad = {
        "isc": {
            "version": "ISC-1.0",
            "template_id": "HIPAA-ISC-v1",
            "priority_lock": {"order": ["KILL", "COMP", "TASK", "FLUENCY"]},
            "provenance": {
                "issuer": "Structural Design Labs (SDL Limited)",
                # Bogus public key/signature are fine; checksum fails first.
                "public_key": "-----BEGIN PUBLIC KEY-----\nMIIB...fake...\n-----END PUBLIC KEY-----",
                "signature": "base64:deadbeef",
            },
            "payload": payload_str,
            "checksum": "sha256:not-the-right-hash",
        }
    }

    res = validate_sir(bad)
    assert res["status"] == "BLOCKED"
    assert "checksum" in res["reason"].lower()
