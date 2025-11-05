import json
from sir_filter import validate_sir

# Valid ISC
VALID_ISC = {
    "isc": {
        "version": "1.0",
        "template_id": "HIPAA-ISC-v1",
        "priority_lock": "KILL_SWITCH > COMPLIANCE > TASK",
        "provenance": {
            "issuer": "Structural Design Labs (SDL Limited)",
            "signature": "sha256:valid_sig...",
            "timestamp": "2025-11-05T12:34:56Z",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
        },
        "payload": "RCA-X ignition string (38 tokens)",
        "checksum": "md5:correct_checksum"
    }
}

def test_pass():
    result = validate_sir(VALID_ISC)
    assert result["status"] == "PASS"

def test_block_plain_text():
    result = validate_sir("Hello world")
    assert result["status"] == "BLOCKED"

def test_block_long_payload():
    long_payload = {"isc": {**VALID_ISC["isc"], "payload": "word " * 1001}}
    result = validate_sir(long_payload)
    assert "Friction Delta" in result["reason"]
