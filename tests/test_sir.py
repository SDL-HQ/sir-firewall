import json
import pytest
from sir_firewall.sir_firewall import validate_sir


@pytest.fixture
def valid_isc():
    return {
        "isc": {
            "version": "1.0",
            "template_id": "HIPAA-ISC-v1",
            "priority_lock": "HARD",
            "provenance": {
                "issuer": "Structural Design Labs (SDL Limited)",
                "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8xEin2TR4b8jL\nzF0b6Y8iK8QIDAQAB\n-----END PUBLIC KEY-----",
                "signature": "rsa-sha256:MEUCIQCli0lY8bP7l6L2x8P7j4v1g1p2h3j4k5l6m7n8o9p0qA=="
            },
            "payload": "Protect PHI.",
            "checksum": "sha256:1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"
        }
    }


def test_valid_passes(valid_isc):
    res = validate_sir(valid_isc)
    assert res["status"] == "PASS"
    assert "key_fingerprint" in res["itgl_log"]


def test_flip_priority_lock_blocks(valid_isc):
    valid_isc["isc"]["priority_lock"] = "SOFT"
    res = validate_sir(valid_isc)
    assert res["status"] == "BLOCKED"
