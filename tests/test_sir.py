import json
import pytest
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from sir_firewall.sir_firewall import validate_sir


@pytest.fixture
def valid_isc():
    # Generate real key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Payload
    payload = "Protect PHI."
    version = "1.0"
    template_id = "HIPAA-ISC-v1"
    priority_lock = "HARD"
    checksum = f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"

    # Build envelope
    envelope_parts = [
        version,
        template_id,
        checksum,
        payload,
        json.dumps(priority_lock, separators=(",", ":"), sort_keys=True)
    ]
    envelope = "|".join(envelope_parts).encode()

    # Sign
    signature = private_key.sign(
        envelope,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(signature).decode()

    # PEM
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return {
        "isc": {
            "version": version,
            "template_id": template_id,
            "priority_lock": priority_lock,
            "provenance": {
                "issuer": "Structural Design Labs (SDL Limited)",
                "public_key": pem,
                "signature": f"rsa-sha256:{sig_b64}"
            },
            "payload": payload,
            "checksum": checksum
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
