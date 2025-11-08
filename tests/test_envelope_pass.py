import json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from sir_firewall import validate_sir  # proves public API export

def _canon(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)

def test_validate_sir_pass():
    # 1) Generate a temporary RSA keypair (2048 bits meets your requirement)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # 2) Build payload as a STRING (your validator expects a string)
    payload_obj = {"purpose": "clinical_triage_assist", "inputs": {"prompt": "hello"}}
    payload_str = _canon(payload_obj)

    # 3) Fill envelope fields
    version = "ISC-1.0"
    template_id = "HIPAA-ISC-v1"
    priority_lock = {"order": ["KILL", "COMP", "TASK", "FLUENCY"]}
    checksum = f"sha256:{hashlib.sha256(payload_str.encode()).hexdigest()}"

    # 4) Create the exact envelope you sign (matches sir_firewall.py)
    envelope_parts = [
        str(version),
        template_id,
        checksum,
        payload_str,
        _canon(priority_lock),
    ]
    envelope = "|".join(envelope_parts).encode()

    signature = private_key.sign(envelope, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = "base64:" + base64.b64encode(signature).decode()

    data = {
        "isc": {
            "version": version,
            "template_id": template_id,
            "priority_lock": priority_lock,
            "provenance": {
                "issuer": "Structural Design Labs (SDL Limited)",
                "public_key": public_pem,
                "signature": sig_b64,
            },
            "payload": payload_str,
            "checksum": checksum,
        }
    }

    res = validate_sir(data)
    assert res["status"] == "PASS", res
    assert res["itgl_log"]["template_id"] == template_id
    assert res["itgl_log"]["issuer"] == "Structural Design Labs (SDL Limited)"
