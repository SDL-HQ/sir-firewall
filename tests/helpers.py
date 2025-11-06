# tests/helpers.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json, hashlib, base64

def _gen_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    return priv_pem, pub_pem

def make_valid_isc(
    payload: str = "Protect PHI.",
    version: str = "1.0.2",
    template_id: str = "HIPAA-ISC-v1",
    priority_lock = {"mode": "HARD"},
):
    # keys
    priv_pem, pub_pem = _gen_rsa_keypair()
    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)

    # checksum over payload
    checksum = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

    # envelope (must match validator order/format)
    envelope_parts = [
        str(version),
        template_id,
        checksum,
        payload,
        json.dumps(priority_lock, separators=(",", ":"), sort_keys=True),
    ]
    envelope = "|".join(envelope_parts).encode()

    # RSA-PKCS1v15-SHA256 signature
    sig_bytes = private_key.sign(envelope, padding.PKCS1v15(), hashes.SHA256())
    signature = "rsa-sha256:" + base64.b64encode(sig_bytes).decode()

    isc = {
        "version": version,
        "template_id": template_id,
        "priority_lock": priority_lock,
        "provenance": {
            "issuer": "Structural Design Labs (SDL Limited)",
            "public_key": pub_pem,
            "signature": signature,
        },
        "payload": payload,
        "checksum": checksum,
    }
    return {"isc": isc}
