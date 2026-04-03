import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sir_firewall import core


def _keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def _mk_isc(private_key=None, payload="Safe request for a summary report."):
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    signature = ""
    if private_key is not None:
        sig = private_key.sign(payload.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        signature = base64.b64encode(sig).decode("ascii")
    return {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": payload,
        "checksum": checksum,
        "signature": signature,
        "key_id": "default",
    }


def _enforce_crypto(monkeypatch, pub_pem):
    monkeypatch.setattr(
        core,
        "load_domain_pack",
        lambda pack_id=None: {
            "pack_id": "generic_safety",
            "templates": {"EU-AI-Act-ISC-v1": {"max_tokens": 2000}},
            "flags": {"STRICT_ISC_ENFORCEMENT": True, "CHECKSUM_ENFORCED": True, "CRYPTO_ENFORCED": True},
        },
    )
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": pub_pem})


def test_crypto_enforced_blocks_invalid_signature(monkeypatch):
    priv, pub = _keypair()
    _enforce_crypto(monkeypatch, pub)
    isc = _mk_isc(priv)
    isc["signature"] = base64.b64encode(b"not-a-real-signature").decode("ascii")
    out = core.validate_sir({"isc": isc})
    assert out["status"] == "BLOCKED"
    assert out["reason"] == "invalid_signature_or_checksum"


def test_crypto_enforced_blocks_missing_signature(monkeypatch):
    _, pub = _keypair()
    _enforce_crypto(monkeypatch, pub)
    isc = _mk_isc(private_key=None)
    out = core.validate_sir({"isc": isc})
    assert out["status"] == "BLOCKED"
    assert out["reason"] == "invalid_signature_or_checksum"


def test_crypto_enforced_passes_valid_signature(monkeypatch):
    priv, pub = _keypair()
    _enforce_crypto(monkeypatch, pub)
    isc = _mk_isc(priv)
    out = core.validate_sir({"isc": isc})
    assert out["status"] == "PASS"


def test_sign_isc_cli_envelope_is_validate_sir_compatible(tmp_path, monkeypatch):
    priv, pub = _keypair()
    _enforce_crypto(monkeypatch, pub)

    private_key_path = tmp_path / "private.pem"
    private_key_path.write_text(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        encoding="utf-8",
    )

    input_path = tmp_path / "isc.json"
    output_path = tmp_path / "isc.signed.json"
    input_path.write_text(
        json.dumps(
            {
                "isc": {
                    "version": "1.0",
                    "template_id": "EU-AI-Act-ISC-v1",
                    "payload": "Summarize this compliant policy statement.",
                    "checksum": "",
                    "signature": "",
                }
            }
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            sys.executable,
            "tools/sign_isc.py",
            "--in",
            str(input_path),
            "--out",
            str(output_path),
            "--private-key-file",
            str(private_key_path),
            "--key-id",
            "default",
        ],
        check=True,
    )
    signed = json.loads(output_path.read_text(encoding="utf-8"))
    out = core.validate_sir(signed)
    assert out["status"] == "PASS"
