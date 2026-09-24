import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sir_firewall.cli", "verify", "cert", *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_verify_cert_forwards_explicit_ledger_and_binds():
    result = _run(
        "--ledger", "proofs/itgl_ledger.jsonl", "proofs/latest-audit.json"
    )
    assert result.returncode == 0, result.stderr
    assert "ledger binding verifies" in result.stdout


def test_cli_verify_cert_forwards_explicit_skip():
    result = _run("--no-ledger", "proofs/latest-audit.json")
    assert result.returncode == 0, result.stderr
    assert (
        "NOT VERIFIED: certificate-to-ledger binding was skipped with --no-ledger."
        in result.stderr
    )


def test_cli_verify_cert_reports_not_checked_when_discovery_finds_nothing(tmp_path):
    certificate = tmp_path / "audit.json"
    payload = json.loads((ROOT / "proofs/latest-audit.json").read_text(encoding="utf-8"))
    payload["run_id"] = "run-not-present"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed_bytes = json.dumps(
        {k: v for k, v in payload.items() if k not in ("signature", "payload_hash")},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    payload["payload_hash"] = "sha256:" + hashlib.sha256(signed_bytes).hexdigest()
    payload["signature"] = base64.b64encode(
        key.sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    certificate.write_text(json.dumps(payload), encoding="utf-8")
    pubkey = tmp_path / "public.pem"
    pubkey.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    result = _run(
        "--key", str(pubkey), "--key-registry", str(tmp_path / "absent.json"),
        str(certificate),
    )
    assert result.returncode == 9
    assert "NOT CHECKED: certificate-to-ledger binding was not checked" in result.stderr


def test_cli_verify_cert_binding_modes_are_mutually_exclusive():
    result = _run(
        "--ledger", "proofs/itgl_ledger.jsonl", "--no-ledger",
        "proofs/latest-audit.json",
    )
    assert result.returncode == 2
    assert "not allowed with argument --ledger" in result.stderr
