import os
import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sir_firewall.evidence_paths import canonical_ledger_path

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "20260805-082453-000000-gh30988883180-c8b702d636fb"


def test_verifiers_run_from_minimal_bundle_without_package_install(tmp_path):
    for relative in (
        "tools/verify_itgl.py", "tools/verify_certificate.py", "tools/itgl.py",
        "tools/key_registry.py", "spec/sdl.pub", "spec/pubkeys/key_registry.v1.json",
        "spec/pubkeys/key_registry.v1.schema.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    archive = tmp_path / "docs/runs" / RUN_ID
    (archive / "proofs").mkdir(parents=True)
    shutil.copy2(
        ROOT / canonical_ledger_path(RUN_ID),
        archive / "proofs/itgl_ledger.jsonl",
    )
    ledger_rows = [
        json.loads(line)
        for line in (archive / "proofs/itgl_ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ledger_hash, row_count = "sha256:" + ledger_rows[-1]["ledger_hash"], len(ledger_rows)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = {
        "sir_firewall_version": "2.3.4",
        "run_id": RUN_ID,
        "itgl_final_hash": ledger_hash,
        "itgl_row_count": row_count,
        "prompts_tested": row_count,
        "detached_ledger": False,
    }
    payload = json.dumps(certificate, separators=(",", ":")).encode()
    certificate["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    certificate["signature"] = base64.b64encode(
        key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    (archive / "audit.json").write_text(json.dumps(certificate), encoding="utf-8")
    (tmp_path / "spec/sdl.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    chain = subprocess.run(
        [sys.executable, "tools/verify_itgl.py", "--ledger", f"docs/runs/{RUN_ID}/proofs/itgl_ledger.jsonl"], cwd=tmp_path, env=env,
        capture_output=True, text=True,
    )
    assert chain.returncode == 0, chain.stderr
    bound = subprocess.run([
        sys.executable, "tools/verify_certificate.py", f"docs/runs/{RUN_ID}/audit.json",
        "--ledger", f"docs/runs/{RUN_ID}/proofs/itgl_ledger.jsonl",
    ], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert bound.returncode == 0, bound.stderr
