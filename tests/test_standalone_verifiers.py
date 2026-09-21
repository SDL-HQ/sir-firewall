import os
import shutil
import subprocess
import sys
from pathlib import Path

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
    (tmp_path / "proofs").mkdir()
    shutil.copy2(ROOT / f"proofs/runs/{RUN_ID}/audit.json", tmp_path / "proofs/audit.json")
    shutil.copy2(
        ROOT / canonical_ledger_path(RUN_ID),
        tmp_path / "proofs/itgl_ledger.jsonl",
    )
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    chain = subprocess.run(
        [sys.executable, "tools/verify_itgl.py"], cwd=tmp_path, env=env,
        capture_output=True, text=True,
    )
    assert chain.returncode == 0, chain.stderr
    bound = subprocess.run([
        sys.executable, "tools/verify_certificate.py", "proofs/audit.json",
        "--ledger", "proofs/itgl_ledger.jsonl",
    ], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert bound.returncode == 0, bound.stderr
