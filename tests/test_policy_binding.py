import json
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_policy_test", ROOT / "tools/verify_policy.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_repository_signed_policy_matches_enforced_policy():
    result = subprocess.run(
        [sys.executable, "tools/verify_policy.py"], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "exactly matches the enforced policy" in result.stdout


def test_policy_verifier_rejects_runtime_drift(tmp_path):
    signed = json.loads((ROOT / "policy/isc_policy.signed.json").read_text())
    signed_path = tmp_path / "signed.json"
    signed_path.write_text(json.dumps(signed))
    enforced = signed["payload"]
    enforced["version"] = "drifted"
    enforced_path = tmp_path / "enforced.json"
    enforced_path.write_text(json.dumps(enforced))
    ok, detail = MODULE.verify_policy(signed_path, enforced_path, ROOT / "spec/sdl.pub")
    assert not ok
    assert "differs" in detail
