import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "spec" / "canonical_example_run.json"


def _is_json_file(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return True


def test_canonical_example_run_remains_verifiable_offline():
    canonical_run_spec = None
    spec_error = None
    try:
        canonical_run_spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        spec_error = exc

    assert isinstance(canonical_run_spec, dict) and isinstance(
        canonical_run_spec.get("run_id"), str
    ), (
        "The canonical example run spec must exist and contain a run_id because the "
        f"public site's verification command depends on it; error: {spec_error}"
    )

    run_id = canonical_run_spec["run_id"]
    dependency_message = (
        f"Run {run_id} must remain available because the public site's verification command depends on it"
    )

    for tree_name, runs_dir in (
        ("authoritative proofs/runs tree", Path("proofs/runs")),
        ("published docs/runs mirror", Path("docs/runs")),
    ):
        run_dir = runs_dir / run_id
        audit = run_dir / "audit.json"
        ledger = run_dir / "proofs" / "itgl_ledger.jsonl"

        assert _is_json_file(ROOT / audit), (
            f"{dependency_message}; {tree_name} audit.json must exist and contain valid JSON"
        )
        assert (ROOT / ledger).is_file() and (ROOT / ledger).stat().st_size > 0, (
            f"{dependency_message}; {tree_name} ledger must exist and be non-empty"
        )

        result = subprocess.run(
            [
                sys.executable,
                "tools/verify_certificate.py",
                str(audit),
                "--ledger",
                str(ledger),
                "--require-registry",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"{dependency_message}; verification against the {tree_name} exited "
            f"{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
