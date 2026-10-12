import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "spec" / "canonical_example_run.json"
VERIFIER_OUTPUT_DOCS = (
    ROOT / "docs/evaluator-technical-explainer.md",
    ROOT / "docs/minimal-pilot-runbook.md",
    ROOT / "docs/assurance-kit.md",
)


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


def test_canonical_verifier_stdout_matches_documented_output():
    run_id = json.loads(SPEC_PATH.read_text(encoding="utf-8"))["run_id"]
    audit = Path("docs/runs") / run_id / "audit.json"
    ledger = Path("docs/runs") / run_id / "proofs/itgl_ledger.jsonl"
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
    assert result.returncode == 0, result.stderr
    verifier_line = result.stdout.strip()

    for document in VERIFIER_OUTPUT_DOCS:
        text = document.read_text(encoding="utf-8")
        assert f"```text\n{verifier_line}\n" in text, document


def test_the_documented_consolidated_output_is_the_actual_output():
    """The assurance kit's worked example is the procedure a reader follows.

    docs/assurance-kit.md documents tools/verify_evidence.py as the evaluator
    procedure and shows its output. A documented output that has drifted from
    the real one is worse than none, because a reader compares what they see
    against it and concludes their copy is wrong. This pins the whole block,
    including the UNKNOWN lines and the verdict, which are the part a reader is
    most likely to think is a problem with their download.
    """
    run_id = json.loads(SPEC_PATH.read_text(encoding="utf-8"))["run_id"]
    result = subprocess.run(
        [sys.executable, "tools/verify_evidence.py", f"docs/runs/{run_id}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1, (
        "the canonical example is expected to report NOT ESTABLISHED, because its "
        "ledger predates the fields needed to recompute the signed counters; if this "
        "changes, the documented output and the prose explaining it change with it"
        f"{chr(10)}{result.stdout}{chr(10)}{result.stderr}"
    )
    kit = (ROOT / "docs/assurance-kit.md").read_text(encoding="utf-8")
    assert f"```text\n{result.stdout.strip()}\n```" in kit


def test_the_kit_explains_every_unknown_it_shows():
    """A reader must not have to guess why a property is unknown.

    Each UNKNOWN in the documented output names a property; the kit must discuss
    that property by name, so the reader is told whether it is expected.
    """
    run_id = json.loads(SPEC_PATH.read_text(encoding="utf-8"))["run_id"]
    result = subprocess.run(
        [sys.executable, "tools/verify_evidence.py", f"docs/runs/{run_id}", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(result.stdout)
    unknown = [
        entry["property"] for entry in report["properties"] if entry["state"] == "unknown"
    ]

    assert unknown, "this test assumes the canonical example has at least one unknown"
    kit = (ROOT / "docs/assurance-kit.md").read_text(encoding="utf-8")
    for name in unknown:
        assert f"**`{name}`**" in kit, (
            f"the documented output shows {name!r} as unknown and the kit does not "
            "explain it"
        )
