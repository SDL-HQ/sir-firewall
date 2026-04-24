import json
import shutil
import subprocess
import sys
from pathlib import Path


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _make_minimal_repo(root: Path, *, malformed_latest_run: bool = False, omit_latest_run: bool = False) -> None:
    script_src = Path(__file__).resolve().parents[1] / "tools" / "export_review_bundle.py"
    script_dst = root / "tools" / "export_review_bundle.py"
    script_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(script_src, script_dst)

    text_files = (
        "README.md",
        "RETENTION.md",
        "docs/assurance-kit.md",
        "docs/evaluator-technical-explainer.md",
        "docs/external-technical-review-prep.md",
        "docs/benchmark-cycle.v1.md",
        "docs/d5-benchmark-first-cycle-review.md",
        "docs/compliance-evidence-map.md",
        "proofs/latest-audit.html",
        "proofs/runs/index.html",
        "spec/evidence_contract.v1.json",
        "tools/verify_certificate.py",
        "tools/verify_archive_receipt.py",
        "tools/verify_itgl.py",
    )
    for rel in text_files:
        _write(root / rel, "x\n")

    _write(
        root / "proofs/latest-audit.json",
        json.dumps(
            {
                "result": "AUDIT PASSED",
                "proof_class": "FIREWALL_ONLY_AUDIT",
                "date": "2026-04-24T00:00:00Z",
                "timestamp_utc": "2026-04-24T00:00:00Z",
                "suite_name": "generic_safety",
                "suite_path": "tests/domain_packs/generic_safety.csv",
                "model": "none",
                "provider": "none",
                "jailbreaks_leaked": 0,
                "harmless_blocked": 0,
                "commit_sha": "abc123",
                "payload_hash": "sha256:1",
                "trust_fingerprint": "sha256:2",
            }
        )
        + "\n",
    )
    _write(
        root / "proofs/runs/index.json",
        json.dumps({"runs": []}) + "\n",
    )
    if not omit_latest_run:
        latest_run_content = "{bad json\n" if malformed_latest_run else json.dumps(
            {
                "status": "PASS",
                "timestamp_utc": "2026-04-24T00:00:00Z",
                "run_id": "run-1",
                "sha": "abc123",
                "source": "ci",
            }
        )
        _write(root / "docs/latest-run.json", latest_run_content + "\n")


def test_export_review_bundle_rejects_non_directory_out_path(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    out_path = tmp_path / "not_a_dir"
    out_path.write_text("x", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "tools/export_review_bundle.py", "--out", str(out_path)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )

    assert proc.returncode != 0
    assert "ERROR: --out must be a directory path" in (proc.stderr + proc.stdout)


def test_export_review_bundle_writes_human_audit_report(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    out_path = tmp_path / "bundle"

    proc = subprocess.run(
        [sys.executable, "tools/export_review_bundle.py", "--out", str(out_path)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    report = (out_path / "HUMAN_AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "## Latest passing proof" in report
    assert "## Latest run status" in report
    assert "proofs/latest-audit.json" in report
    assert "docs/latest-run.json" in report
    assert "These are distinct surfaces and can differ." in report
    assert "Source artefacts remain authoritative." in report


def test_export_review_bundle_fails_if_required_source_json_missing(tmp_path):
    repo_root = tmp_path / "repo"
    _make_minimal_repo(repo_root, omit_latest_run=True)
    out_path = tmp_path / "bundle"

    proc = subprocess.run(
        [sys.executable, "tools/export_review_bundle.py", "--out", str(out_path)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )

    assert proc.returncode != 0
    assert "ERROR: missing required file: docs/latest-run.json" in (proc.stderr + proc.stdout)


def test_export_review_bundle_fails_if_required_source_json_malformed(tmp_path):
    repo_root = tmp_path / "repo"
    _make_minimal_repo(repo_root, malformed_latest_run=True)
    out_path = tmp_path / "bundle"

    proc = subprocess.run(
        [sys.executable, "tools/export_review_bundle.py", "--out", str(out_path)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )

    assert proc.returncode != 0
    assert "ERROR: malformed JSON:" in (proc.stderr + proc.stdout)
    assert "docs/latest-run.json" in (proc.stderr + proc.stdout)
