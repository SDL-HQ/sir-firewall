import importlib.util
import json
from pathlib import Path


def _load_publish_run_module():
    module_path = Path(__file__).resolve().parents[1] / "tools" / "publish_run.py"
    spec = importlib.util.spec_from_file_location("publish_run", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_benchmark_index_keeps_latest_run_and_latest_passing_run(tmp_path):
    publish_run = _load_publish_run_module()

    runs_dir = tmp_path / "runs"
    failing_run = runs_dir / "run-fail"
    passing_run = runs_dir / "run-pass"
    failing_run.mkdir(parents=True)
    passing_run.mkdir(parents=True)

    (failing_run / "audit.json").write_text(
        json.dumps(
            {
                "result": "AUDIT FAILED",
                "proof_class": "FIREWALL_ONLY_AUDIT",
                "pack_id": "generic_safety",
                "pack_version": "1.0.0",
                "provider_call_attempts": 0,
            }
        ),
        encoding="utf-8",
    )
    (passing_run / "audit.json").write_text(
        json.dumps(
            {
                "result": "AUDIT PASSED",
                "proof_class": "LIVE_GATING_CHECK",
                "pack_id": "generic_safety",
                "pack_version": "1.0.0",
                "provider_call_attempts": 2,
            }
        ),
        encoding="utf-8",
    )

    inconclusive_run = runs_dir / "run-inconclusive"
    inconclusive_run.mkdir(parents=True)
    (inconclusive_run / "audit.json").write_text(
        json.dumps(
            {
                "result": "INCONCLUSIVE",
                "proof_class": "LIVE_GATING_CHECK",
                "pack_id": "generic_safety",
                "pack_version": "1.0.0",
                "provider_call_attempts": 1,
            }
        ),
        encoding="utf-8",
    )

    runs = [
        {"run_id": "run-fail", "path": "runs/run-fail/", "result": "AUDIT FAILED"},
        {"run_id": "run-inconclusive", "path": "runs/run-inconclusive/", "result": "INCONCLUSIVE"},
        {"run_id": "run-pass", "path": "runs/run-pass/", "result": "AUDIT PASSED"},
    ]
    index = publish_run._build_benchmark_index(runs_dir=runs_dir, runs=runs)

    assert index["version"] == "benchmark_index.v1"
    assert index["latest_run"]["run_id"] == "run-fail"
    assert index["latest_passing_run"]["run_id"] == "run-pass"
    assert [entry["result"] for entry in index["entries"]] == ["AUDIT FAILED", "INCONCLUSIVE", "AUDIT PASSED"]
    assert index["entries"][0]["proof_class"] == "FIREWALL_ONLY_AUDIT"
    assert index["entries"][0]["evidence"]["audit"] == "runs/run-fail/audit.json"
    assert index["entries"][1]["evidence"]["audit"] == "runs/run-inconclusive/audit.json"


def test_is_passing_result_only_accepts_canonical_pass_value():
    publish_run = _load_publish_run_module()

    assert publish_run._is_passing_result("AUDIT PASSED")
    assert publish_run._is_passing_result("  audit passed  ")
    assert not publish_run._is_passing_result("BYPASS")
    assert not publish_run._is_passing_result("AUDIT FAILED")


def test_benchmark_entry_marks_invalid_archived_audit_json(tmp_path, capsys):
    publish_run = _load_publish_run_module()

    runs_dir = tmp_path / "runs"
    run_dir = runs_dir / "run-bad-audit"
    run_dir.mkdir(parents=True)
    (run_dir / "audit.json").write_text("{not-json", encoding="utf-8")

    entry = publish_run._benchmark_entry_from_run(
        runs_dir=runs_dir,
        run={"run_id": "run-bad-audit", "path": "runs/run-bad-audit/"},
    )

    captured = capsys.readouterr()
    assert "WARN: invalid JSON" in captured.err
    assert "evidence_error" in entry
    assert "invalid JSON" in entry["evidence_error"]
