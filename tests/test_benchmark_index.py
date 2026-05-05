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
    index = publish_run._build_benchmark_index_v1(runs_dir=runs_dir, runs=runs)

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


def test_benchmark_index_skips_malformed_run_ids(tmp_path, capsys):
    publish_run = _load_publish_run_module()

    runs_dir = tmp_path / "runs"
    good_run = runs_dir / "run-good"
    good_run.mkdir(parents=True)
    (good_run / "audit.json").write_text(json.dumps({"result": "AUDIT PASSED"}), encoding="utf-8")

    index = publish_run._build_benchmark_index_v1(
        runs_dir=runs_dir,
        runs=[
            {"run_id": "", "path": "runs//", "result": "AUDIT FAILED"},
            {"run_id": "../escape", "path": "runs/../escape/", "result": "AUDIT FAILED"},
            {"run_id": "run-good", "path": "runs/run-good/", "result": "AUDIT PASSED"},
        ],
    )

    captured = capsys.readouterr()
    assert "WARN: skipping malformed run index entry" in captured.err
    assert [entry["run_id"] for entry in index["entries"]] == ["run-good"]
    assert index["latest_run"]["run_id"] == "run-good"


def test_benchmark_entry_prefers_effective_pack_id_from_audit(tmp_path):
    publish_run = _load_publish_run_module()

    runs_dir = tmp_path / "runs"
    run_dir = runs_dir / "run-effective-pack"
    run_dir.mkdir(parents=True)
    (run_dir / "audit.json").write_text(
        json.dumps(
            {
                "result": "AUDIT PASSED",
                "proof_class": "FIREWALL_ONLY_AUDIT",
                "pack_id": "selected_pack_placeholder",
                "selected_pack_id": "selected_pack_placeholder",
                "effective_pack_id": "generic_safety",
                "selected_pack_version": "1.2.3",
            }
        ),
        encoding="utf-8",
    )

    entry = publish_run._benchmark_entry_from_run(
        runs_dir=runs_dir,
        run={"run_id": "run-effective-pack", "path": "runs/run-effective-pack/"},
    )

    assert entry["evaluation_target"]["pack_id"] == "generic_safety"
    assert entry["evaluation_target"]["pack_version"] == "1.2.3"


def test_benchmark_entry_adds_downstream_evidence_link_only_when_artifact_present(tmp_path):
    publish_run = _load_publish_run_module()

    runs_dir = tmp_path / "runs"
    run_id = "run-live"
    run_dir = runs_dir / run_id
    (run_dir / "proofs").mkdir(parents=True)
    (run_dir / "audit.json").write_text(
        json.dumps(
            {
                "result": "AUDIT PASSED",
                "proof_class": "LIVE_GATING_CHECK",
                "pack_id": "generic_safety",
                "pack_version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )

    no_sidecar_entry = publish_run._benchmark_entry_from_run(
        runs_dir=runs_dir,
        run={"run_id": run_id, "path": f"runs/{run_id}/"},
    )
    assert "downstream_evidence" not in no_sidecar_entry["evidence"]

    (run_dir / "proofs" / "downstream_evidence.jsonl").write_text("{}", encoding="utf-8")
    with_sidecar_entry = publish_run._benchmark_entry_from_run(
        runs_dir=runs_dir,
        run={"run_id": run_id, "path": f"runs/{run_id}/"},
    )
    assert with_sidecar_entry["evidence"]["downstream_evidence"] == f"runs/{run_id}/proofs/downstream_evidence.jsonl"


def test_copy_optional_artifacts_includes_downstream_sidecar_in_manifest(tmp_path):
    publish_run = _load_publish_run_module()

    repo_root = tmp_path / "repo"
    run_dir = tmp_path / "archive" / "run-1"
    (repo_root / "proofs").mkdir(parents=True)
    run_dir.mkdir(parents=True)
    (repo_root / "proofs" / "downstream_evidence.jsonl").write_text('{"ok":true}\n', encoding="utf-8")

    copied = publish_run._copy_optional_artifacts(
        repo_root=repo_root,
        run_dir=run_dir,
        extra_paths=["proofs/downstream_evidence.jsonl"],
    )
    assert copied == ["proofs/downstream_evidence.jsonl"]

    manifest = publish_run._build_manifest(
        run_dir=run_dir,
        run_id="run-1",
        cert={"repository": "SDL-HQ/sir-firewall", "commit_sha": "abc"},
    )
    manifest_paths = {entry["path"] for entry in manifest["files"]}
    assert "proofs/downstream_evidence.jsonl" in manifest_paths


def test_benchmark_index_v2_loads_pair_artifact_and_computes_deltas(tmp_path):
    publish_run = _load_publish_run_module()

    runs_dir = tmp_path / "runs"
    baseline_run = runs_dir / "run-baseline"
    gated_run = runs_dir / "run-gated"
    pairs_dir = runs_dir / "pairs"
    baseline_run.mkdir(parents=True)
    gated_run.mkdir(parents=True)
    pairs_dir.mkdir(parents=True)

    (baseline_run / "audit.json").write_text(
        json.dumps(
            {
                "model": "xai/grok-3-beta",
                "provider": "xai",
                "effective_pack_id": "generic_safety",
                "pack_version": "1.0.0",
                "suite_hash": "sha256:abc",
                "commit_sha": "deadbeef",
                "jailbreaks_leaked": 10,
                "harmless_blocked": 1,
                "provider_call_attempts": 0,
                "provider_call_successes": 0,
                "provider_call_failures": 0,
                "benchmark_execution": {"benchmark_role": "baseline", "gate_mode": "ungated"},
            }
        ),
        encoding="utf-8",
    )
    (gated_run / "audit.json").write_text(
        json.dumps(
            {
                "model": "xai/grok-3-beta",
                "provider": "xai",
                "effective_pack_id": "generic_safety",
                "pack_version": "1.0.0",
                "suite_hash": "sha256:abc",
                "commit_sha": "deadbeef",
                "jailbreaks_leaked": 0,
                "harmless_blocked": 2,
                "provider_call_attempts": 0,
                "provider_call_successes": 0,
                "provider_call_failures": 1,
                "benchmark_execution": {"benchmark_role": "gated", "gate_mode": "sir_gated"},
            }
        ),
        encoding="utf-8",
    )
    (pairs_dir / "pair-1.json").write_text(
        json.dumps(
            {
                "pair_id": "pair-1",
                "pair_key": "k1",
                "pair_status": "valid_complete",
                "baseline_run_id": "run-baseline",
                "gated_run_id": "run-gated",
            }
        ),
        encoding="utf-8",
    )

    index_v2 = publish_run._build_benchmark_index_v2(
        runs_dir=runs_dir,
        runs=[
            {"run_id": "run-gated", "path": "runs/run-gated/", "result": "AUDIT PASSED"},
            {"run_id": "run-baseline", "path": "runs/run-baseline/", "result": "AUDIT FAILED"},
        ],
        pairs_dir=pairs_dir,
    )

    assert index_v2["version"] == "benchmark_index.v2"
    assert len(index_v2["pairs"]) == 1
    pair = index_v2["pairs"][0]
    assert pair["pair_status"] == "valid_complete"
    assert pair["baseline_provider_complete"] is True
    assert pair["gated_provider_complete"] is False
    assert pair["pair_provider_status"] == "incomplete"
    assert pair["deltas"]["leaks_delta"] == -10
    assert pair["deltas"]["harmless_blocked_delta"] == 1
    assert pair["deltas"]["provider_call_successes_delta"] == 0
    assert pair["deltas"]["provider_call_failures_delta"] == 1
