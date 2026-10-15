#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import sys
from pathlib import Path as _Path

# Run directly from a clone without an editable install. The four verifiers in
# this directory already do this; a tool that only works once the package is
# installed makes a test's outcome depend on the ambient environment, which is
# how test_rule_coverage_report came to pass or fail according to whether
# PYTHONPATH happened to be set. tests/test_tools_run_from_a_clone.py holds the
# property for every tool here that imports sir_firewall.
_REPO_ROOT = _Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_Path(__file__).resolve().parent))

from pair_validation import validate_pair
from sir_firewall.model_selection import DEFAULT_MODEL, DEFAULT_PROVIDER, validate_execution_selection

ROOT = Path(__file__).resolve().parents[1]


def _utc_now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_checked(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return proc


def _parse_generated_document_path(stdout: str, *, key: str) -> str:
    """The path a generator reports, by the key it reports it under.

    Two generators now: the certificate's prints OUTPUT_AUDIT_JSON and the
    baseline record's prints OUTPUT_BASELINE_JSON. Keyed rather than positional
    so one half cannot pick up the other half's document.
    """
    for line in stdout.splitlines():
        if line.startswith(f"{key}="):
            out = line.split("=", 1)[1].strip()
            if out:
                return out
    raise SystemExit(f"ERROR: generator output missing {key}")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_benchmark_indexes() -> None:
    """Rebuild both benchmark indexes after a pair is written.

    v2 is built from the v1 entries, which come from the run index and are
    therefore gate runs only. v3 is built from the archive directories, which
    is the only way it can see a baseline record: the record has no result, so
    it is not a row in the run index at all.
    """
    runs_dir = ROOT / "proofs" / "runs"
    benchmark_v1_path = runs_dir / "benchmark_index.v1.json"
    benchmark_v2_path = runs_dir / "benchmark_index.v2.json"
    benchmark_v3_path = runs_dir / "benchmark_index.v3.json"
    docs_runs_dir = ROOT / "docs" / "runs"

    if not benchmark_v1_path.exists():
        raise SystemExit(f"ERROR: missing benchmark index v1 required for the refresh: {benchmark_v1_path}")

    spec = importlib.util.spec_from_file_location("publish_run_module", ROOT / "tools" / "publish_run.py")
    if spec is None or spec.loader is None:
        raise SystemExit("ERROR: unable to load tools/publish_run.py for the index refresh")
    publish_run_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publish_run_module)

    v1_payload = _read_json(benchmark_v1_path)
    runs = v1_payload.get("entries")
    if not isinstance(runs, list):
        raise SystemExit("ERROR: benchmark_index.v1.json has invalid entries payload")

    benchmark_index_v2 = publish_run_module._build_benchmark_index_v2(
        runs_dir=runs_dir,
        runs=runs,
        pairs_dir=(runs_dir / "pairs"),
    )
    _write_json(benchmark_v2_path, benchmark_index_v2)
    _write_json(docs_runs_dir / "benchmark_index.v2.json", benchmark_index_v2)

    benchmark_index_v3 = publish_run_module._build_benchmark_index_v3(
        runs_dir=runs_dir,
        pairs_dir=(runs_dir / "pairs"),
    )
    _write_json(benchmark_v3_path, benchmark_index_v3)
    _write_json(docs_runs_dir / "benchmark_index.v3.json", benchmark_index_v3)


def _run_single(
    *,
    mode: str,
    pack: Optional[str],
    suite: Optional[str],
    scenario: Optional[str],
    provider: str,
    model: str,
    template: Optional[str],
    no_model_calls: bool,
    ungated_baseline: bool,
) -> tuple[str, Dict[str, Any]]:
    suite_cmd = [sys.executable, str(ROOT / "red_team_suite.py"), "--mode", mode]
    if pack:
        suite_cmd.extend(["--pack", pack])
    if suite:
        suite_cmd.extend(["--suite", suite])
    if scenario:
        suite_cmd.extend(["--scenario", scenario])
    suite_cmd.extend(["--provider", provider, "--model", model])
    if template:
        suite_cmd.extend(["--template", template])
    if no_model_calls:
        suite_cmd.append("--no-model-calls")
    if ungated_baseline:
        suite_cmd.append("--ungated-baseline")

    _run_checked(suite_cmd)

    # Refresh the compatibility hash artifact from this half's ledger. The
    # document generator independently verifies the summary-bound ledger.
    summary = _read_json(ROOT / "proofs" / "run_summary.json")
    _run_checked([
        sys.executable,
        str(ROOT / "tools" / "verify_itgl.py"),
        "--ledger",
        str(summary["ledger_path"]),
    ])

    # Which document this half produces follows from what it was: the gate
    # decided, or it was not there. From SIR 2.5 the baseline half cannot
    # produce a certificate at all, because tools/generate_certificate.py
    # refuses a ledger whose rows say the gate was not in the path.
    if ungated_baseline:
        gen_proc = _run_checked(
            [sys.executable, str(ROOT / "tools" / "generate_baseline_record.py")]
        )
        document_rel_path = _parse_generated_document_path(
            gen_proc.stdout, key="OUTPUT_BASELINE_JSON"
        )
        publish_flag, archived_name = "--baseline", "baseline.json"
    else:
        gen_proc = _run_checked([sys.executable, str(ROOT / "tools" / "generate_certificate.py")])
        document_rel_path = _parse_generated_document_path(
            gen_proc.stdout, key="OUTPUT_AUDIT_JSON"
        )
        publish_flag, archived_name = "--cert", "audit.json"

    publish_cmd = [
        sys.executable,
        str(ROOT / "tools" / "publish_run.py"),
        publish_flag,
        document_rel_path,
        "--copy",
        "proofs/itgl_ledger.jsonl",
        "--copy",
        "proofs/itgl_final_hash.txt",
        "--copy",
        "proofs/latest-attempts.log",
        "--copy",
        "proofs/run_summary.json",
    ]
    _run_checked(publish_cmd)

    # The summary's own run id, not proofs/run_id.txt: the publisher writes
    # that file for the single-run workflow, and a baseline is not a row there.
    run_id = str(summary.get("run_id") or "").strip()
    if not run_id:
        raise SystemExit("ERROR: the run summary carries no run_id")

    document = _read_json(ROOT / "proofs" / "runs" / run_id / archived_name)
    return run_id, document


def main() -> int:
    ap = argparse.ArgumentParser(description="Execute a paired benchmark (ungated baseline + gated run) using existing single-run paths.")
    ap.add_argument("--mode", choices=["audit", "live"], default="audit")
    ap.add_argument("--pack", default=None)
    ap.add_argument("--suite", default=None)
    ap.add_argument("--scenario", default=None)
    ap.add_argument("--provider", choices=["xai", "openai"], default=DEFAULT_PROVIDER)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--template", default=None)
    ap.add_argument("--no-model-calls", action="store_true")
    ap.add_argument("--pair-key", default=None, help="Optional operator-supplied pair key; otherwise derived from required dimensions.")
    args = ap.parse_args()
    try:
        provider, model = validate_execution_selection(provider=args.provider, model=args.model, mode=args.mode)
    except ValueError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc

    baseline_run_id, baseline_record = _run_single(
        mode=args.mode,
        pack=args.pack,
        suite=args.suite,
        scenario=args.scenario,
        provider=provider,
        model=model,
        template=args.template,
        no_model_calls=args.no_model_calls,
        ungated_baseline=True,
    )
    gated_run_id, gated_audit = _run_single(
        mode=args.mode,
        pack=args.pack,
        suite=args.suite,
        scenario=args.scenario,
        provider=provider,
        model=model,
        template=args.template,
        no_model_calls=args.no_model_calls,
        ungated_baseline=False,
    )

    baseline_entry_ref = f"runs/{baseline_run_id}/baseline.json"
    gated_entry_ref = f"runs/{gated_run_id}/audit.json"

    # The assessment is tools/pair_validation.py's, computed from the two
    # signed documents. This runner does no arithmetic of its own: the first
    # draft of the 2.5 plan computed the gate's blocks here by subtraction and
    # credited systemic resets to the gate, and that function is where the rule
    # now lives and is tested.
    assessment = validate_pair(baseline_record, gated_audit)
    pair_status = assessment["pair_status"]
    non_comparable_reason = assessment["non_comparable_reason"]
    required_dims = assessment["required_dimensions"]

    provider_calls = assessment.get(
        "provider_calls",
        {
            "baseline": {"attempts": None, "successes": None, "failures": None},
            "gated": {"attempts": None, "successes": None, "failures": None},
        },
    )
    baseline_failures = provider_calls["baseline"]["failures"]
    gated_failures = provider_calls["gated"]["failures"]
    baseline_complete = None if baseline_failures is None else baseline_failures == 0
    gated_complete = None if gated_failures is None else gated_failures == 0
    pair_provider_status = (
        "complete"
        if (baseline_complete is True and gated_complete is True)
        else "unknown"
        if (baseline_complete is None or gated_complete is None)
        else "incomplete"
    )

    pair_key = args.pair_key
    if not pair_key:
        pair_key = "|".join(
            [
                f"provider={required_dims.get('provider') or ''}",
                f"model={required_dims.get('model') or ''}",
                f"pack_id={required_dims.get('pack_id') or ''}",
                f"pack_version={required_dims.get('pack_version') or ''}",
                f"prompt_set_hash={required_dims.get('prompt_set_hash') or ''}",
                f"commit_sha={required_dims.get('commit_sha') or ''}",
            ]
        )
    pair_id_seed = f"{baseline_run_id}|{gated_run_id}|{pair_key}"
    pair_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha256(
        pair_id_seed.encode("utf-8")
    ).hexdigest()[:12]

    pair_artifact: Dict[str, Any] = {
        "pair_form": "record_and_certificate",
        "pair_id": pair_id,
        "pair_key": pair_key,
        "created_at_utc": _utc_now_z(),
        "baseline_definition": (
            "same prompt set forwarded to the provider without SIR pre-inference gate "
            "intervention"
        ),
        "baseline_run_id": baseline_run_id,
        "gated_run_id": gated_run_id,
        "pair_status": pair_status,
        "baseline_provider_complete": baseline_complete,
        "gated_provider_complete": gated_complete,
        "pair_provider_status": pair_provider_status,
        "non_comparable_reason": non_comparable_reason,
        "required_dimensions": required_dims,
        "provider_calls": provider_calls,
        "deltas": assessment.get("deltas", {"provider_call_attempts_delta": None}),
        "evidence": {
            "baseline_entry_ref": baseline_entry_ref,
            "gated_entry_ref": gated_entry_ref,
        },
    }
    # Present only when the pair is comparable. A gated half whose own result is
    # INCONCLUSIVE decided an unknown share of its prompts, and no gate figure
    # is published for such a pair at all.
    if "gate_figures" in assessment:
        pair_artifact["gate_figures"] = assessment["gate_figures"]

    out_path = ROOT / "proofs" / "runs" / "pairs" / f"{pair_id}.json"
    _write_json(out_path, pair_artifact)
    _refresh_benchmark_indexes()

    print(f"OK: Pair artifact -> {out_path}")
    print("OK: Refreshed the benchmark indexes in proofs/runs and docs/runs")
    print(f"PAIR_ID={pair_id}")
    print(f"BASELINE_RUN_ID={baseline_run_id}")
    print(f"GATED_RUN_ID={gated_run_id}")
    print(f"PAIR_STATUS={pair_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
