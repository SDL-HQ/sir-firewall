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


def _parse_generated_cert_path(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("OUTPUT_AUDIT_JSON="):
            out = line.split("=", 1)[1].strip()
            if out:
                return out
    raise SystemExit("ERROR: generate_certificate.py output missing OUTPUT_AUDIT_JSON")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_benchmark_index_v2() -> None:
    runs_dir = ROOT / "proofs" / "runs"
    benchmark_v1_path = runs_dir / "benchmark_index.v1.json"
    benchmark_v2_path = runs_dir / "benchmark_index.v2.json"
    docs_benchmark_v2_path = ROOT / "docs" / "runs" / "benchmark_index.v2.json"

    if not benchmark_v1_path.exists():
        raise SystemExit(f"ERROR: missing benchmark index v1 required for v2 refresh: {benchmark_v1_path}")

    spec = importlib.util.spec_from_file_location("publish_run_module", ROOT / "tools" / "publish_run.py")
    if spec is None or spec.loader is None:
        raise SystemExit("ERROR: unable to load tools/publish_run.py for v2 refresh")
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
    _write_json(docs_benchmark_v2_path, benchmark_index_v2)


def _extract_run_dims(audit: Dict[str, Any]) -> Dict[str, Optional[str]]:
    suite_hash = str(audit.get("suite_hash") or "").strip() or None
    scenario_hash = str(audit.get("scenario_hash") or "").strip() or None
    return {
        "model": str(audit.get("model") or "").strip() or None,
        "provider": str(audit.get("provider") or "").strip() or None,
        "pack_id": (
            str(audit.get("effective_pack_id") or "").strip()
            or str(audit.get("pack_id") or "").strip()
            or None
        ),
        "pack_version": str(audit.get("pack_version") or audit.get("selected_pack_version") or "").strip() or None,
        "prompt_set_hash": scenario_hash or suite_hash,
        "suite_hash": suite_hash,
        "scenario_hash": scenario_hash,
        "commit_sha": str(audit.get("commit_sha") or "").strip() or None,
    }


def _int_or_none(v: Any) -> Optional[int]:
    return v if isinstance(v, int) else None


def _compute_delta(baseline_val: Optional[int], gated_val: Optional[int]) -> Optional[int]:
    if baseline_val is None or gated_val is None:
        return None
    return gated_val - baseline_val


def _validate_pair(*, baseline_audit: Dict[str, Any], gated_audit: Dict[str, Any]) -> tuple[str, Optional[str], Dict[str, Optional[str]]]:
    baseline_exec = baseline_audit.get("benchmark_execution") if isinstance(baseline_audit.get("benchmark_execution"), dict) else {}
    gated_exec = gated_audit.get("benchmark_execution") if isinstance(gated_audit.get("benchmark_execution"), dict) else {}

    baseline_role_ok = baseline_exec.get("benchmark_role") == "baseline" and baseline_exec.get("gate_mode") == "ungated"
    gated_role_ok = gated_exec.get("benchmark_role") == "gated" and gated_exec.get("gate_mode") == "sir_gated"
    if not baseline_role_ok or not gated_role_ok:
        return (
            "invalid_mismatched_dimensions",
            "role correctness failed: baseline must be (benchmark_role=baseline, gate_mode=ungated) and gated must be (benchmark_role=gated, gate_mode=sir_gated)",
            {},
        )

    baseline_dims = _extract_run_dims(baseline_audit)
    gated_dims = _extract_run_dims(gated_audit)

    required = {
        "provider": gated_dims["provider"],
        "model": gated_dims["model"],
        "pack_id": gated_dims["pack_id"],
        "pack_version": gated_dims["pack_version"],
        "prompt_set_hash": gated_dims["prompt_set_hash"],
        "commit_sha": gated_dims["commit_sha"],
    }

    mismatches = []
    for field in ("provider", "model", "pack_id", "pack_version", "commit_sha"):
        if baseline_dims[field] != gated_dims[field]:
            mismatches.append(field)

    # Prompt-set identity is strict when available on either side.
    b_prompt = baseline_dims["prompt_set_hash"]
    g_prompt = gated_dims["prompt_set_hash"]
    if b_prompt or g_prompt:
        if b_prompt != g_prompt:
            mismatches.append("prompt_set_hash")

    if mismatches:
        return (
            "invalid_mismatched_dimensions",
            "mismatched required attribution dimensions: " + ", ".join(mismatches),
            required,
        )

    return "valid_complete", None, required


def _run_single(*, mode: str, pack: Optional[str], suite: Optional[str], scenario: Optional[str], model: Optional[str], template: Optional[str], no_model_calls: bool, ungated_baseline: bool) -> tuple[str, Dict[str, Any]]:
    suite_cmd = [sys.executable, str(ROOT / "red_team_suite.py"), "--mode", mode]
    if pack:
        suite_cmd.extend(["--pack", pack])
    if suite:
        suite_cmd.extend(["--suite", suite])
    if scenario:
        suite_cmd.extend(["--scenario", scenario])
    if model:
        suite_cmd.extend(["--model", model])
    if template:
        suite_cmd.extend(["--template", template])
    if no_model_calls:
        suite_cmd.append("--no-model-calls")
    if ungated_baseline:
        suite_cmd.append("--ungated-baseline")

    _run_checked(suite_cmd)

    gen_proc = _run_checked([sys.executable, str(ROOT / "tools" / "generate_certificate.py")])
    cert_rel_path = _parse_generated_cert_path(gen_proc.stdout)

    publish_cmd = [
        sys.executable,
        str(ROOT / "tools" / "publish_run.py"),
        "--cert",
        cert_rel_path,
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

    run_id = (ROOT / "proofs" / "run_id.txt").read_text(encoding="utf-8").strip()
    if not run_id:
        raise SystemExit("ERROR: publish_run did not write run_id")

    audit = _read_json(ROOT / "proofs" / "runs" / run_id / "audit.json")
    return run_id, audit


def main() -> int:
    ap = argparse.ArgumentParser(description="Execute a paired benchmark (ungated baseline + gated run) using existing single-run paths.")
    ap.add_argument("--mode", choices=["audit", "live"], default="audit")
    ap.add_argument("--pack", default=None)
    ap.add_argument("--suite", default=None)
    ap.add_argument("--scenario", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--template", default=None)
    ap.add_argument("--no-model-calls", action="store_true")
    ap.add_argument("--pair-key", default=None, help="Optional operator-supplied pair key; otherwise derived from required dimensions.")
    args = ap.parse_args()

    baseline_run_id, baseline_audit = _run_single(
        mode=args.mode,
        pack=args.pack,
        suite=args.suite,
        scenario=args.scenario,
        model=args.model,
        template=args.template,
        no_model_calls=args.no_model_calls,
        ungated_baseline=True,
    )
    gated_run_id, gated_audit = _run_single(
        mode=args.mode,
        pack=args.pack,
        suite=args.suite,
        scenario=args.scenario,
        model=args.model,
        template=args.template,
        no_model_calls=args.no_model_calls,
        ungated_baseline=False,
    )

    baseline_entry_ref = f"runs/{baseline_run_id}/audit.json"
    gated_entry_ref = f"runs/{gated_run_id}/audit.json"

    pair_status, non_comparable_reason, required_dims = _validate_pair(
        baseline_audit=baseline_audit,
        gated_audit=gated_audit,
    )

    if not required_dims:
        # fallback dimensions when validation fails before extraction completes
        gated_dims = _extract_run_dims(gated_audit)
        required_dims = {
            "provider": gated_dims["provider"],
            "model": gated_dims["model"],
            "pack_id": gated_dims["pack_id"],
            "pack_version": gated_dims["pack_version"],
            "prompt_set_hash": gated_dims["prompt_set_hash"],
            "commit_sha": gated_dims["commit_sha"],
        }

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
    pair_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha256(pair_id_seed.encode("utf-8")).hexdigest()[:12]

    baseline_leaks = _int_or_none(baseline_audit.get("jailbreaks_leaked"))
    gated_leaks = _int_or_none(gated_audit.get("jailbreaks_leaked"))
    baseline_harmless = _int_or_none(baseline_audit.get("harmless_blocked"))
    gated_harmless = _int_or_none(gated_audit.get("harmless_blocked"))
    baseline_attempts = _int_or_none(baseline_audit.get("provider_call_attempts"))
    gated_attempts = _int_or_none(gated_audit.get("provider_call_attempts"))

    pair_artifact: Dict[str, Any] = {
        "pair_id": pair_id,
        "pair_key": pair_key,
        "created_at_utc": _utc_now_z(),
        "baseline_definition": "same prompt set evaluated without SIR pre-inference gate intervention",
        "baseline_run_id": baseline_run_id,
        "gated_run_id": gated_run_id,
        "pair_status": pair_status,
        "non_comparable_reason": non_comparable_reason,
        "required_dimensions": required_dims,
        "deltas": {
            "leaks_delta": _compute_delta(baseline_leaks, gated_leaks),
            "harmless_blocked_delta": _compute_delta(baseline_harmless, gated_harmless),
            "provider_call_attempts_delta": _compute_delta(baseline_attempts, gated_attempts),
        },
        "evidence": {
            "baseline_entry_ref": baseline_entry_ref,
            "gated_entry_ref": gated_entry_ref,
        },
    }

    out_path = ROOT / "proofs" / "runs" / "pairs" / f"{pair_id}.json"
    _write_json(out_path, pair_artifact)
    _refresh_benchmark_index_v2()

    print(f"OK: Pair artifact -> {out_path}")
    print("OK: Refreshed benchmark_index.v2.json in proofs/runs and docs/runs")
    print(f"PAIR_ID={pair_id}")
    print(f"BASELINE_RUN_ID={baseline_run_id}")
    print(f"GATED_RUN_ID={gated_run_id}")
    print(f"PAIR_STATUS={pair_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
