#!/usr/bin/env python3
"""
SIR Firewall — Run Archiver

Creates an immutable per-run archive under proofs/runs/<run_id>/ and updates
proofs/runs/index.json + proofs/runs/index.html can render it for humans.

Designed to be called from CI AFTER proofs/latest-audit.json exists.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

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
from sir_firewall.evidence_paths import canonical_ledger_path


EVIDENCE_CONTRACT_VERSION = "v1"
BENCHMARK_INDEX_V1_VERSION = "benchmark_index.v1"
BENCHMARK_INDEX_V2_VERSION = "benchmark_index.v2"


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _coerce_runs_payload(index_payload: Any) -> List[Dict[str, Any]]:
    if isinstance(index_payload, list):
        return [r for r in index_payload if isinstance(r, dict)]
    if isinstance(index_payload, dict):
        runs = index_payload.get("runs", [])
        if isinstance(runs, list):
            return [r for r in runs if isinstance(r, dict)]
    return []


def _first_not_none(*vals: Any) -> Any:
    for v in vals:
        if v is not None:
            return v
    return None


def _non_empty_str(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    s = value.strip()
    return s or None


def _index_entry_from_audit(run_id: str, audit: Dict[str, Any]) -> Dict[str, Any]:
    pack_id = (
        audit.get("effective_pack_id")
        or audit.get("pack_id")
        or audit.get("selected_pack_id")
    )
    pack_version = audit.get("selected_pack_version") or audit.get("pack_version")
    return {
        "run_id": run_id,
        "date": audit.get("date") or audit.get("timestamp_utc"),
        "result": audit.get("result"),
        "proof_class": audit.get("proof_class"),
        "pack_id": pack_id,
        "pack_version": pack_version,
        "leaks": _first_not_none(audit.get("successful_leaks"), audit.get("leaks"), audit.get("jailbreaks_leaked")),
        "harmless_blocked": _first_not_none(audit.get("harmless_blocked")),
        "trust_fingerprint": audit.get("trust_fingerprint") or audit.get("safety_fingerprint"),
        "safety_fingerprint": audit.get("safety_fingerprint") or audit.get("trust_fingerprint"),
        "itgl_final_hash": audit.get("itgl_final_hash"),
        "ci_run_url": audit.get("ci_run_url"),
        "path": f"runs/{run_id}/",
    }


def _is_passing_result(result: Any) -> bool:
    if not isinstance(result, str):
        return False
    return result.strip().upper() in {"AUDIT PASSED"}


def _validated_run_id(raw_run_id: Any) -> str:
    run_id = str(raw_run_id or "")
    if not run_id:
        raise ValueError("run_id is empty")
    if any(sep in run_id for sep in ("/", "\\")):
        raise ValueError(f"run_id contains path separator: {run_id!r}")
    if run_id in {".", ".."} or ".." in run_id:
        raise ValueError(f"run_id contains traversal-like segment: {run_id!r}")
    return run_id


def _benchmark_entry_from_run(runs_dir: Path, run: Dict[str, Any]) -> Dict[str, Any]:
    run_id = _validated_run_id(run.get("run_id"))
    run_path = str(run.get("path") or f"runs/{run_id}/")
    run_dir = runs_dir / run_id

    expected_run_path = f"runs/{run_id}/"
    if run_path != expected_run_path:
        print(
            f"WARN: unexpected run path for run_id={run_id!r}: {run_path!r} "
            f"(expected {expected_run_path!r}); using run_id-derived paths",
            file=sys.stderr,
        )

    try:
        run_dir.resolve().relative_to(runs_dir.resolve())
    except ValueError as exc:
        raise ValueError(
            f"resolved run directory escapes runs_dir for run_id={run_id!r}"
        ) from exc

    audit: Dict[str, Any] = {}
    audit_parse_error: Optional[str] = None
    audit_path = run_dir / "audit.json"
    if audit_path.exists():
        try:
            audit = _read_json(audit_path)
        except json.JSONDecodeError as exc:
            audit = {}
            audit_parse_error = f"invalid JSON in {audit_path}: {exc}"
            print(f"WARN: {audit_parse_error}", file=sys.stderr)

    def artifact_path(name: str) -> str:
        return f"runs/{run_id}/{name}"

    pack_id = (
        _non_empty_str(run.get("pack_id"))
        or _non_empty_str(audit.get("effective_pack_id"))
        or _non_empty_str(audit.get("pack_id"))
        or _non_empty_str(audit.get("selected_pack_id"))
    )
    pack_version = (
        _non_empty_str(run.get("pack_version"))
        or _non_empty_str(audit.get("selected_pack_version"))
        or _non_empty_str(audit.get("pack_version"))
    )
    scenario_id = _non_empty_str(run.get("scenario_id")) or _non_empty_str(audit.get("scenario_id"))
    proof_class = _non_empty_str(run.get("proof_class")) or _non_empty_str(audit.get("proof_class"))

    target_kind = "scenario_pack" if (scenario_id or proof_class == "SCENARIO_AUDIT") else "domain_pack"
    row_identity = "|".join(
        [
            f"sir={_non_empty_str(audit.get('sir_firewall_version')) or ''}",
            f"commit={_non_empty_str(audit.get('commit_sha')) or ''}",
            f"target={target_kind}:{pack_id or ''}@{pack_version or ''}",
            f"proof_class={proof_class or ''}",
            f"provider={_non_empty_str(audit.get('provider')) or ''}",
            f"model={_non_empty_str(audit.get('model')) or ''}",
        ]
    )

    evidence = {
        "audit": artifact_path("audit.json"),
        "manifest": artifact_path("manifest.json"),
        "archive_receipt": artifact_path("archive_receipt.json"),
        "run_summary": artifact_path("proofs/run_summary.json"),
        "itgl_ledger": canonical_ledger_path(run_id, runs_dir=Path("runs")).as_posix(),
        "itgl_final_hash": artifact_path("proofs/itgl_final_hash.txt"),
        "attempt_log": artifact_path("proofs/latest-attempts.log"),
    }
    if (run_dir / "proofs" / "downstream_evidence.jsonl").exists():
        evidence["downstream_evidence"] = artifact_path("proofs/downstream_evidence.jsonl")

    entry: Dict[str, Any] = {
        "run_id": run_id,
        "run_timestamp_utc": run.get("date") or audit.get("date") or audit.get("timestamp_utc"),
        "sir_firewall_version": audit.get("sir_firewall_version"),
        "commit_sha": run.get("commit_sha") or audit.get("commit_sha"),
        "result": run.get("result") or audit.get("result"),
        "proof_class": proof_class,
        "evaluation_target": {
            "target_kind": target_kind,
            "pack_id": pack_id,
            "pack_version": pack_version,
            "scenario_id": scenario_id,
        },
        "provider": audit.get("provider"),
        "model": audit.get("model"),
        "row_identity": row_identity,
        # comparison contains observed values only (counts + hashes), never a derived score.
        "comparison": {
            "leaks": _first_not_none(run.get("leaks"), audit.get("successful_leaks"), audit.get("leaks"), audit.get("jailbreaks_leaked")),
            "harmless_blocked": _first_not_none(run.get("harmless_blocked"), audit.get("harmless_blocked")),
            "provider_call_attempts": audit.get("provider_call_attempts"),
            "provider_call_successes": audit.get("provider_call_successes"),
            "provider_call_failures": audit.get("provider_call_failures"),
            "trust_fingerprint": run.get("trust_fingerprint") or run.get("safety_fingerprint") or audit.get("trust_fingerprint") or audit.get("safety_fingerprint"),
            "itgl_final_hash": run.get("itgl_final_hash") or audit.get("itgl_final_hash"),
        },
        "ci_run_url": run.get("ci_run_url") or audit.get("ci_run_url"),
        "evidence": evidence,
    }
    if audit_parse_error:
        entry["evidence_error"] = audit_parse_error
    return entry


BASELINE_RECORD_KIND = "sir_ungated_baseline"
BENCHMARK_INDEX_V3_VERSION = "benchmark_index.v3"


def _document_kind(document: Dict[str, Any]) -> str:
    """Which kind of signed document this is, by its own declaration."""
    return (
        "ungated_baseline_record"
        if document.get("record_kind") == BASELINE_RECORD_KIND
        else "audit_certificate"
    )


def _archived_document(run_dir: Path) -> Tuple[Optional[str], Dict[str, Any], Optional[str]]:
    """The one signed document in an archive, with its kind.

    An archive holds audit.json or baseline.json and never both. Both present
    describes one run two ways, and nothing here can say which is the run, so
    it is reported rather than resolved in either document's favour.
    """
    certificate = run_dir / "audit.json"
    record = run_dir / "baseline.json"

    if certificate.is_file() and record.is_file():
        return None, {}, f"{run_dir.name} holds both audit.json and baseline.json"
    for path, kind in ((certificate, "audit_certificate"), (record, "ungated_baseline_record")):
        if not path.is_file():
            continue
        try:
            return kind, _read_json(path), None
        except json.JSONDecodeError as exc:
            return kind, {}, f"invalid JSON in {path}: {exc}"
    return None, {}, None


def _baseline_entry_from_record(runs_dir: Path, run_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """A benchmark index v3 entry for an ungated baseline run.

    It carries forwarding counters and no result, because the record carries
    no result. Nothing here supplies a verdict the document does not have:
    spec/benchmark_index.v3.schema.json forbids one on this entry kind, which
    is the rule that stops a reader finding a field where a verdict would be.
    """
    counters = record.get("counters") if isinstance(record.get("counters"), dict) else {}
    run_dir = runs_dir / run_id
    scenario_id = _non_empty_str(record.get("scenario_id"))
    target_kind = (
        "scenario_pack"
        if record.get("prompt_set_hash_kind") == "scenario_hash" or scenario_id
        else "domain_pack"
    )

    def artifact_path(name: str) -> str:
        return f"runs/{run_id}/{name}"

    evidence = {
        "baseline": artifact_path("baseline.json"),
        "manifest": artifact_path("manifest.json"),
        "archive_receipt": artifact_path("archive_receipt.json"),
        "run_summary": artifact_path("proofs/run_summary.json"),
        "itgl_ledger": canonical_ledger_path(run_id, runs_dir=Path("runs")).as_posix(),
        "itgl_final_hash": artifact_path("proofs/itgl_final_hash.txt"),
        "attempt_log": artifact_path("proofs/latest-attempts.log"),
    }

    entry: Dict[str, Any] = {
        "entry_kind": "ungated_baseline_record",
        "run_id": run_id,
        "run_timestamp_utc": record.get("timestamp_utc"),
        "sir_firewall_version": record.get("sir_firewall_version"),
        "commit_sha": record.get("commit_sha"),
        "evaluation_target": {
            "target_kind": target_kind,
            "pack_id": _non_empty_str(record.get("pack_id")),
            "pack_version": _non_empty_str(record.get("pack_version")),
            "scenario_id": scenario_id,
        },
        "provider": record.get("provider"),
        "model": record.get("model"),
        "row_identity": "|".join(
            [
                f"sir={_non_empty_str(record.get('sir_firewall_version')) or ''}",
                f"commit={_non_empty_str(record.get('commit_sha')) or ''}",
                f"target={target_kind}:{_non_empty_str(record.get('pack_id')) or ''}"
                f"@{_non_empty_str(record.get('pack_version')) or ''}",
                "gate=ungated",
                f"provider={_non_empty_str(record.get('provider')) or ''}",
                f"model={_non_empty_str(record.get('model')) or ''}",
            ]
        ),
        "forwarding": {
            "prompts_forwarded": counters.get("prompts_forwarded"),
            "expected_block_prompts_forwarded": counters.get("expected_block_prompts_forwarded"),
            "expected_allow_prompts_forwarded": counters.get("expected_allow_prompts_forwarded"),
            "provider_call_attempts": counters.get("provider_call_attempts"),
            "provider_call_successes": counters.get("provider_call_successes"),
            "provider_call_failures": counters.get("provider_call_failures"),
        },
        "ci_run_url": record.get("ci_run_url"),
        "evidence": evidence,
    }
    if not (run_dir / "baseline.json").is_file():
        entry["evidence_error"] = f"runs/{run_id}/baseline.json is missing"
    return entry


def _archive_run_ids(runs_dir: Path) -> List[str]:
    if not runs_dir.is_dir():
        return []
    return sorted(
        (p.name for p in runs_dir.iterdir() if p.is_dir() and p.name != "pairs"),
        reverse=True,
    )


def _build_benchmark_index_v3(
    runs_dir: Path, pairs_dir: Path, keep: int = 200
) -> Dict[str, Any]:
    """The benchmark index from SIR 2.5, built from the archives themselves.

    Not from proofs/runs/index.json, which is the single-run truth surface and
    holds gate runs only: a baseline record has no result, so it is not a row
    there, and an index derived from it could never see one.

    The window is the most recent `keep` archives, as index.json's is, plus
    every archive a pair references however old it is. A pair whose half fell
    out of the window would otherwise point at an entry that is not in the
    document, which is the kind of dangling reference a reader cannot
    distinguish from a missing archive.
    """
    pair_artifacts = _load_pair_artifacts(pairs_dir)

    referenced: set = set()
    for artifact in pair_artifacts:
        for key in ("baseline_run_id", "gated_run_id"):
            run_id = _non_empty_str(artifact.get(key))
            if run_id:
                referenced.add(run_id)

    windowed = _archive_run_ids(runs_dir)[: max(1, int(keep))]
    wanted = list(dict.fromkeys(windowed + sorted(referenced, reverse=True)))

    entries: List[Dict[str, Any]] = []
    for run_id in wanted:
        run_dir = runs_dir / run_id
        if not run_dir.is_dir():
            continue
        kind, document, error = _archived_document(run_dir)
        if kind is None:
            if error:
                print(f"WARN: {error}", file=sys.stderr)
            continue
        if kind == "ungated_baseline_record":
            entry = _baseline_entry_from_record(runs_dir, run_id, document)
        else:
            entry = dict(
                _benchmark_entry_from_run(
                    runs_dir=runs_dir, run={"run_id": run_id, "path": f"runs/{run_id}/"}
                ),
                entry_kind="audit_certificate",
            )
            # entry_kind is declared first in the schema's branch order; the
            # field order of a JSON object is not part of the contract, and the
            # publisher does not rely on it.
        if error:
            entry["evidence_error"] = error
        entries.append(entry)

    kinds = {entry["run_id"]: entry["entry_kind"] for entry in entries}
    pairs: List[Dict[str, Any]] = []
    for artifact in pair_artifacts:
        try:
            pairs.append(
                _build_v3_pair_entry(runs_dir=runs_dir, pair_artifact=artifact, kinds=kinds)
            )
        except ValueError as exc:
            print(f"WARN: skipping malformed pair artifact: {exc}", file=sys.stderr)

    index_v1 = _build_benchmark_index_v1(
        runs_dir=runs_dir,
        runs=[
            {"run_id": entry["run_id"], "path": f"runs/{entry['run_id']}/"}
            for entry in entries
            if entry["entry_kind"] == "audit_certificate"
        ],
    )

    return {
        "version": BENCHMARK_INDEX_V3_VERSION,
        "supersedes": BENCHMARK_INDEX_V2_VERSION,
        "updated_at_utc": _utc_now_z(),
        # Gate-run pointers. A baseline record has no result and is never named
        # here, which _build_benchmark_index_v1 guarantees by construction
        # because it was given certificate entries only.
        "latest_run": index_v1.get("latest_run"),
        "latest_passing_run": index_v1.get("latest_passing_run"),
        "entries": entries,
        "pairs": pairs,
    }


def _build_v3_pair_entry(
    *, runs_dir: Path, pair_artifact: Dict[str, Any], kinds: Dict[str, str]
) -> Dict[str, Any]:
    """One pair, in whichever form its two halves make it.

    A pair published before 2.5 has two certificates and keeps its figures as
    published, including a leaks_delta that is the negative of the gate's block
    count over expected-block prompts; docs/archive-errata.md E7 records why
    that is not harm prevented. A pair from 2.5 has a baseline record and a
    certificate, and its figures are recomputed here from those two documents
    by tools/pair_validation.py rather than read from the artifact.
    """
    baseline_run_id = _non_empty_str(pair_artifact.get("baseline_run_id"))
    gated_run_id = _non_empty_str(pair_artifact.get("gated_run_id"))

    if kinds.get(baseline_run_id) != "ungated_baseline_record":
        legacy = _build_pair_entry_from_artifact(runs_dir=runs_dir, pair_artifact=pair_artifact)
        return dict(legacy, pair_form="certificate_pair_legacy")

    record_path = runs_dir / baseline_run_id / "baseline.json"
    certificate_path = runs_dir / gated_run_id / "audit.json"
    record = _read_json(record_path) if record_path.is_file() else None
    certificate = _read_json(certificate_path) if certificate_path.is_file() else None

    assessment = validate_pair(record, certificate)

    entry: Dict[str, Any] = {
        "pair_form": "record_and_certificate",
        "pair_id": _non_empty_str(pair_artifact.get("pair_id")) or "",
        "pair_key": _non_empty_str(pair_artifact.get("pair_key")) or "",
        "baseline_run_id": baseline_run_id,
        "gated_run_id": gated_run_id,
        "baseline_definition": (
            "same prompt set forwarded to the provider without SIR pre-inference gate "
            "intervention"
        ),
        "evidence": {
            "baseline_entry_ref": f"runs/{baseline_run_id}/baseline.json",
            "gated_entry_ref": f"runs/{gated_run_id}/audit.json",
        },
    }
    entry.update(assessment)

    baseline_failures = (assessment.get("provider_calls") or {}).get("baseline", {}).get("failures")
    gated_failures = (assessment.get("provider_calls") or {}).get("gated", {}).get("failures")
    entry["baseline_provider_complete"] = None if baseline_failures is None else baseline_failures == 0
    entry["gated_provider_complete"] = None if gated_failures is None else gated_failures == 0
    if entry["baseline_provider_complete"] and entry["gated_provider_complete"]:
        entry["pair_provider_status"] = "complete"
    elif baseline_failures is None or gated_failures is None:
        entry["pair_provider_status"] = "unknown"
    else:
        entry["pair_provider_status"] = "incomplete"

    if "provider_calls" not in entry:
        entry["provider_calls"] = {
            "baseline": {"attempts": None, "successes": None, "failures": None},
            "gated": {"attempts": None, "successes": None, "failures": None},
        }
    if "deltas" not in entry:
        entry["deltas"] = {"provider_call_attempts_delta": None}
    return entry


def _build_benchmark_index_v1(runs_dir: Path, runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for run in runs:
        try:
            entry = _benchmark_entry_from_run(runs_dir=runs_dir, run=run)
        except ValueError as exc:
            print(f"WARN: skipping malformed run index entry: {exc}", file=sys.stderr)
            continue
        entries.append(entry)

    latest_run = entries[0] if entries else None
    latest_passing_run = next((entry for entry in entries if _is_passing_result(entry.get("result"))), None)

    return {
        "version": BENCHMARK_INDEX_V1_VERSION,
        "updated_at_utc": _utc_now_z(),
        "latest_run": {
            "run_id": latest_run.get("run_id"),
            "result": latest_run.get("result"),
        }
        if latest_run
        else None,
        "latest_passing_run": {
            "run_id": latest_passing_run.get("run_id"),
            "result": latest_passing_run.get("result"),
        }
        if latest_passing_run
        else None,
        "entries": entries,
    }


def _extract_required_dims(audit: Dict[str, Any]) -> Dict[str, Optional[str]]:
    suite_hash = _non_empty_str(audit.get("suite_hash"))
    scenario_hash = _non_empty_str(audit.get("scenario_hash"))
    return {
        "provider": _non_empty_str(audit.get("provider")),
        "model": _non_empty_str(audit.get("model")),
        "pack_id": _non_empty_str(audit.get("effective_pack_id")) or _non_empty_str(audit.get("pack_id")),
        "pack_version": _non_empty_str(audit.get("pack_version")) or _non_empty_str(audit.get("selected_pack_version")),
        "prompt_set_hash": scenario_hash or suite_hash,
        "commit_sha": _non_empty_str(audit.get("commit_sha")),
    }


def _as_int(v: Any) -> Optional[int]:
    return v if isinstance(v, int) else None


def _delta(gated: Optional[int], baseline: Optional[int]) -> Optional[int]:
    if gated is None or baseline is None:
        return None
    return gated - baseline


def _build_pair_entry_from_artifact(*, runs_dir: Path, pair_artifact: Dict[str, Any]) -> Dict[str, Any]:
    pair_id = _non_empty_str(pair_artifact.get("pair_id"))
    if not pair_id:
        raise ValueError("pair artifact missing pair_id")
    pair_key = _non_empty_str(pair_artifact.get("pair_key"))
    if not pair_key:
        raise ValueError(f"pair artifact missing pair_key: {pair_id}")

    baseline_run_id = _non_empty_str(pair_artifact.get("baseline_run_id"))
    gated_run_id = _non_empty_str(pair_artifact.get("gated_run_id"))
    if not baseline_run_id or not gated_run_id:
        raise ValueError(f"pair artifact {pair_id} missing baseline_run_id/gated_run_id")

    baseline_audit_path = runs_dir / baseline_run_id / "audit.json"
    gated_audit_path = runs_dir / gated_run_id / "audit.json"
    if not baseline_audit_path.exists() or not gated_audit_path.exists():
        return {
            "pair_id": pair_id,
            "pair_key": pair_key,
            "pair_status": "invalid_evidence_gap",
            "baseline_run_id": baseline_run_id,
            "gated_run_id": gated_run_id,
            "baseline_definition": "same prompt set evaluated without SIR pre-inference gate intervention",
            "required_dimensions": {
                "provider": None,
                "model": None,
                "target_kind": "domain_pack",
                "pack_id": None,
                "pack_version": None,
                "commit_sha": None,
            },
            "non_comparable_reason": "referenced run audit artifact missing",
            "deltas": {
                "leaks_delta": None,
                "harmless_blocked_delta": None,
                "provider_call_attempts_delta": None,
            },
            "evidence": {
                "baseline_entry_ref": f"runs/{baseline_run_id}/audit.json",
                "gated_entry_ref": f"runs/{gated_run_id}/audit.json",
            },
        }

    baseline_audit = _read_json(baseline_audit_path)
    gated_audit = _read_json(gated_audit_path)
    baseline_exec = baseline_audit.get("benchmark_execution") if isinstance(baseline_audit.get("benchmark_execution"), dict) else {}
    gated_exec = gated_audit.get("benchmark_execution") if isinstance(gated_audit.get("benchmark_execution"), dict) else {}

    baseline_dims = _extract_required_dims(baseline_audit)
    gated_dims = _extract_required_dims(gated_audit)
    required_dimensions = {
        "provider": gated_dims["provider"],
        "model": gated_dims["model"],
        "target_kind": "scenario_pack" if _non_empty_str(gated_audit.get("scenario_id")) else "domain_pack",
        "pack_id": gated_dims["pack_id"],
        "pack_version": gated_dims["pack_version"],
        "commit_sha": gated_dims["commit_sha"],
    }

    pair_status = _non_empty_str(pair_artifact.get("pair_status")) or "valid_complete"
    non_comparable_reason = pair_artifact.get("non_comparable_reason")
    if not isinstance(non_comparable_reason, str):
        non_comparable_reason = None

    baseline_role_ok = baseline_exec.get("benchmark_role") == "baseline" and baseline_exec.get("gate_mode") == "ungated"
    gated_role_ok = gated_exec.get("benchmark_role") == "gated" and gated_exec.get("gate_mode") == "sir_gated"

    mismatches: List[str] = []
    for field in ("provider", "model", "pack_id", "pack_version", "commit_sha"):
        if baseline_dims[field] != gated_dims[field]:
            mismatches.append(field)
    if baseline_dims["prompt_set_hash"] or gated_dims["prompt_set_hash"]:
        if baseline_dims["prompt_set_hash"] != gated_dims["prompt_set_hash"]:
            mismatches.append("prompt_set_hash")

    if not baseline_role_ok or not gated_role_ok:
        pair_status = "invalid_mismatched_dimensions"
        non_comparable_reason = (
            "role correctness failed: baseline must be ungated baseline and gated must be sir_gated treatment"
        )
    elif mismatches:
        pair_status = "invalid_mismatched_dimensions"
        non_comparable_reason = "mismatched required attribution dimensions: " + ", ".join(mismatches)

    return {
        "pair_id": pair_id,
        "pair_key": pair_key,
        "pair_status": pair_status,
        "baseline_run_id": baseline_run_id,
        "gated_run_id": gated_run_id,
        "baseline_definition": "same prompt set evaluated without SIR pre-inference gate intervention",
        "required_dimensions": required_dimensions,
        "non_comparable_reason": non_comparable_reason,
        "deltas": {
            "leaks_delta": _delta(_as_int(gated_audit.get("jailbreaks_leaked")), _as_int(baseline_audit.get("jailbreaks_leaked"))),
            "harmless_blocked_delta": _delta(_as_int(gated_audit.get("harmless_blocked")), _as_int(baseline_audit.get("harmless_blocked"))),
            "provider_call_attempts_delta": _delta(
                _as_int(gated_audit.get("provider_call_attempts")),
                _as_int(baseline_audit.get("provider_call_attempts")),
            ),
            "provider_call_successes_delta": _delta(
                _as_int(gated_audit.get("provider_call_successes")),
                _as_int(baseline_audit.get("provider_call_successes")),
            ),
            "provider_call_failures_delta": _delta(
                _as_int(gated_audit.get("provider_call_failures")),
                _as_int(baseline_audit.get("provider_call_failures")),
            ),
        },
        "baseline_provider_complete": (
            True if _as_int(baseline_audit.get("provider_call_failures")) == 0 else False
            if _as_int(baseline_audit.get("provider_call_failures")) is not None
            else None
        ),
        "gated_provider_complete": (
            True if _as_int(gated_audit.get("provider_call_failures")) == 0 else False
            if _as_int(gated_audit.get("provider_call_failures")) is not None
            else None
        ),
        "pair_provider_status": (
            "complete"
            if (_as_int(baseline_audit.get("provider_call_failures")) == 0 and _as_int(gated_audit.get("provider_call_failures")) == 0)
            else "incomplete"
            if (
                (_as_int(baseline_audit.get("provider_call_failures")) is not None and _as_int(baseline_audit.get("provider_call_failures")) > 0)
                or (_as_int(gated_audit.get("provider_call_failures")) is not None and _as_int(gated_audit.get("provider_call_failures")) > 0)
            )
            else "unknown"
        ),
        "provider_calls": {
            "baseline": {
                "attempts": _as_int(baseline_audit.get("provider_call_attempts")),
                "successes": _as_int(baseline_audit.get("provider_call_successes")),
                "failures": _as_int(baseline_audit.get("provider_call_failures")),
            },
            "gated": {
                "attempts": _as_int(gated_audit.get("provider_call_attempts")),
                "successes": _as_int(gated_audit.get("provider_call_successes")),
                "failures": _as_int(gated_audit.get("provider_call_failures")),
            },
        },
        "evidence": {
            "baseline_entry_ref": f"runs/{baseline_run_id}/audit.json",
            "gated_entry_ref": f"runs/{gated_run_id}/audit.json",
        },
    }


def _load_pair_artifacts(pairs_dir: Path) -> List[Dict[str, Any]]:
    if not pairs_dir.exists():
        return []
    artifacts: List[Dict[str, Any]] = []
    for path in sorted((p for p in pairs_dir.glob("*.json") if p.is_file()), key=lambda p: p.name, reverse=True):
        try:
            payload = _read_json(path)
        except json.JSONDecodeError as exc:
            print(f"WARN: invalid pair artifact JSON {path}: {exc}", file=sys.stderr)
            continue
        artifacts.append(payload)
    return artifacts


def _build_benchmark_index_v2(runs_dir: Path, runs: List[Dict[str, Any]], pairs_dir: Path) -> Dict[str, Any]:
    index_v1 = _build_benchmark_index_v1(runs_dir=runs_dir, runs=runs)
    pair_entries: List[Dict[str, Any]] = []
    for artifact in _load_pair_artifacts(pairs_dir):
        try:
            pair_entries.append(_build_pair_entry_from_artifact(runs_dir=runs_dir, pair_artifact=artifact))
        except ValueError as exc:
            print(f"WARN: skipping malformed pair artifact: {exc}", file=sys.stderr)
            continue
    return {
        "version": BENCHMARK_INDEX_V2_VERSION,
        "updated_at_utc": _utc_now_z(),
        "latest_run": index_v1.get("latest_run"),
        "latest_passing_run": index_v1.get("latest_passing_run"),
        "entries": index_v1.get("entries", []),
        "pairs": pair_entries,
    }


def _rebuild_runs_index_from_archives(runs_dir: Path) -> List[Dict[str, Any]]:
    rebuilt: List[Tuple[str, Dict[str, Any]]] = []
    for run_dir in sorted((p for p in runs_dir.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True):
        audit_path = run_dir / "audit.json"
        if not audit_path.exists():
            continue
        try:
            audit = _read_json(audit_path)
        except json.JSONDecodeError:
            continue
        rebuilt.append((run_dir.name, _index_entry_from_audit(run_dir.name, audit)))
    return [entry for _, entry in rebuilt]


def _load_existing_runs(index_path: Path, runs_dir: Path) -> List[Dict[str, Any]]:
    if not index_path.exists():
        return []
    try:
        index_payload = _read_json(index_path)
        return _coerce_runs_payload(index_payload)
    except json.JSONDecodeError:
        print(f"WARN: Existing index is invalid JSON, rebuilding from archived runs: {index_path}")
        return _rebuild_runs_index_from_archives(runs_dir)


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _utc_now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _short(s: Optional[str], n: int = 12) -> str:
    if not s:
        return "unknown"
    s2 = s.split(":", 1)[-1]
    return s2[:n]


def _safe_run_id(cert: Dict[str, Any]) -> str:
    """
    Build a collision-resistant run_id.

    - Use timestamp with microseconds.
    - Include GitHub run id if available (unique in CI).
    - Keep a short suffix from trust_fingerprint/safety_fingerprint/payload_hash/signature for human scanning.
    """
    raw_date = cert.get("date")
    ts: dt.datetime
    if isinstance(raw_date, str) and raw_date:
        try:
            ts = dt.datetime.fromisoformat(raw_date.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
        except Exception:
            ts = dt.datetime.now(dt.timezone.utc)
    else:
        ts = dt.datetime.now(dt.timezone.utc)

    stamp = ts.strftime("%Y%m%d-%H%M%S") + f"-{ts.microsecond:06d}"

    fp = cert.get("trust_fingerprint") or cert.get("safety_fingerprint") or cert.get("payload_hash") or cert.get("signature")
    suffix = _short(fp, 12)

    gh_run_id = (os.getenv("GITHUB_RUN_ID") or "").strip()
    gh_part = f"-gh{gh_run_id}" if gh_run_id else ""

    return f"{stamp}{gh_part}-{suffix}"


def _unique_run_dir(runs_dir: Path, base_run_id: str) -> tuple[str, Path]:
    """
    Preserve immutability (never overwrite), but disambiguate if a collision occurs.

    Collisions should be extremely rare after microseconds + GITHUB_RUN_ID, but this
    keeps CI truth-preserving even under weird rerun/concurrency edge cases.
    """
    for i in range(0, 50):
        # base_run_id, base_run_id-01, base_run_id-02, ...
        run_id = base_run_id if i == 0 else f"{base_run_id}-{i:02d}"
        run_dir = runs_dir / run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
            return run_id, run_dir
        except FileExistsError:
            continue
    raise SystemExit(f"ERROR: unable to allocate unique run archive dir after 50 attempts: {base_run_id}")


def _copy_optional_artifacts(repo_root: Path, run_dir: Path, extra_paths: List[str]) -> List[str]:
    copied: List[str] = []
    for p in extra_paths:
        rel = Path(p)
        src = (repo_root / rel).resolve()
        if src.exists() and src.is_file():
            dst = (run_dir / rel).resolve()
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(rel.as_posix())
    return copied


def _build_manifest(run_dir: Path, run_id: str, cert: Dict[str, Any]) -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []

    for path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(run_dir).as_posix()
        if rel in {"manifest.json", "archive_receipt.json"}:
            continue
        files.append(
            {
                "path": rel,
                "sha256": _sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    return {
        "run_id": run_id,
        "repository": cert.get("repository") or os.getenv("GITHUB_REPOSITORY", ""),
        "commit_sha": cert.get("commit_sha") or os.getenv("GITHUB_SHA", ""),
        "ci_run_url": cert.get("ci_run_url") or "",
        "timestamp_utc": _utc_now_z(),
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        # A baseline record has no proof class, because no gate ran, so the
        # manifest does not invent one. The record's own kind is named instead,
        # which is what a reader of the archive needs to know first.
        "extras": (
            {
                "record_kind": cert.get("record_kind"),
                "pack_id": cert.get("pack_id"),
                "pack_version": cert.get("pack_version"),
            }
            if _document_kind(cert) == "ungated_baseline_record"
            else {
                "proof_class": cert.get("proof_class"),
                "pack_id": cert.get("pack_id"),
                "pack_version": cert.get("pack_version"),
            }
        ),
        "files": files,
    }


def _build_archive_receipt(manifest: Dict[str, Any], cert: Dict[str, Any], private_key_pem: str, run_dir: Path) -> Dict[str, Any]:
    manifest_bytes = _canonical_json_bytes(manifest)
    manifest_hash = _sha256_bytes(manifest_bytes)

    parts = [f"{entry['path']}:{entry['sha256']}" for entry in manifest.get("files", [])]
    run_folder_hash = _sha256_bytes("\n".join(parts).encode("utf-8"))

    receipt: Dict[str, Any] = {
        "run_id": manifest.get("run_id"),
        "repository": manifest.get("repository", ""),
        "commit_sha": manifest.get("commit_sha", ""),
        "ci_run_url": manifest.get("ci_run_url", ""),
        "manifest_hash": manifest_hash,
        "run_folder_hash": run_folder_hash,
        "timestamp_utc": _utc_now_z(),
        "signing_key_id": cert.get("signing_key_id") or "default",
    }

    payload = _canonical_json_bytes(receipt)
    receipt["payload_hash"] = _sha256_bytes(payload)

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    receipt["signature"] = base64.b64encode(signature).decode("ascii")

    # Defensive check to guarantee we sign exactly the payload fields.
    payload_after = _canonical_json_bytes({k: v for k, v in receipt.items() if k not in ("payload_hash", "signature")})
    if payload != payload_after:
        raise SystemExit(f"ERROR: payload instability while signing archive receipt in {run_dir}")

    return receipt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="Repo root (default: .)")
    ap.add_argument(
        "--cert",
        default=None,
        help="Path to a signed audit certificate (a gated run). Default: proofs/latest-audit.json.",
    )
    ap.add_argument(
        "--baseline",
        default=None,
        help=(
            "Path to a signed ungated baseline record. Mutually exclusive with --cert: "
            "one run is described by one signed document."
        ),
    )
    ap.add_argument("--runs-dir", default="proofs/runs", help="Runs directory")
    ap.add_argument(
        "--copy",
        action="append",
        default=[],
        help="Optional extra file to archive (relative to repo root). Can be repeated.",
    )
    ap.add_argument("--keep", type=int, default=200, help="Keep last N entries in index.json (default: 200)")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    runs_dir = (repo_root / args.runs_dir).resolve()

    # One run, one signed document. A gated run is described by a certificate
    # and an ungated baseline by a baseline record, and from SIR 2.5 the
    # publisher is told which it is being given rather than inferring it.
    if args.cert and args.baseline:
        raise SystemExit(
            "ERROR: --cert and --baseline are mutually exclusive. One run is described by "
            "one signed document: a gated run by a certificate, an ungated baseline by a "
            "baseline record."
        )
    document_path = (repo_root / (args.baseline or args.cert or "proofs/latest-audit.json")).resolve()
    archived_name = "baseline.json" if args.baseline else "audit.json"

    if not document_path.exists():
        raise SystemExit(f"Missing signed document: {document_path}")

    cert = _read_json(document_path)
    document_kind = _document_kind(cert)

    # The flag and the document must agree. A certificate published as a
    # baseline, or a record published as a certificate, would put a document of
    # one kind at the other's filename, and every reader downstream dispatches
    # on that filename.
    expected_kind = "ungated_baseline_record" if args.baseline else "audit_certificate"
    if document_kind != expected_kind:
        raise SystemExit(
            f"ERROR: {document_path} is a {document_kind} and was passed as a "
            f"{expected_kind}. Pass a certificate with --cert and a baseline record with "
            "--baseline."
        )

    cert_run_id = cert.get("run_id")
    if cert_run_id is not None:
        run_id = _validated_run_id(cert_run_id)
        run_dir = runs_dir / run_id
        if not run_dir.is_dir():
            raise SystemExit(f"ERROR: run directory does not exist: {run_dir}")
        for existing in ("audit.json", "baseline.json"):
            if (run_dir / existing).exists():
                raise SystemExit(
                    f"ERROR: run archive already contains a signed document: "
                    f"{run_dir / existing}"
                )
    else:
        if args.baseline:
            raise SystemExit(
                "ERROR: a baseline record must carry a run_id. The revocation rule cannot "
                "check a document whose run identity is absent."
            )
        base_run_id = _safe_run_id(cert)
        run_id, run_dir = _unique_run_dir(runs_dir, base_run_id)

    archived_audit = run_dir / archived_name
    shutil.copy2(document_path, archived_audit)
    downstream_evidence_rel = "proofs/downstream_evidence.jsonl"
    if (repo_root / downstream_evidence_rel).is_file() and downstream_evidence_rel not in args.copy:
        args.copy.append(downstream_evidence_rel)
    _copy_optional_artifacts(repo_root, run_dir, args.copy)

    # Persist run_id for workflow consumers (e.g. docs/latest-run.json publishing).
    run_id_path = repo_root / "proofs" / "run_id.txt"
    run_id_path.parent.mkdir(parents=True, exist_ok=True)
    run_id_path.write_text(run_id + "\n", encoding="utf-8")

    manifest = _build_manifest(run_dir=run_dir, run_id=run_id, cert=cert)
    _write_json(run_dir / "manifest.json", manifest)

    private_key_pem = os.getenv("SDL_PRIVATE_KEY_PEM", "").strip()
    if not private_key_pem:
        raise SystemExit("ERROR: SDL_PRIVATE_KEY_PEM is required to sign archive_receipt.json")

    receipt = _build_archive_receipt(manifest=manifest, cert=cert, private_key_pem=private_key_pem, run_dir=run_dir)
    _write_json(run_dir / "archive_receipt.json", receipt)

    index_path = runs_dir / "index.json"
    runs = _load_existing_runs(index_path=index_path, runs_dir=runs_dir)

    # proofs/runs/index.json is a single-run truth surface: every row carries a
    # result and a proof class, and docs/latest-run.json and the monitor window
    # are read from it. A baseline record has neither, so it is not a row here.
    # Adding one with nulls would put a verdict-shaped hole where every other
    # row has a verdict, which is the shape that made 54 published baselines
    # read as failed audits.
    #
    # It is not unpublished: the benchmark index v3 below is built from the
    # archives themselves and carries both kinds.
    if document_kind == "audit_certificate":
        runs.insert(0, _index_entry_from_audit(run_id=run_id, audit=cert))
        runs = runs[: max(1, int(args.keep))]
        new_index = {
            "updated_at_utc": _utc_now_z(),
            "count": len(runs),
            "runs": runs,
        }
        _write_json(index_path, new_index)
    else:
        print(
            "OK: run index unchanged: an ungated baseline record is not a single-run "
            "truth row, because it carries no result"
        )

    benchmark_index_v1 = _build_benchmark_index_v1(runs_dir=runs_dir, runs=runs)
    benchmark_v1_path = runs_dir / f"{BENCHMARK_INDEX_V1_VERSION}.json"
    _write_json(benchmark_v1_path, benchmark_index_v1)

    benchmark_index_v2 = _build_benchmark_index_v2(
        runs_dir=runs_dir,
        runs=runs,
        pairs_dir=(runs_dir / "pairs"),
    )
    benchmark_v2_path = runs_dir / f"{BENCHMARK_INDEX_V2_VERSION}.json"
    _write_json(benchmark_v2_path, benchmark_index_v2)

    # v3 is built from the archive directories rather than from the run index,
    # so it can hold a baseline record at all. v2 stays as published and keeps
    # describing the gate runs it already describes.
    benchmark_index_v3 = _build_benchmark_index_v3(
        runs_dir=runs_dir,
        pairs_dir=(runs_dir / "pairs"),
        keep=max(1, int(args.keep)),
    )
    benchmark_v3_path = runs_dir / f"{BENCHMARK_INDEX_V3_VERSION}.json"
    _write_json(benchmark_v3_path, benchmark_index_v3)

    print(f"OK: Archived run {run_id} -> {run_dir}")
    print(f"OK: Wrote run id -> {run_id_path}")
    print(f"OK: Wrote manifest -> {run_dir / 'manifest.json'}")
    print(f"OK: Wrote archive receipt -> {run_dir / 'archive_receipt.json'}")
    print(f"OK: Updated index -> {index_path}")
    print(f"OK: Updated benchmark index -> {benchmark_v1_path}")
    print(f"OK: Updated benchmark index -> {benchmark_v2_path}")
    print(f"OK: Updated benchmark index -> {benchmark_v3_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
