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
        "itgl_ledger": artifact_path("proofs/itgl_ledger.jsonl"),
        "itgl_final_hash": artifact_path("proofs/itgl_final_hash.txt"),
        "attempt_log": artifact_path("proofs/latest-attempts.log"),
    }

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
        "extras": {
            "proof_class": cert.get("proof_class"),
            "pack_id": cert.get("pack_id"),
            "pack_version": cert.get("pack_version"),
        },
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
    ap.add_argument("--cert", default="proofs/latest-audit.json", help="Path to latest signed cert JSON")
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
    cert_path = (repo_root / args.cert).resolve()
    runs_dir = (repo_root / args.runs_dir).resolve()

    if not cert_path.exists():
        raise SystemExit(f"Missing certificate: {cert_path}")

    cert = _read_json(cert_path)

    base_run_id = _safe_run_id(cert)
    run_id, run_dir = _unique_run_dir(runs_dir, base_run_id)

    archived_audit = run_dir / "audit.json"
    shutil.copy2(cert_path, archived_audit)
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

    entry = _index_entry_from_audit(run_id=run_id, audit=cert)

    runs.insert(0, entry)
    runs = runs[: max(1, int(args.keep))]

    new_index = {
        "updated_at_utc": _utc_now_z(),
        "count": len(runs),
        "runs": runs,
    }
    _write_json(index_path, new_index)

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

    print(f"OK: Archived run {run_id} -> {run_dir}")
    print(f"OK: Wrote run id -> {run_id_path}")
    print(f"OK: Wrote manifest -> {run_dir / 'manifest.json'}")
    print(f"OK: Wrote archive receipt -> {run_dir / 'archive_receipt.json'}")
    print(f"OK: Updated index -> {index_path}")
    print(f"OK: Updated benchmark index -> {benchmark_v1_path}")
    print(f"OK: Updated benchmark index -> {benchmark_v2_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
