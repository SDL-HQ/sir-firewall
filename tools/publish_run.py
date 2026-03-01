#!/usr/bin/env python3
"""
SIR Firewall — Run Archiver

Creates an immutable per-run archive under proofs/runs/<run_id>/ and updates
proofs/runs/index.json + proofs/runs/index.html can render it for humans.

Designed to be called from CI AFTER proofs/latest-audit.json exists.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


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


def _collect_optional_artifacts(repo_root: Path, extra_paths: List[str]) -> List[Dict[str, str]]:
    collected: List[Dict[str, str]] = []
    for p in extra_paths:
        src = (repo_root / p).resolve()
        if src.exists() and src.is_file():
            collected.append(
                {
                    "path": p,
                    "sha256": _sha256_file(src),
                }
            )
    return collected


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

    # Persist run_id for workflow consumers (e.g. docs/latest-run.json publishing).
    run_id_path = repo_root / "proofs" / "run_id.txt"
    run_id_path.parent.mkdir(parents=True, exist_ok=True)
    run_id_path.write_text(run_id + "\n", encoding="utf-8")

    env = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }

    extras = _collect_optional_artifacts(repo_root, args.copy)

    manifest = {
        "run_id": run_id,
        "archived_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_cert": os.path.relpath(cert_path, repo_root),
        "archived_audit": os.path.relpath(archived_audit, repo_root),
        "env": env,
        "extras": extras,
        "date": cert.get("date"),
        "suite": cert.get("suite") or cert.get("domain_pack"),
        "model": cert.get("model"),
        "provider": cert.get("provider"),
        "result": cert.get("result"),
        "prompts_tested": cert.get("prompts_tested"),
        "leaks": cert.get("successful_leaks") or cert.get("leaks") or cert.get("jailbreaks_leaked"),
        "harmless_blocked": cert.get("harmless_blocked"),
        "trust_fingerprint": cert.get("trust_fingerprint") or cert.get("safety_fingerprint"),
        "safety_fingerprint": cert.get("safety_fingerprint") or cert.get("trust_fingerprint"),
        "policy_hash": cert.get("policy_hash"),
        "suite_hash": cert.get("suite_hash"),
        "itgl_final_hash": cert.get("itgl_final_hash"),
        "ci_run_url": cert.get("ci_run_url"),
        "payload_hash": cert.get("payload_hash"),
        "signature": cert.get("signature"),
    }

    _write_json(run_dir / "manifest.json", manifest)

    index_path = runs_dir / "index.json"
    if index_path.exists():
        index = _read_json(index_path)
        runs = index.get("runs", [])
        if not isinstance(runs, list):
            runs = []
    else:
        runs = []

    entry = {
        "run_id": run_id,
        "date": manifest.get("date"),
        "result": manifest.get("result"),
        "leaks": manifest.get("leaks"),
        "harmless_blocked": manifest.get("harmless_blocked"),
        "trust_fingerprint": manifest.get("trust_fingerprint") or manifest.get("safety_fingerprint"),
        "safety_fingerprint": manifest.get("safety_fingerprint") or manifest.get("trust_fingerprint"),
        "itgl_final_hash": manifest.get("itgl_final_hash"),
        "ci_run_url": manifest.get("ci_run_url"),
        "path": f"runs/{run_id}/",
    }

    runs.insert(0, entry)
    runs = runs[: max(1, int(args.keep))]

    new_index = {
        "updated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "count": len(runs),
        "runs": runs,
    }
    _write_json(index_path, new_index)

    print(f"OK: Archived run {run_id} -> {run_dir}")
    print(f"OK: Wrote run id -> {run_id_path}")
    print(f"OK: Updated index -> {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
