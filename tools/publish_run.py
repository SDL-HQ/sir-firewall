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
    # allow values like "sha256:...."
    s2 = s.split(":", 1)[-1]
    return s2[:n]


def _safe_run_id(cert: Dict[str, Any]) -> str:
    # Prefer cert date if present; fall back to UTC now.
    raw_date = cert.get("date")
    ts: dt.datetime
    if isinstance(raw_date, str) and raw_date:
        try:
            # allow "2025-12-13T16:19:00Z" or similar
            ts = dt.datetime.fromisoformat(raw_date.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
        except Exception:
            ts = dt.datetime.now(dt.timezone.utc)
    else:
        ts = dt.datetime.now(dt.timezone.utc)

    stamp = ts.strftime("%Y%m%d-%H%M%S")

    # Prefer safety_fingerprint; else payload_hash; else signature; else random-ish.
    fp = cert.get("safety_fingerprint") or cert.get("payload_hash") or cert.get("signature")
    suffix = _short(fp, 12)

    return f"{stamp}-{suffix}"


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
    run_id = _safe_run_id(cert)

    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Archive cert as audit.json (immutable record)
    archived_audit = run_dir / "audit.json"
    shutil.copy2(cert_path, archived_audit)

    # Minimal environment capture (helps reproduction without adding “crap”)
    env = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }

    # Optional extra artifacts (only if they exist)
    extras = _collect_optional_artifacts(repo_root, args.copy)

    manifest = {
        "run_id": run_id,
        "archived_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_cert": os.path.relpath(cert_path, repo_root),
        "archived_audit": os.path.relpath(archived_audit, repo_root),
        "env": env,
        "extras": extras,
        # A few convenient “index fields” (don’t depend on exact schema)
        "date": cert.get("date"),
        "suite": cert.get("suite") or cert.get("domain_pack"),
        "model": cert.get("model"),
        "provider": cert.get("provider"),
        "result": cert.get("result"),
        "prompts_tested": cert.get("prompts_tested"),
        "leaks": cert.get("successful_leaks") or cert.get("leaks") or cert.get("jailbreaks_leaked"),
        "harmless_blocked": cert.get("harmless_blocked"),
        "safety_fingerprint": cert.get("safety_fingerprint"),
        "policy_hash": cert.get("policy_hash"),
        "suite_hash": cert.get("suite_hash"),
        "itgl_final_hash": cert.get("itgl_final_hash"),
        "ci_run_url": cert.get("ci_run_url"),
        "payload_hash": cert.get("payload_hash"),
        "signature": cert.get("signature"),
    }

    _write_json(run_dir / "manifest.json", manifest)

    # Update index.json
    index_path = runs_dir / "index.json"
    if index_path.exists():
        index = _read_json(index_path)
        runs = index.get("runs", [])
        if not isinstance(runs, list):
            runs = []
    else:
        runs = []

    # Remove existing entry with same run_id (idempotent)
    runs = [r for r in runs if isinstance(r, dict) and r.get("run_id") != run_id]

    entry = {
        "run_id": run_id,
        "date": manifest.get("date"),
        "result": manifest.get("result"),
        "leaks": manifest.get("leaks"),
        "harmless_blocked": manifest.get("harmless_blocked"),
        "safety_fingerprint": manifest.get("safety_fingerprint"),
        "itgl_final_hash": manifest.get("itgl_final_hash"),
        "ci_run_url": manifest.get("ci_run_url"),
        "path": f"runs/{run_id}/",  # relative under proofs/
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
    print(f"OK: Updated index -> {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
