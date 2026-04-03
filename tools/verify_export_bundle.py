#!/usr/bin/env python3
"""Verify a SIR export bundle offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

OK = 0
MISMATCH = 2
PARSE = 3


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _collect_files(root: Path) -> List[Path]:
    return sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix())


def _compute_bundle_hash(bundle_root: Path) -> str:
    lines: List[str] = []
    for p in _collect_files(bundle_root):
        rel = p.relative_to(bundle_root).as_posix()
        if rel in {"bundle_manifest.json", "bundle.tar"}:
            continue
        lines.append(f"{rel}:{_sha256_file(p)}")
    return _sha256_bytes("\n".join(lines).encode("utf-8"))


def _read_json_object(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"failed to parse JSON {path}: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object in {path}, got {type(obj).__name__}")
    return obj


def _verify_archive_receipt(bundle_root: Path, pubkey: str) -> int:
    cmd = [sys.executable, "tools/verify_archive_receipt.py", str(bundle_root), "--pubkey", pubkey]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, end="", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def _verify_manifest(bundle_root: Path) -> int:
    manifest_path = bundle_root / "bundle_manifest.json"
    if not manifest_path.exists():
        print("OK: bundle_manifest.json not present (skipping optional descriptor checks)")
        return OK

    try:
        manifest = _read_json_object(manifest_path)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return PARSE

    required = {"exported_at_utc", "source_run_id", "receipt_hash", "bundle_hash"}
    missing = sorted(required - set(manifest.keys()))
    if missing:
        print(f"ERROR: bundle_manifest.json missing required fields: {', '.join(missing)}", file=sys.stderr)
        return MISMATCH

    run_dir = bundle_root / "proofs" / "runs" / str(manifest.get("source_run_id", ""))
    receipt_path = run_dir / "archive_receipt.json"
    if not receipt_path.exists():
        print(f"ERROR: missing archive_receipt.json at {receipt_path}", file=sys.stderr)
        return MISMATCH

    receipt_hash = _sha256_bytes(receipt_path.read_bytes())
    if manifest.get("receipt_hash") != receipt_hash:
        print("ERROR: receipt_hash mismatch", file=sys.stderr)
        print(f"  manifest: {manifest.get('receipt_hash')}", file=sys.stderr)
        print(f"  calc:     {receipt_hash}", file=sys.stderr)
        return MISMATCH

    bundle_hash = _compute_bundle_hash(bundle_root)
    if manifest.get("bundle_hash") != bundle_hash:
        print("ERROR: bundle_hash mismatch", file=sys.stderr)
        print(f"  manifest: {manifest.get('bundle_hash')}", file=sys.stderr)
        print(f"  calc:     {bundle_hash}", file=sys.stderr)
        return MISMATCH

    return OK


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify an exported SIR run bundle")
    ap.add_argument("bundle_path", help="Path to export bundle directory")
    ap.add_argument("--pubkey", default="spec/sdl.pub", help="Path to PEM public key (default: spec/sdl.pub)")
    args = ap.parse_args()

    bundle_root = Path(args.bundle_path).resolve()
    if not bundle_root.exists() or not bundle_root.is_dir():
        print(f"ERROR: bundle path is not a directory: {bundle_root}", file=sys.stderr)
        return PARSE

    if (bundle_root / "bundle.tar").exists() and not (bundle_root / "proofs").exists():
        print("ERROR: bundle directory contains bundle.tar but no extracted proofs/ tree", file=sys.stderr)
        return PARSE

    receipt_status = _verify_archive_receipt(bundle_root, pubkey=args.pubkey)
    if receipt_status == PARSE:
        return PARSE
    if receipt_status != OK:
        return MISMATCH

    manifest_status = _verify_manifest(bundle_root)
    if manifest_status != OK:
        return manifest_status

    print(f"OK: export bundle verified for {bundle_root}")
    return OK


if __name__ == "__main__":
    raise SystemExit(main())
