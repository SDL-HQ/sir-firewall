#!/usr/bin/env python3
"""Verify a signed SIR run archive receipt offline."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from key_registry import find_registry_key, public_key_pem_from_entry, revocation_allows_proof

DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")
DEFAULT_KEY_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")


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


def _load_json_obj(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"failed to parse JSON {path}: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object in {path}, got {type(obj).__name__}")
    return obj


def _resolve_archive_dir(path: Path) -> Path:
    manifest = path / "manifest.json"
    receipt = path / "archive_receipt.json"
    if manifest.exists() or receipt.exists():
        return path

    candidates: List[Path] = []
    for candidate in path.rglob("manifest.json"):
        run_dir = candidate.parent
        if (run_dir / "archive_receipt.json").exists():
            candidates.append(run_dir)

    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise ValueError(f"multiple run archives found under {path}; pass a specific run folder")
    raise ValueError(f"no run archive found at {path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a SIR run archive receipt.")
    ap.add_argument("archive_path", help="Path to run folder or exported bundle folder")
    ap.add_argument("--pubkey", default=None, help="Path to PEM public key (default: spec/sdl.pub)")
    ap.add_argument(
        "--key-registry",
        default=str(DEFAULT_KEY_REGISTRY),
        help="Path to key registry JSON used when signing_key_id is present.",
    )
    ap.add_argument(
        "--require-registry",
        action="store_true",
        help="Fail when signing_key_id is present but key registry is missing/unreadable.",
    )
    args = ap.parse_args()
    pubkey_explicit = args.pubkey is not None
    if args.pubkey is None:
        args.pubkey = str(DEFAULT_PUBKEY_PATH)

    try:
        archive_dir = _resolve_archive_dir(Path(args.archive_path))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    manifest_path = archive_dir / "manifest.json"
    receipt_path = archive_dir / "archive_receipt.json"

    if not manifest_path.exists():
        print(f"ERROR: missing manifest.json in {archive_dir}", file=sys.stderr)
        return 3
    if not receipt_path.exists():
        print(f"ERROR: missing archive_receipt.json in {archive_dir} (legacy archive without receipt)", file=sys.stderr)
        return 3

    try:
        manifest = _load_json_obj(manifest_path)
        receipt = _load_json_obj(receipt_path)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    required_receipt_fields = {
        "run_id",
        "repository",
        "commit_sha",
        "ci_run_url",
        "manifest_hash",
        "run_folder_hash",
        "timestamp_utc",
        "signing_key_id",
        "payload_hash",
        "signature",
    }
    missing = sorted(required_receipt_fields - set(receipt.keys()))
    if missing:
        print(f"ERROR: archive_receipt.json missing required fields: {', '.join(missing)}", file=sys.stderr)
        return 3

    signing_key_id = receipt.get("signing_key_id")
    if not isinstance(signing_key_id, str) or not signing_key_id:
        print("ERROR: signing_key_id must be a non-empty string", file=sys.stderr)
        return 3

    try:
        registry_path = Path(args.key_registry)
        if registry_path.exists():
            entry = find_registry_key(registry_path, signing_key_id)
            if entry is None:
                if pubkey_explicit and not args.require_registry:
                    print(
                        "WARNING: signing_key_id not found in key registry; using explicit --pubkey for local/dev verification only (revocation checks not enforced).",
                        file=sys.stderr,
                    )
                    public_key = serialization.load_pem_public_key(Path(args.pubkey).read_bytes())
                else:
                    print(
                        f"ERROR: signing_key_id not found in key registry: {signing_key_id}",
                        file=sys.stderr,
                    )
                    return 2
            else:
                allowed, reason = revocation_allows_proof(entry, receipt.get("timestamp_utc"))
                if not allowed:
                    print(f"ERROR: revoked-key verification failure: {reason}", file=sys.stderr)
                    return 2
                public_key = serialization.load_pem_public_key(public_key_pem_from_entry(entry).encode("utf-8"))
        else:
            if args.require_registry:
                print(
                    f"ERROR: key registry not found: {registry_path} (required for signing_key_id={signing_key_id})",
                    file=sys.stderr,
                )
                return 3
            print(
                "WARNING: signing_key_id present but key registry unavailable; falling back to --pubkey verification only (revocation checks not enforced).",
                file=sys.stderr,
            )
            public_key = serialization.load_pem_public_key(Path(args.pubkey).read_bytes())
    except ValueError as e:
        if args.require_registry:
            print(f"ERROR: failed to load required key registry {args.key_registry} ({e})", file=sys.stderr)
            return 3
        print(
            "WARNING: signing_key_id present but key registry unreadable; falling back to --pubkey verification only (revocation checks not enforced).",
            file=sys.stderr,
        )
        try:
            public_key = serialization.load_pem_public_key(Path(args.pubkey).read_bytes())
        except Exception as ex:
            print(f"ERROR: failed to load verification key ({ex})", file=sys.stderr)
            return 3
    except Exception as e:
        print(f"ERROR: failed to load verification key ({e})", file=sys.stderr)
        return 3

    manifest_hash = _sha256_bytes(_canonical_json_bytes(manifest))
    if receipt.get("manifest_hash") != manifest_hash:
        print("ERROR: manifest_hash mismatch", file=sys.stderr)
        print(f"  receipt: {receipt.get('manifest_hash')}", file=sys.stderr)
        print(f"  calc:    {manifest_hash}", file=sys.stderr)
        return 2

    files = manifest.get("files")
    if not isinstance(files, list):
        print("ERROR: manifest.files must be an array", file=sys.stderr)
        return 2

    for i, entry in enumerate(files):
        if not isinstance(entry, dict):
            print(f"ERROR: manifest.files[{i}] must be an object", file=sys.stderr)
            return 2
        path = entry.get("path")
        sha = entry.get("sha256")
        size = entry.get("size_bytes")
        if not isinstance(path, str) or not isinstance(sha, str) or not isinstance(size, int):
            print(f"ERROR: manifest.files[{i}] requires path(str), sha256(str), size_bytes(int)", file=sys.stderr)
            return 2

        file_path = archive_dir / path
        if not file_path.exists() or not file_path.is_file():
            print(f"ERROR: file listed in manifest is missing: {path}", file=sys.stderr)
            return 2

        calc_sha = _sha256_file(file_path)
        if calc_sha != sha:
            print(f"ERROR: file hash mismatch for {path}", file=sys.stderr)
            print(f"  manifest: {sha}", file=sys.stderr)
            print(f"  calc:     {calc_sha}", file=sys.stderr)
            return 2

        calc_size = file_path.stat().st_size
        if calc_size != size:
            print(f"ERROR: file size mismatch for {path}", file=sys.stderr)
            print(f"  manifest: {size}", file=sys.stderr)
            print(f"  calc:     {calc_size}", file=sys.stderr)
            return 2

    parts = [f"{entry['path']}:{entry['sha256']}" for entry in files]
    run_folder_hash = _sha256_bytes("\n".join(parts).encode("utf-8"))
    if receipt.get("run_folder_hash") != run_folder_hash:
        print("ERROR: run_folder_hash mismatch", file=sys.stderr)
        print(f"  receipt: {receipt.get('run_folder_hash')}", file=sys.stderr)
        print(f"  calc:    {run_folder_hash}", file=sys.stderr)
        return 2

    payload = {k: v for k, v in receipt.items() if k not in ("payload_hash", "signature")}
    payload_bytes = _canonical_json_bytes(payload)
    payload_hash = _sha256_bytes(payload_bytes)
    if receipt.get("payload_hash") != payload_hash:
        print("ERROR: payload_hash mismatch", file=sys.stderr)
        print(f"  receipt: {receipt.get('payload_hash')}", file=sys.stderr)
        print(f"  calc:    {payload_hash}", file=sys.stderr)
        return 2

    try:
        sig = base64.b64decode(str(receipt["signature"]))
    except Exception as e:
        print(f"ERROR: signature is not valid base64 ({e})", file=sys.stderr)
        return 2

    try:
        public_key.verify(sig, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print("ERROR: signature verification failed (InvalidSignature)", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: signature verification failed ({e})", file=sys.stderr)
        return 2

    print(f"OK: archive receipt verified for {archive_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
