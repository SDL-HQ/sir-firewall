#!/usr/bin/env python3
"""Export a deterministic SIR run-archive bundle for Tier B retention."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REQUIRED_RUN_FILES = ("audit.json", "manifest.json", "archive_receipt.json")


def _utc_now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _read_json_object(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object in {path}, got {type(obj).__name__}")
    return obj


def _resolve_run_path(run_id: Optional[str], run_path: Optional[str]) -> Path:
    if bool(run_id) == bool(run_path):
        raise ValueError("pass exactly one of --run-id or --run-path")
    if run_id:
        path = Path("proofs") / "runs" / run_id
    else:
        path = Path(run_path or "")
    return path.resolve()


def _collect_files(root: Path) -> List[Path]:
    files = [p for p in root.rglob("*") if p.is_file()]
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def _compute_bundle_hash(export_root: Path) -> str:
    lines: List[str] = []
    for path in _collect_files(export_root):
        rel = path.relative_to(export_root).as_posix()
        if rel in {"bundle_manifest.json", "bundle.tar"}:
            continue
        lines.append(f"{rel}:{_sha256_file(path)}")
    return _sha256_bytes("\n".join(lines).encode("utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_run_tree(src_run_dir: Path, dst_run_dir: Path) -> None:
    shutil.copytree(src_run_dir, dst_run_dir, copy_function=shutil.copy2, dirs_exist_ok=True)


def _assert_byte_preserving_copy(src_run_dir: Path, dst_run_dir: Path) -> None:
    src_files = _collect_files(src_run_dir)
    dst_files = _collect_files(dst_run_dir)

    src_rel = [p.relative_to(src_run_dir).as_posix() for p in src_files]
    dst_rel = [p.relative_to(dst_run_dir).as_posix() for p in dst_files]

    if src_rel != dst_rel:
        raise SystemExit("ERROR: exported file listing differs from source run folder")

    for rel in src_rel:
        src = src_run_dir / rel
        dst = dst_run_dir / rel
        if src.stat().st_size != dst.stat().st_size:
            raise SystemExit(f"ERROR: size mismatch after export copy for {rel}")
        if _sha256_file(src) != _sha256_file(dst):
            raise SystemExit(f"ERROR: byte mismatch after export copy for {rel}")


def _build_bundle_manifest(export_root: Path, run_dir: Path) -> Dict[str, Any]:
    manifest = _read_json_object(run_dir / "manifest.json")
    receipt_path = run_dir / "archive_receipt.json"
    receipt_bytes = receipt_path.read_bytes()
    receipt = _read_json_object(receipt_path)

    source_repo = receipt.get("repository") or manifest.get("repository") or ""
    source_commit = receipt.get("commit_sha") or manifest.get("commit_sha") or ""
    source_run_id = manifest.get("run_id") or run_dir.name

    return {
        "bundle_hash": _compute_bundle_hash(export_root),
        "exported_at_utc": _utc_now_z(),
        "receipt_hash": _sha256_bytes(receipt_bytes),
        "source_commit_sha": source_commit,
        "source_repository": source_repo,
        "source_run_id": source_run_id,
    }


def _validate_source_run(run_dir: Path) -> Tuple[Path, str]:
    if not run_dir.exists() or not run_dir.is_dir():
        raise ValueError(f"run folder not found: {run_dir}")
    for name in REQUIRED_RUN_FILES:
        p = run_dir / name
        if not p.exists() or not p.is_file():
            raise ValueError(f"run folder missing required file: {p}")
    manifest = _read_json_object(run_dir / "manifest.json")
    run_id = manifest.get("run_id") if isinstance(manifest.get("run_id"), str) else run_dir.name
    return run_dir, run_id


def _create_deterministic_tar(src_root: Path, tar_path: Path) -> None:
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "w") as tf:
        for src in _collect_files(src_root):
            arcname = src.relative_to(src_root).as_posix()
            info = tf.gettarinfo(str(src), arcname=arcname)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with src.open("rb") as f:
                tf.addfile(info, f)


def _dir_has_contents(path: Path) -> bool:
    try:
        next(path.iterdir())
        return True
    except StopIteration:
        return False


def _prepare_export_root(out_dir: Path, force: bool) -> Path:
    if out_dir.exists() and out_dir.is_file():
        raise SystemExit(f"ERROR: output path is a file: {out_dir}")

    if out_dir.exists() and _dir_has_contents(out_dir) and not force:
        print("ERROR: output path exists; use --force to overwrite")
        raise SystemExit(3)

    if force:
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        tmp_root = Path(tempfile.mkdtemp(prefix=f".export-{out_dir.name}-", dir=str(out_dir.parent)))
        return tmp_root

    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _finalize_export_root(staging_dir: Path, out_dir: Path, force: bool) -> None:
    if not force:
        return

    if out_dir.exists():
        backup = out_dir.parent / f".{out_dir.name}.backup-{os.getpid()}-{int(dt.datetime.now(dt.timezone.utc).timestamp())}"
        out_dir.rename(backup)
        staging_dir.rename(out_dir)
        shutil.rmtree(backup, ignore_errors=True)
        return

    staging_dir.rename(out_dir)


def main() -> int:
    ap = argparse.ArgumentParser(description="Export a deterministic run-archive bundle")
    ap.add_argument("--run-id", help="Run id under proofs/runs/<run_id>")
    ap.add_argument("--run-path", help="Path to proofs/runs/<run_id>")
    ap.add_argument("--out", required=True, help="Output directory path")
    ap.add_argument("--format", choices=("dir", "tar"), default="dir", help="Bundle output format")
    ap.add_argument("--force", action="store_true", help="Overwrite non-empty --out path")
    ap.add_argument("--s3-bucket", help="Optional S3 bucket for upload")
    ap.add_argument("--s3-prefix", default="", help="Optional S3 key prefix")
    args = ap.parse_args()

    try:
        source_run = _resolve_run_path(run_id=args.run_id, run_path=args.run_path)
        source_run, source_run_id = _validate_source_run(source_run)
    except Exception as e:
        raise SystemExit(f"ERROR: {e}")

    out_dir = Path(args.out).resolve()
    staging_out_dir = _prepare_export_root(out_dir, force=bool(args.force))

    bundle_root = staging_out_dir / "proofs" / "runs" / source_run_id
    _copy_run_tree(source_run, bundle_root)
    _assert_byte_preserving_copy(source_run, bundle_root)

    bundle_manifest = _build_bundle_manifest(staging_out_dir, bundle_root)
    _write_json(staging_out_dir / "bundle_manifest.json", bundle_manifest)

    if args.format == "tar":
        tar_path = staging_out_dir / "bundle.tar"
        _create_deterministic_tar(staging_out_dir / "proofs", tar_path)

    _finalize_export_root(staging_out_dir, out_dir, force=bool(args.force))

    if args.s3_bucket:
        try:
            import boto3  # type: ignore
        except Exception:
            raise SystemExit("ERROR: boto3 not installed; S3 upload not available in this environment")

        s3 = boto3.client("s3")
        prefix = args.s3_prefix.strip("/")

        if args.format == "tar":
            targets = [out_dir / "bundle.tar", out_dir / "bundle_manifest.json"]
        else:
            targets = _collect_files(out_dir)

        for src in targets:
            rel = src.relative_to(out_dir).as_posix()
            key = f"{prefix}/{rel}" if prefix else rel
            s3.upload_file(str(src), args.s3_bucket, key)

    print(f"OK: exported run {source_run_id} -> {out_dir}")
    print(f"OK: bundle manifest -> {out_dir / 'bundle_manifest.json'}")
    if args.format == "tar":
        print(f"OK: deterministic tar -> {out_dir / 'bundle.tar'}")
    if args.s3_bucket:
        print(f"OK: uploaded bundle to s3://{args.s3_bucket}/{args.s3_prefix.strip('/')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
