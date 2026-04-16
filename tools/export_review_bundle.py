#!/usr/bin/env python3
"""Export a deterministic local review bundle from explicit SIR evidence paths."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Iterable

EXPLICIT_FILES: tuple[str, ...] = (
    "README.md",
    "RETENTION.md",
    "docs/assurance-kit.md",
    "docs/evaluator-technical-explainer.md",
    "docs/external-technical-review-prep.md",
    "docs/benchmark-cycle.v1.md",
    "docs/d5-benchmark-first-cycle-review.md",
    "docs/compliance-evidence-map.md",
    "docs/latest-run.json",
    "proofs/latest-audit.json",
    "proofs/latest-audit.html",
    "proofs/runs/index.json",
    "proofs/runs/index.html",
    "spec/evidence_contract.v1.json",
    "tools/verify_certificate.py",
    "tools/verify_archive_receipt.py",
    "tools/verify_itgl.py",
)


def _copy_file(root: Path, out: Path, rel: str) -> None:
    src = root / rel
    if not src.exists() or not src.is_file():
        raise SystemExit(f"ERROR: missing required file: {rel}")
    dst = out / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _copy_tree(root: Path, out: Path, rel_dir: str) -> None:
    src = root / rel_dir
    if not src.exists() or not src.is_dir():
        raise SystemExit(f"ERROR: missing required directory: {rel_dir}")
    dst = out / rel_dir
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, copy_function=shutil.copy2)


def _write_manifest(out: Path, included_files: Iterable[str], run_id: str | None) -> None:
    manifest_path = out / "B9_BUNDLE_MANIFEST.txt"
    lines = [
        "SIR B9 local review bundle",
        "",
        "This is a convenience copy of existing repository artifacts.",
        "It does not generate new proof material and does not certify compliance.",
        "",
        "Included explicit files:",
    ]
    lines.extend(f"- {path}" for path in included_files)
    if run_id:
        lines.extend(["", "Included explicit run directory:", f"- proofs/runs/{run_id}/"])
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Copy explicit SIR evidence files into a local review bundle. "
            "No discovery, aggregation, scoring, or derived evidence generation is performed."
        )
    )
    ap.add_argument("--out", required=True, help="Output directory for the local review bundle")
    ap.add_argument(
        "--run-id",
        help="Optional explicit run id to include from proofs/runs/<run_id>/",
    )
    ap.add_argument("--force", action="store_true", help="Overwrite non-empty output directory")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_dir = Path(args.out).resolve()

    if out_dir.exists() and any(out_dir.iterdir()) and not args.force:
        raise SystemExit("ERROR: output directory is non-empty; use --force to overwrite")

    if out_dir.exists() and args.force:
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for rel in EXPLICIT_FILES:
        _copy_file(repo_root, out_dir, rel)

    if args.run_id:
        _copy_tree(repo_root, out_dir, f"proofs/runs/{args.run_id}")

    _write_manifest(out_dir, EXPLICIT_FILES, args.run_id)

    print(f"OK: exported B9 local review bundle -> {out_dir}")
    print(f"OK: included {len(EXPLICIT_FILES)} explicit files")
    if args.run_id:
        print(f"OK: included explicit run directory proofs/runs/{args.run_id}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
