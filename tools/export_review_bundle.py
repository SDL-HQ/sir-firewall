#!/usr/bin/env python3
"""Export a deterministic local review bundle from explicit SIR evidence paths."""

from __future__ import annotations

import argparse
import json
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


def _read_json_file(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"ERROR: malformed JSON: {path.as_posix()} ({exc})") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"ERROR: expected JSON object at: {path.as_posix()}")
    return data


def _render_report_section(title: str, source_path: str, payload: dict, keys: Iterable[str]) -> list[str]:
    lines = [f"## {title}", "", f"Source: `{source_path}`", ""]
    for key in keys:
        value = payload.get(key)
        lines.append(f"- `{key}`: `{json.dumps(value, ensure_ascii=False)}`")
    lines.append("")
    return lines


def _write_human_audit_report(out: Path, run_id: str | None) -> None:
    latest_audit_rel = "proofs/latest-audit.json"
    latest_run_rel = "docs/latest-run.json"
    latest_audit = _read_json_file(out / latest_audit_rel)
    latest_run = _read_json_file(out / latest_run_rel)

    lines = [
        "# HUMAN_AUDIT_REPORT",
        "",
        "This file is a deterministic, static restatement of already copied bundle artefacts.",
        "No verdicts are recomputed here.",
        "",
        "Semantics note:",
        "- `latest-audit.json` is latest passing proof material.",
        "- `latest-run.json` is most recent run status material.",
        "- These are distinct surfaces and can differ.",
        "",
        "Authority note:",
        "- Source artefacts remain authoritative.",
        "- This report is convenience-only.",
        "",
    ]

    lines.extend(
        _render_report_section(
            title="Latest passing proof",
            source_path=latest_audit_rel,
            payload=latest_audit,
            keys=(
                "result",
                "proof_class",
                "date",
                "timestamp_utc",
                "suite_name",
                "suite_path",
                "model",
                "provider",
                "jailbreaks_leaked",
                "harmless_blocked",
                "commit_sha",
                "payload_hash",
                "trust_fingerprint",
            ),
        )
    )
    lines.extend(
        _render_report_section(
            title="Latest run status",
            source_path=latest_run_rel,
            payload=latest_run,
            keys=(
                "status",
                "timestamp_utc",
                "run_id",
                "sha",
                "source",
            ),
        )
    )

    if run_id:
        run_manifest_rel = f"proofs/runs/{run_id}/manifest.json"
        run_manifest = _read_json_file(out / run_manifest_rel)
        lines.extend(
            _render_report_section(
                title="Selected run manifest",
                source_path=run_manifest_rel,
                payload=run_manifest,
                keys=(
                    "run_id",
                    "run_timestamp_utc",
                    "result",
                    "proof_class",
                    "archive_receipt_path",
                    "audit_path",
                ),
            )
        )

    (out / "HUMAN_AUDIT_REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Copy explicit SIR evidence files into a local review bundle. "
            "No discovery, aggregation, scoring, or derived evidence generation is performed."
        ),
        epilog=(
            "Example: python3 tools/export_review_bundle.py --out /tmp/sir-review-bundle\n"
            "Optional run copy: --run-id <run_id> copies proofs/runs/<run_id>/ as-is."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--out",
        required=True,
        help="Output directory for the local review bundle (must be a directory path).",
    )
    ap.add_argument(
        "--run-id",
        help="Optional explicit run id to include from proofs/runs/<run_id>/",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output directory when non-empty.",
    )
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_dir = Path(args.out).resolve()

    if out_dir.exists() and not out_dir.is_dir():
        raise SystemExit(f"ERROR: --out must be a directory path, but a non-directory already exists: {out_dir}")

    if out_dir.exists() and any(out_dir.iterdir()) and not args.force:
        raise SystemExit(f"ERROR: output directory is non-empty: {out_dir} (use --force to overwrite)")

    if out_dir.exists() and args.force:
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for rel in EXPLICIT_FILES:
        _copy_file(repo_root, out_dir, rel)

    if args.run_id:
        run_rel = f"proofs/runs/{args.run_id}"
        run_dir = repo_root / run_rel
        if not run_dir.exists() or not run_dir.is_dir():
            raise SystemExit(
                f"ERROR: requested --run-id directory not found: {run_rel} "
                "(omit --run-id to export only baseline review artifacts)"
            )
        _copy_tree(repo_root, out_dir, run_rel)

    _write_manifest(out_dir, EXPLICIT_FILES, args.run_id)
    _write_human_audit_report(out_dir, args.run_id)

    print(f"OK: exported B9 local review bundle -> {out_dir}")
    print(f"OK: included {len(EXPLICIT_FILES)} explicit files")
    if args.run_id:
        print(f"OK: included explicit run directory proofs/runs/{args.run_id}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
