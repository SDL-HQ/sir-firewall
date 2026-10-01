#!/usr/bin/env python3
"""
Report what a third party actually gets when they verify the published archive.

Published figures about the archive have been hand-counted, and hand-counted
figures drift. This runs the repository's own verifiers over every published run
archive and reports the exit-code distribution, so any claim about the archive
can be re-derived by anyone with a clone and no network.

It writes nothing and changes nothing. Output goes to stdout, or to a JSON file
with --json-out.

Verification is three-valued, not two. A record that cannot be checked and a
record that fails are different results and are reported separately.

Runtime is roughly two subprocesses per archive, a few minutes for the full set.

Usage:
    python3 tools/archive_verification_report.py
    python3 tools/archive_verification_report.py --json-out /tmp/archive.json
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

CERTIFICATE_EXIT_MEANINGS = {
    0: "verified",
    1: "signing key not in registry",
    2: "required fields missing",
    3: "payload hash mismatch",
    4: "signature not valid base64",
    5: "SIGNATURE VERIFICATION FAILED",
    6: "signature verification error",
    7: "ledger binding failed",
    9: "ledger binding not checked (certificate carries no run identity)",
}

RECEIPT_EXIT_MEANINGS = {
    0: "verified",
    1: "receipt invalid",
    2: "archive incomplete or signature failed",
    3: "no archive receipt (legacy archive)",
}


def _exit_code(command: list[str]) -> tuple[int, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    first_error = ""
    for line in result.stderr.splitlines():
        if line.startswith(("ERROR", "NOT CHECKED")):
            first_error = line.strip()
            break
    return result.returncode, first_error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-derive the published archive verification figures."
    )
    parser.add_argument(
        "--runs-dir",
        default="proofs/runs",
        help="Directory of per-run archives. Default: proofs/runs",
    )
    parser.add_argument("--json-out", default=None, help="Also write the full result as JSON.")
    args = parser.parse_args()

    runs_dir = Path(args.runs_dir)
    if not runs_dir.is_dir():
        print(f"ERROR: no run archive directory at {runs_dir}", file=sys.stderr)
        return 2

    records = []
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        certificate = run_dir / "audit.json"
        manifest = run_dir / "manifest.json"
        if not certificate.is_file() and not manifest.is_file():
            continue

        record = {"run_id": run_dir.name}

        if certificate.is_file():
            code, detail = _exit_code(
                [sys.executable, "tools/verify_certificate.py", str(certificate)]
            )
            record["certificate_exit"] = code
            record["certificate_meaning"] = CERTIFICATE_EXIT_MEANINGS.get(code, "unmapped exit code")
            record["certificate_detail"] = detail
        else:
            record["certificate_exit"] = None
            record["certificate_meaning"] = "no certificate in archive"

        if manifest.is_file():
            code, detail = _exit_code(
                [sys.executable, "tools/verify_archive_receipt.py", str(run_dir)]
            )
            record["receipt_exit"] = code
            record["receipt_meaning"] = RECEIPT_EXIT_MEANINGS.get(code, "unmapped exit code")
            record["receipt_detail"] = detail
        else:
            record["receipt_exit"] = None
            record["receipt_meaning"] = "no manifest in archive"

        records.append(record)

    def tally(field: str) -> list[tuple]:
        counts: dict = {}
        for record in records:
            counts[record[field]] = counts.get(record[field], 0) + 1
        return sorted(counts.items(), key=lambda item: -item[1])

    total = len(records)
    print(f"Published run archives examined: {total}")
    print(f"Source: {runs_dir}\n")

    print("Certificate verification (tools/verify_certificate.py)")
    for code, count in tally("certificate_exit"):
        label = CERTIFICATE_EXIT_MEANINGS.get(code, "no certificate" if code is None else "unmapped")
        print(f"  exit {str(code):>4}  {count:>4}  {label}")

    print("\nArchive receipt verification (tools/verify_archive_receipt.py)")
    for code, count in tally("receipt_exit"):
        label = RECEIPT_EXIT_MEANINGS.get(code, "no manifest" if code is None else "unmapped")
        print(f"  exit {str(code):>4}  {count:>4}  {label}")

    failing = [r for r in records if r["certificate_exit"] not in (0, 9, None)]
    if failing:
        print(f"\nCertificates that FAIL verification ({len(failing)}):")
        for record in failing:
            print(f"  {record['run_id']}  exit {record['certificate_exit']}  {record['certificate_detail']}")

    incomplete = [r for r in records if r["receipt_exit"] == 2]
    if incomplete:
        print(f"\nArchives whose receipt does not verify ({len(incomplete)}):")
        for record in incomplete[:5]:
            print(f"  {record['run_id']}  {record['receipt_detail']}")
        if len(incomplete) > 5:
            print(f"  ... and {len(incomplete) - 5} more; use --json-out for the full list")

    if args.json_out:
        payload = {
            "runs_dir": str(runs_dir),
            "total_archives": total,
            "records": records,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nOK: wrote full result to {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
