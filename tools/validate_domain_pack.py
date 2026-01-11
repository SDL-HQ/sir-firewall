#!/usr/bin/env python3
"""
SIR Firewall — Domain Pack (Suite CSV) Validator

Purpose:
- Keep domain packs curated, versioned, testable, portable (P7 hygiene)
- Prevent schema drift causing silent audit ambiguity

Accepted schemas (minimum):
- required: expected
- required: one of [prompt, prompt_b64]
- optional: id, note, category, any extra columns (ignored)

Rules:
- expected must be one of: allow, block
- prompt/prompt_b64 must be non-empty
- if prompt_b64 is present, it must be valid base64 (decodable)
"""

from __future__ import annotations

import argparse
import base64
import csv
import glob
import sys
from pathlib import Path
from typing import List, Tuple


ALLOWED_EXPECTED = {"allow", "block"}


def _is_base64(s: str) -> bool:
    try:
        # validate=True rejects non-b64 chars; padding is handled
        base64.b64decode(s.encode("utf-8"), validate=True)
        return True
    except Exception:
        return False


def validate_file(path: Path) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    if not path.exists() or not path.is_file():
        return False, [f"Missing file: {path}"]

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return False, [f"{path}: missing header row"]

        fields = [h.strip() for h in reader.fieldnames if h is not None]
        field_set = set(fields)

        if "expected" not in field_set:
            errors.append(f"{path}: missing required column: expected")

        has_prompt = "prompt" in field_set
        has_prompt_b64 = "prompt_b64" in field_set

        if not has_prompt and not has_prompt_b64:
            errors.append(f"{path}: missing required column: prompt OR prompt_b64")

        # Validate rows
        row_count = 0
        for i, row in enumerate(reader, start=2):  # header is line 1
            row_count += 1

            expected = (row.get("expected") or "").strip().lower()
            if expected not in ALLOWED_EXPECTED:
                errors.append(
                    f"{path}: line {i}: expected must be one of {sorted(ALLOWED_EXPECTED)} (got: {expected!r})"
                )

            prompt_val = (row.get("prompt") or "").strip() if has_prompt else ""
            prompt_b64_val = (row.get("prompt_b64") or "").strip() if has_prompt_b64 else ""

            if has_prompt and has_prompt_b64:
                if not prompt_val and not prompt_b64_val:
                    errors.append(f"{path}: line {i}: prompt and prompt_b64 are both empty")
            elif has_prompt:
                if not prompt_val:
                    errors.append(f"{path}: line {i}: prompt is empty")
            elif has_prompt_b64:
                if not prompt_b64_val:
                    errors.append(f"{path}: line {i}: prompt_b64 is empty")

            if has_prompt_b64 and prompt_b64_val:
                if not _is_base64(prompt_b64_val):
                    errors.append(f"{path}: line {i}: prompt_b64 is not valid base64")

        if row_count == 0:
            errors.append(f"{path}: no data rows found")

    return (len(errors) == 0), errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="Validate a single CSV file")
    ap.add_argument("--glob", dest="glob_pattern", help="Validate multiple CSVs via glob (e.g. tests/domain_packs/*.csv)")
    args = ap.parse_args()

    targets: List[Path] = []
    if args.file:
        targets.append(Path(args.file))
    if args.glob_pattern:
        for p in glob.glob(args.glob_pattern):
            targets.append(Path(p))

    if not targets:
        print("ERROR: provide --file and/or --glob", file=sys.stderr)
        return 2

    all_ok = True
    for t in targets:
        ok, errs = validate_file(t)
        if ok:
            print(f"OK: {t}")
        else:
            all_ok = False
            for e in errs:
                print(f"ERROR: {e}", file=sys.stderr)

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
