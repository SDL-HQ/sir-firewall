#!/usr/bin/env python3
"""Validate scenario JSON pack schema (scenario_json_v1)."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any, List, Tuple

ALLOWED_EXPECTED = {"allow", "block"}
ALLOWED_ROLES = {"user", "system", "assistant"}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read file: {path} ({exc})") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("scenario pack must be a top-level JSON object")
    return data


def _decode_b64_utf8(value: str) -> Tuple[bool, str]:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return False, ""
    return True, decoded.decode("utf-8", errors="replace")


def validate_scenario(path: Path) -> List[str]:
    errors: List[str] = []
    data = _load_json(path)

    scenario_id = data.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        errors.append("scenario_id must be a non-empty string")

    turns = data.get("turns")
    if not isinstance(turns, list) or not turns:
        errors.append("turns must be a non-empty array")
        return errors

    seen_turn_ids: set[str] = set()
    for idx, turn in enumerate(turns):
        prefix = f"turns[{idx}]"
        if not isinstance(turn, dict):
            errors.append(f"{prefix} must be an object")
            continue

        turn_id = turn.get("turn_id")
        if not isinstance(turn_id, str) or not turn_id.strip():
            errors.append(f"{prefix}.turn_id must be a non-empty string")
        elif turn_id in seen_turn_ids:
            errors.append(f"duplicate turn_id: {turn_id}")
        else:
            seen_turn_ids.add(turn_id)

        expected = str(turn.get("expected") or "").strip().lower()
        if expected not in ALLOWED_EXPECTED:
            errors.append(f"{prefix}.expected must be one of {sorted(ALLOWED_EXPECTED)}")

        role = str(turn.get("role") or "user").strip().lower()
        if role not in ALLOWED_ROLES:
            errors.append(f"{prefix}.role must be one of {sorted(ALLOWED_ROLES)}")

        content = turn.get("content")
        content_b64 = turn.get("content_b64")
        has_content = isinstance(content, str) and bool(content.strip())
        has_content_b64 = isinstance(content_b64, str) and bool(content_b64.strip())
        if has_content == has_content_b64:
            errors.append(f"{prefix} must contain exactly one of content or content_b64")
            continue

        if has_content_b64:
            ok, _ = _decode_b64_utf8(str(content_b64))
            if not ok:
                errors.append(f"{prefix}.content_b64 must be valid base64")

    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="Path to scenario pack JSON")
    args = ap.parse_args()

    target = Path(args.file)
    try:
        errors = validate_scenario(target)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 2

    print(f"OK: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
