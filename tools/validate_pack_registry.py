#!/usr/bin/env python3
"""Validate pack registry metadata (v1)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ALLOWED_SCHEMA = {"csv_single_turn_v1"}
ALLOWED_RISK_CLASS = {"baseline", "encoded_high_risk", "domain"}
ALLOWED_STATUS = {"active", "draft", "deprecated"}
REQUIRED_PACK_FIELDS = {
    "pack_id",
    "schema",
    "risk_class",
    "status",
    "version",
    "suite_path",
    "hash_binds_to",
}


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
        raise ValueError("registry must be a top-level JSON object")
    return data


def validate_registry(path: Path) -> list[str]:
    errors: list[str] = []

    data = _load_json(path)

    if data.get("registry_version") != "v1":
        errors.append("registry_version must be present and exactly 'v1'")

    packs = data.get("packs")
    if not isinstance(packs, list):
        errors.append("packs must be a list")
        return errors

    seen_pack_ids: set[str] = set()
    repo_root = Path.cwd()

    for idx, pack in enumerate(packs):
        prefix = f"packs[{idx}]"
        if not isinstance(pack, dict):
            errors.append(f"{prefix} must be an object")
            continue

        missing = sorted(REQUIRED_PACK_FIELDS - set(pack.keys()))
        if missing:
            errors.append(f"{prefix} missing required fields: {', '.join(missing)}")
            continue

        pack_id = pack.get("pack_id")
        if not isinstance(pack_id, str) or not pack_id:
            errors.append(f"{prefix}.pack_id must be a non-empty string")
        elif pack_id in seen_pack_ids:
            errors.append(f"duplicate pack_id: {pack_id}")
        else:
            seen_pack_ids.add(pack_id)

        schema = pack.get("schema")
        if schema not in ALLOWED_SCHEMA:
            errors.append(f"{prefix}.schema must be one of {sorted(ALLOWED_SCHEMA)}")

        risk_class = pack.get("risk_class")
        if risk_class not in ALLOWED_RISK_CLASS:
            errors.append(f"{prefix}.risk_class must be one of {sorted(ALLOWED_RISK_CLASS)}")

        status = pack.get("status")
        if status not in ALLOWED_STATUS:
            errors.append(f"{prefix}.status must be one of {sorted(ALLOWED_STATUS)}")

        suite_path = pack.get("suite_path")
        if not isinstance(suite_path, str) or not suite_path:
            errors.append(f"{prefix}.suite_path must be a non-empty string")
        elif not (repo_root / suite_path).is_file():
            errors.append(f"{prefix}.suite_path does not exist: {suite_path}")

        doc_path = pack.get("doc_path")
        if doc_path is not None:
            if not isinstance(doc_path, str) or not doc_path:
                errors.append(f"{prefix}.doc_path must be a non-empty string when provided")
            elif not (repo_root / doc_path).is_file():
                errors.append(f"{prefix}.doc_path does not exist: {doc_path}")

        if pack.get("hash_binds_to") != "decoded_prompt_content":
            errors.append(f"{prefix}.hash_binds_to must equal 'decoded_prompt_content'")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="Path to pack registry JSON")
    args = parser.parse_args()

    target = Path(args.file)
    try:
        errors = validate_registry(target)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2

    print(f"OK: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
