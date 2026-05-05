#!/usr/bin/env python3
"""Validate workflow run-selection tuple against canonical registries."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUN_SELECTION_REGISTRY = ROOT / "spec" / "execution" / "run_selection_registry.v1.json"
PACK_REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"top-level JSON object required: {path}")
    return payload


def validate_run_selection(*, operation: str, mode: str, provider: str, model: str, pack_id: str) -> None:
    registry = _load_json(RUN_SELECTION_REGISTRY)
    pack_registry = _load_json(PACK_REGISTRY)

    allowed_operations = registry.get("allowed_operations") or []
    if operation not in allowed_operations:
        raise ValueError(f"invalid operation {operation!r}; allowed_operations={allowed_operations}")

    modes_by_operation = registry.get("modes_by_operation") or {}
    allowed_modes = modes_by_operation.get(operation) or []
    if mode not in allowed_modes:
        raise ValueError(f"invalid mode {mode!r} for operation {operation!r}; allowed={allowed_modes}")

    providers = registry.get("providers") or []
    if provider not in providers:
        raise ValueError(f"invalid provider {provider!r}; allowed providers={providers}")

    models_by_provider = registry.get("models_by_provider") or {}
    allowed_models = models_by_provider.get(provider) or []
    if model not in allowed_models:
        raise ValueError(
            f"invalid model {model!r} for provider {provider!r}; allowed models={allowed_models}"
        )

    workflow_pack_ids = registry.get("workflow_pack_ids") or []
    if pack_id not in workflow_pack_ids:
        raise ValueError(f"pack_id {pack_id!r} not allowed for workflow; workflow_pack_ids={workflow_pack_ids}")

    packs = pack_registry.get("packs")
    if not isinstance(packs, list):
        raise ValueError("invalid pack registry: packs must be an array")

    pack = next((p for p in packs if isinstance(p, dict) and p.get("pack_id") == pack_id), None)
    if not pack:
        raise ValueError(f"pack_id {pack_id!r} not found in pack registry")

    if pack.get("status") != "active":
        raise ValueError(f"pack_id {pack_id!r} must be active for workflow; status={pack.get('status')!r}")

    if pack.get("schema") != "csv_single_turn_v1":
        raise ValueError(
            f"pack_id {pack_id!r} must use schema 'csv_single_turn_v1' for audit/live workflow; "
            f"schema={pack.get('schema')!r}"
        )

    suite_path = str(pack.get("suite_path") or "").strip()
    if not suite_path:
        raise ValueError(f"pack_id {pack_id!r} missing suite_path")
    abs_suite = ROOT / suite_path
    if not abs_suite.is_file():
        raise ValueError(f"pack_id {pack_id!r} suite_path does not exist: {suite_path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--operation", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--provider", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--pack", required=True)
    args = ap.parse_args()

    try:
        validate_run_selection(
            operation=args.operation.strip(),
            mode=args.mode.strip(),
            provider=args.provider.strip(),
            model=args.model.strip(),
            pack_id=args.pack.strip(),
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("OK: run selection validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
