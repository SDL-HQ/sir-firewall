from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

import importlib.util

_spec = importlib.util.spec_from_file_location("validate_run_selection", ROOT / "tools" / "validate_run_selection.py")
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_module)
validate_run_selection = _module.validate_run_selection


def test_valid_xai_selection_passes() -> None:
    validate_run_selection(
        operation="run",
        mode="audit",
        provider="xai",
        model="grok-4-1-fast",
        pack_id="generic_safety",
    )


def test_valid_openai_selection_passes() -> None:
    validate_run_selection(
        operation="benchmark",
        mode="live",
        provider="openai",
        model="gpt-4.1-mini",
        pack_id="support_operator_override",
    )


def test_invalid_provider_fails() -> None:
    with pytest.raises(ValueError, match="invalid provider"):
        validate_run_selection(
            operation="run",
            mode="audit",
            provider="anthropic",
            model="claude-3-7-sonnet",
            pack_id="generic_safety",
        )


def test_invalid_model_provider_combo_fails() -> None:
    with pytest.raises(ValueError, match="invalid model"):
        validate_run_selection(
            operation="run",
            mode="audit",
            provider="openai",
            model="grok-4-1-fast",
            pack_id="generic_safety",
        )


def test_invalid_pack_fails() -> None:
    with pytest.raises(ValueError, match="not allowed for workflow"):
        validate_run_selection(
            operation="run",
            mode="audit",
            provider="xai",
            model="grok-4-1-fast",
            pack_id="scenario_injection_chain",
        )


def test_scenario_pack_rejected_for_workflow_path() -> None:
    with pytest.raises(ValueError, match="not allowed for workflow"):
        validate_run_selection(
            operation="benchmark",
            mode="audit",
            provider="xai",
            model="grok-3-beta",
            pack_id="scenario_tool_injection",
        )


def test_workflow_pack_ids_resolve_to_active_csv_packs_and_paths_exist() -> None:
    run_registry = json.loads((ROOT / "spec" / "execution" / "run_selection_registry.v1.json").read_text(encoding="utf-8"))
    pack_registry = json.loads((ROOT / "spec" / "packs" / "pack_registry.v1.json").read_text(encoding="utf-8"))
    pack_map = {p.get("pack_id"): p for p in pack_registry.get("packs", []) if isinstance(p, dict)}

    for pack_id in run_registry["workflow_pack_ids"]:
        assert pack_id in pack_map, f"workflow pack_id missing from pack registry: {pack_id}"
        pack = pack_map[pack_id]
        assert pack.get("status") == "active", f"workflow pack must be active: {pack_id}"
        assert pack.get("schema") == "csv_single_turn_v1", f"workflow pack must be csv_single_turn_v1: {pack_id}"
        suite_path = str(pack.get("suite_path") or "").strip()
        assert suite_path, f"workflow pack missing suite_path: {pack_id}"
        assert (ROOT / suite_path).is_file(), f"workflow pack suite_path missing file: {pack_id} -> {suite_path}"


def test_workflow_dropdown_options_match_registry_choices() -> None:
    text = (ROOT / ".github/workflows/audit-and-sign.yml").read_text(encoding="utf-8")

    run_registry = json.loads((ROOT / "spec" / "execution" / "run_selection_registry.v1.json").read_text(encoding="utf-8"))
    expected_providers = run_registry["providers"]
    expected_packs = run_registry["workflow_pack_ids"]
    expected_models = run_registry["models_by_provider"]["xai"] + run_registry["models_by_provider"]["openai"]

    for value in expected_providers + expected_packs + expected_models:
        assert f"- {value}" in text
