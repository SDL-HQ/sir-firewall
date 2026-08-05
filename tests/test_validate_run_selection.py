from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from sir_firewall.model_selection import (
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    SUPPORTED_MODELS_BY_PROVIDER,
)

ROOT = Path(__file__).resolve().parents[1]
RUN_SELECTION_REGISTRY_PATH = ROOT / "spec" / "execution" / "run_selection_registry.v1.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "audit-and-sign.yml"

_spec = importlib.util.spec_from_file_location("validate_run_selection", ROOT / "tools" / "validate_run_selection.py")
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_module)
validate_run_selection = _module.validate_run_selection


def _load_run_selection_registry() -> dict[str, Any]:
    registry = json.loads(RUN_SELECTION_REGISTRY_PATH.read_text(encoding="utf-8"))
    assert isinstance(registry, dict), (
        "run selection registry must be a JSON object; "
        f"registry carried {type(registry).__name__}: {registry!r}"
    )
    return registry


def _load_workflow_inputs() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), (
        "audit-and-sign workflow must parse as a YAML mapping; "
        f"workflow carried {type(workflow).__name__}: {workflow!r}"
    )
    assert True in workflow, (
        "audit-and-sign workflow is missing the YAML 1.1 boolean True key corresponding to top-level 'on'; "
        f"workflow carried top-level keys: {list(workflow)!r}"
    )

    events = workflow[True]
    assert isinstance(events, dict), (
        "audit-and-sign workflow 'on' surface must be a mapping; "
        f"workflow carried {events!r}"
    )
    assert "workflow_dispatch" in events, (
        "audit-and-sign workflow 'on' surface is missing 'workflow_dispatch'; "
        f"workflow carried events: {list(events)!r}"
    )

    dispatch = events["workflow_dispatch"]
    assert isinstance(dispatch, dict), (
        "audit-and-sign workflow workflow_dispatch surface must be a mapping; "
        f"workflow carried {dispatch!r}"
    )
    assert "inputs" in dispatch, (
        "audit-and-sign workflow workflow_dispatch surface is missing 'inputs'; "
        f"workflow carried keys: {list(dispatch)!r}"
    )

    inputs = dispatch["inputs"]
    assert isinstance(inputs, dict), (
        "audit-and-sign workflow workflow_dispatch inputs must be a mapping; "
        f"workflow carried {inputs!r}"
    )
    return inputs


def _assert_unique_strings(values: Any, *, surface: str, require_non_empty: bool = True) -> list[str]:
    assert isinstance(values, list), (
        f"{surface} must carry a list; {surface} carried {type(values).__name__}: {values!r}"
    )
    if require_non_empty:
        assert values, f"{surface} must carry at least one value; it carried []"

    non_strings = [value for value in values if not isinstance(value, str)]
    assert not non_strings, (
        f"{surface} must carry only strings; {surface} carried non-string value(s): {non_strings!r}"
    )

    duplicates = sorted(value for value, count in Counter(values).items() if count > 1)
    assert not duplicates, f"{surface} carries duplicate value(s): {duplicates!r}"
    return values


def _assert_same_values(
    *, expected: set[str], actual: set[str], expected_surface: str, actual_surface: str
) -> None:
    missing = sorted(expected - actual)
    extras = sorted(actual - expected)
    assert not missing and not extras, (
        f"{actual_surface} differs from {expected_surface}; "
        f"{actual_surface} is missing value(s) present in {expected_surface}: {missing!r}; "
        f"{actual_surface} carries extra value(s) absent from {expected_surface}: {extras!r}"
    )


def _workflow_choice(inputs: dict[str, Any], input_name: str) -> dict[str, Any]:
    assert input_name in inputs, (
        f"audit-and-sign workflow inputs surface is missing {input_name!r}; "
        f"workflow carried inputs: {sorted(inputs)!r}"
    )
    choice = inputs[input_name]
    assert isinstance(choice, dict), (
        f"audit-and-sign workflow input {input_name!r} must be a mapping; workflow carried {choice!r}"
    )
    assert "options" in choice, (
        f"audit-and-sign workflow input {input_name!r} is missing 'options'; "
        f"workflow carried keys: {sorted(choice)!r}"
    )
    assert "default" in choice, (
        f"audit-and-sign workflow input {input_name!r} is missing 'default'; "
        f"workflow carried keys: {sorted(choice)!r}"
    )
    _assert_unique_strings(
        choice["options"], surface=f"audit-and-sign workflow {input_name!r} options"
    )
    return choice


def test_valid_xai_selection_passes() -> None:
    validate_run_selection(
        operation="run",
        mode="audit",
        provider="xai",
        model="grok-4.3",
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
            model="grok-4.3",
            pack_id="generic_safety",
        )


def test_invalid_pack_fails() -> None:
    with pytest.raises(ValueError, match="not allowed for workflow"):
        validate_run_selection(
            operation="run",
            mode="audit",
            provider="xai",
            model="grok-4.3",
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
    run_registry = _load_run_selection_registry()
    pack_registry = json.loads((ROOT / "spec" / "packs" / "pack_registry.v1.json").read_text(encoding="utf-8"))
    pack_map = {p.get("pack_id"): p for p in pack_registry.get("packs", []) if isinstance(p, dict)}

    for pack_id in run_registry["workflow_pack_ids"]:
        assert pack_id in pack_map, f"pack registry is missing workflow pack value: {pack_id!r}"
        pack = pack_map[pack_id]
        assert pack.get("status") == "active", (
            f"pack registry carries non-active workflow pack value: {pack_id!r}; status={pack.get('status')!r}"
        )
        assert pack.get("schema") == "csv_single_turn_v1", (
            f"pack registry carries workflow pack value {pack_id!r} with unexpected schema: {pack.get('schema')!r}"
        )
        suite_path = str(pack.get("suite_path") or "").strip()
        assert suite_path, f"pack registry workflow pack value {pack_id!r} is missing suite_path"
        assert (ROOT / suite_path).is_file(), (
            f"pack registry workflow pack value {pack_id!r} carries missing suite_path file: {suite_path!r}"
        )


def test_run_selection_registry_is_well_formed() -> None:
    registry = _load_run_selection_registry()

    providers = _assert_unique_strings(
        registry.get("providers"), surface="run selection registry 'providers'"
    )

    models_by_provider = registry.get("models_by_provider")
    assert isinstance(models_by_provider, dict), (
        "run selection registry 'models_by_provider' must carry a mapping; registry carried "
        f"{type(models_by_provider).__name__}: {models_by_provider!r}"
    )
    non_string_provider_keys = [
        provider for provider in models_by_provider if not isinstance(provider, str)
    ]
    assert not non_string_provider_keys, (
        "run selection registry 'models_by_provider' must carry only string provider keys; "
        f"registry carried non-string key(s): {non_string_provider_keys!r}"
    )

    _assert_same_values(
        expected=set(providers),
        actual=set(models_by_provider),
        expected_surface="run selection registry 'providers'",
        actual_surface="run selection registry 'models_by_provider' keys",
    )

    model_owners: dict[str, list[str]] = {}
    for provider in providers:
        models = _assert_unique_strings(
            models_by_provider[provider],
            surface=f"run selection registry 'models_by_provider[{provider}]'",
        )
        for model in models:
            model_owners.setdefault(model, []).append(provider)

    multiply_authorised = {
        model: owners for model, owners in sorted(model_owners.items()) if len(owners) > 1
    }
    assert not multiply_authorised, (
        "run selection registry carries model value(s) under more than one provider: "
        f"{multiply_authorised!r}"
    )

    _assert_unique_strings(
        registry.get("workflow_pack_ids"),
        surface="run selection registry 'workflow_pack_ids'",
    )


def test_registry_matches_model_selection_authorisation() -> None:
    registry = _load_run_selection_registry()
    registry_providers = set(registry["providers"])
    model_selection_providers = set(SUPPORTED_MODELS_BY_PROVIDER)

    _assert_same_values(
        expected=registry_providers,
        actual=model_selection_providers,
        expected_surface="run selection registry providers",
        actual_surface="model_selection SUPPORTED_MODELS_BY_PROVIDER keys",
    )

    for provider in sorted(registry_providers):
        _assert_same_values(
            expected=set(registry["models_by_provider"][provider]),
            actual=set(SUPPORTED_MODELS_BY_PROVIDER[provider]),
            expected_surface=f"run selection registry models for provider {provider!r}",
            actual_surface=(
                "model_selection SUPPORTED_MODELS_BY_PROVIDER models "
                f"for provider {provider!r}"
            ),
        )


def test_registry_matches_workflow_dropdown_options() -> None:
    registry = _load_run_selection_registry()
    inputs = _load_workflow_inputs()

    provider_choice = _workflow_choice(inputs, "provider")
    model_choice = _workflow_choice(inputs, "model")
    pack_choice = _workflow_choice(inputs, "pack")

    registry_models = {
        model for models in registry["models_by_provider"].values() for model in models
    }

    _assert_same_values(
        expected=set(registry["providers"]),
        actual=set(provider_choice["options"]),
        expected_surface="run selection registry providers",
        actual_surface="audit-and-sign workflow provider options",
    )
    _assert_same_values(
        expected=registry_models,
        actual=set(model_choice["options"]),
        expected_surface="run selection registry model union",
        actual_surface="audit-and-sign workflow model options",
    )
    _assert_same_values(
        expected=set(registry["workflow_pack_ids"]),
        actual=set(pack_choice["options"]),
        expected_surface="run selection registry workflow_pack_ids",
        actual_surface="audit-and-sign workflow pack options",
    )


def test_workflow_defaults_are_authorised_and_match_local_defaults() -> None:
    registry = _load_run_selection_registry()
    inputs = _load_workflow_inputs()

    provider_default = _workflow_choice(inputs, "provider")["default"]
    model_default = _workflow_choice(inputs, "model")["default"]
    pack_default = _workflow_choice(inputs, "pack")["default"]

    assert provider_default in registry["providers"], (
        "audit-and-sign workflow provider default carries value absent from run selection "
        f"registry providers: {provider_default!r}"
    )
    assert model_default in registry["models_by_provider"][provider_default], (
        "audit-and-sign workflow model default carries value absent from run selection "
        f"registry models for provider {provider_default!r}: {model_default!r}"
    )
    assert pack_default in registry["workflow_pack_ids"], (
        "audit-and-sign workflow pack default carries value absent from run selection "
        f"registry workflow_pack_ids: {pack_default!r}"
    )
    assert provider_default == DEFAULT_PROVIDER, (
        "audit-and-sign workflow provider default differs from model_selection "
        f"DEFAULT_PROVIDER; workflow carries {provider_default!r}, "
        f"model_selection carries {DEFAULT_PROVIDER!r}"
    )
    assert model_default == DEFAULT_MODEL, (
        "audit-and-sign workflow model default differs from model_selection DEFAULT_MODEL; "
        f"workflow carries {model_default!r}, model_selection carries {DEFAULT_MODEL!r}"
    )
