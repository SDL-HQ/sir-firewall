import argparse
import importlib.util
import json
import hashlib
from pathlib import Path

from sir_firewall import core, validate_sir


def _load_red_team_suite_module():
    module_path = Path(__file__).resolve().parents[1] / "red_team_suite.py"
    spec = importlib.util.spec_from_file_location("red_team_suite", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_main(runner) -> int:
    """Run the suite runner and return its exit code.

    Since 7 October 2026 the runner exits 2 when no prompt reached content
    evaluation, so a caller checking only the exit status can no longer mistake
    an unassessed run for a clean one.
    """
    try:
        runner.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def test_selected_pack_id_controls_enforcement_context(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "pci_payments", "1.0.0", "csv_single_turn_v1", "pci_payments"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="audit",
            pack="pci_payments",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
        ),
    )

    rts.main()

    ledger_path = tmp_path / "proofs" / "itgl_ledger.jsonl"
    first_entry = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[0])
    assert first_entry["domain_pack"] == "pci_payments"


def test_run_summary_flags_use_effective_pack_context(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "pci_payments", "1.0.0", "csv_single_turn_v1", "pci_payments"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="audit",
            pack="pci_payments",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
        ),
    )
    def _fake_load_domain_pack(pack_id=None):
        return {
            "pack_id": pack_id or "generic_safety",
            "flags": {"CRYPTO_ENFORCED": True, "CHECKSUM_ENFORCED": False},
        }

    monkeypatch.setattr(rts, "load_domain_pack", _fake_load_domain_pack)
    monkeypatch.setattr(core, "load_domain_pack", _fake_load_domain_pack)

    exit_code = _run_main(rts)

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    # This fixture's single row reaches a systemic reset, so nothing was
    # content-evaluated. That was always true; before 7 October 2026 the run
    # exited 0 and said nothing about it. Asserted here so the fixture's nature
    # is explicit rather than incidental.
    assert summary["content_evaluated"] == 0
    assert exit_code == 2
    assert summary["selected_pack_id"] == "pci_payments"
    assert summary["effective_pack_id"] == "pci_payments"
    assert summary["pack_id"] == "pci_payments"
    assert summary["selected_pack_version"] == "1.0.0"
    assert summary["flags"] == {"CRYPTO_ENFORCED": True, "CHECKSUM_ENFORCED": False}
    assert summary["governance_scope"] == "deployment"
    assert summary["crypto_enforced"] is True


def test_run_summary_separates_selected_and_effective_pack_when_selection_is_implicit(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "", "", "csv_single_turn_v1", ""),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="audit",
            pack=None,
            suite=str(suite_path),
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
        ),
    )

    rts.main()

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["selected_pack_id"] == ""
    assert summary["effective_pack_id"] == "generic_safety"
    assert summary["pack_id"] == "generic_safety"


def test_run_summary_effective_pack_falls_back_to_selected_pack_when_verdict_omits_domain_pack(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "support_operator_override", "1.0.0", "csv_single_turn_v1", "support_operator_override"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="audit",
            pack="support_operator_override",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
        ),
    )
    monkeypatch.setattr(
        rts,
        "validate_sir",
        lambda *_args, **_kwargs: {"status": "PASS", "reason": "clean", "domain_pack": ""},
    )

    rts.main()

    ledger_path = tmp_path / "proofs" / "itgl_ledger.jsonl"
    first_entry = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[0])
    assert first_entry["domain_pack"] == "support_operator_override"

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["selected_pack_id"] == "support_operator_override"
    assert summary["effective_pack_id"] == "support_operator_override"
    assert summary["pack_id"] == "support_operator_override"


def test_validate_sir_binds_pack_identity_into_itgl_context_and_governance_context():
    payload = "hello world"
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    verdict = validate_sir(
        {
            "isc": {
                "version": "1.0",
                "template_id": "EU-AI-Act-ISC-v1",
                "payload": payload,
                "checksum": checksum,
                "signature": "",
                "key_id": "default",
            }
        },
        pack_identity_context={"pack_version": "1.0.0", "pack_hash": "sha256:testpackhash"},
    )

    assert verdict["status"] == "PASS"
    context_entry = verdict["itgl_log"][0]
    assert context_entry["component"] == "context"
    assert context_entry["input"]["pack_version"] == "1.0.0"
    assert verdict["governance_context"]["pack_version"] == "1.0.0"
    assert verdict["governance_context"]["governance_scope"] == "deployment"
    assert verdict["governance_context"]["crypto_enforced"] is False

    # From 7 October 2026 the gate hashes the pack it loaded, so a
    # caller-supplied pack_hash no longer reaches the record. A caller cannot
    # know the identity of an artefact the gate read for itself, and before
    # this nothing supplied the field at all, so it travelled empty.
    assert verdict["governance_context"]["pack_hash"] != "sha256:testpackhash"
    assert context_entry["input"]["pack_hash"] != "sha256:testpackhash"


def test_the_caller_cannot_assert_the_identity_of_the_pack_the_gate_loaded():
    """pack_hash is computed from the loaded pack, not accepted from the
    caller. Two calls differing only in the claimed hash must agree."""
    payload = "hello world"
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    isc = {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": payload,
        "checksum": checksum,
        "signature": "",
        "key_id": "default",
    }

    honest = validate_sir({"isc": dict(isc)}, pack_identity_context={"pack_version": "1.0.0"})
    claimed = validate_sir(
        {"isc": dict(isc)},
        pack_identity_context={"pack_version": "1.0.0", "pack_hash": "sha256:" + "f" * 64},
    )

    assert honest["governance_context"]["pack_hash"].startswith("sha256:")
    assert honest["governance_context"]["pack_hash"] == claimed["governance_context"]["pack_hash"]
    assert (
        honest["governance_context"]["execution_configuration"]["configuration_hash"]
        == claimed["governance_context"]["execution_configuration"]["configuration_hash"]
    )


def test_red_team_suite_passes_selected_pack_identity_context_to_validate_sir(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "pci_payments", "1.0.0", "csv_single_turn_v1", "pci_payments"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="audit",
            pack="pci_payments",
            suite=None,
            scenario=None,
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
            provider="xai",
        ),
    )

    observed: dict[str, str] = {}

    def _fake_validate_sir(input_dict, enforcement_pack_id=None, pack_identity_context=None):
        observed["pack_version"] = str((pack_identity_context or {}).get("pack_version") or "")
        observed["pack_hash"] = str((pack_identity_context or {}).get("pack_hash") or "")
        return {
            "status": "PASS",
            "reason": "clean",
            "domain_pack": enforcement_pack_id or "generic_safety",
            "pass_rule_explainability": {
                "evaluated_rule_families": ["jailbreak_bypass", "exfiltration"],
                "clean_rule_families": ["jailbreak_bypass", "exfiltration"],
                "obfuscation_signal_detected": True,
            },
            "governance_context": {"itgl_final_hash": "sha256:abc"},
        }

    monkeypatch.setattr(rts, "validate_sir", _fake_validate_sir)

    rts.main()

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    ledger_entry = json.loads((tmp_path / "proofs" / "itgl_ledger.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert observed["pack_version"] == "1.0.0"
    assert observed["pack_hash"] == ""
    assert summary["selected_pack_version"] == "1.0.0"
    assert ledger_entry["pass_rule_explainability"]["evaluated_rule_families"] == ["jailbreak_bypass", "exfiltration"]
    assert ledger_entry["pass_rule_explainability"]["obfuscation_signal_detected"] is True
