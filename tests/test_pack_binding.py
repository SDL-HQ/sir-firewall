import argparse
import importlib.util
import json
import hashlib
from pathlib import Path

from sir_firewall import validate_sir


def _load_red_team_suite_module():
    module_path = Path(__file__).resolve().parents[1] / "red_team_suite.py"
    spec = importlib.util.spec_from_file_location("red_team_suite", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_selected_pack_id_controls_enforcement_context(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "pci_payments", "1.0.0", "csv_single_turn_v1"),
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
        lambda **_kwargs: (str(suite_path), "", "pci_payments", "1.0.0", "csv_single_turn_v1"),
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
    monkeypatch.setattr(
        rts,
        "load_domain_pack",
        lambda pack_id=None: {
            "pack_id": pack_id or "generic_safety",
            "flags": {"CRYPTO_ENFORCED": True, "CHECKSUM_ENFORCED": False},
        },
    )

    rts.main()

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["selected_pack_id"] == "pci_payments"
    assert summary["effective_pack_id"] == "pci_payments"
    assert summary["pack_id"] == "pci_payments"
    assert summary["selected_pack_version"] == "1.0.0"
    assert summary["flags"] == {"CRYPTO_ENFORCED": True, "CHECKSUM_ENFORCED": False}


def test_run_summary_separates_selected_and_effective_pack_when_selection_is_implicit(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "", "", "csv_single_turn_v1"),
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
        lambda **_kwargs: (str(suite_path), "", "support_operator_override", "1.0.0", "csv_single_turn_v1"),
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
    assert context_entry["input"]["pack_hash"] == "sha256:testpackhash"
    assert verdict["governance_context"]["pack_version"] == "1.0.0"
    assert verdict["governance_context"]["pack_hash"] == "sha256:testpackhash"


def test_red_team_suite_passes_selected_pack_identity_context_to_validate_sir(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nrow-1,hello,allow,,\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "pci_payments", "1.0.0", "csv_single_turn_v1"),
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
            "governance_context": {"itgl_final_hash": "sha256:abc"},
        }

    monkeypatch.setattr(rts, "validate_sir", _fake_validate_sir)

    rts.main()

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    assert observed["pack_version"] == "1.0.0"
    assert observed["pack_hash"] == summary["suite_hash"]
    assert summary["selected_pack_version"] == "1.0.0"
