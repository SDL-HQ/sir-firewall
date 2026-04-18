import argparse
import importlib.util
import json
from pathlib import Path


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
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
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
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
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
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
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
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
        ),
    )
    monkeypatch.setattr(
        rts,
        "validate_sir",
        lambda *_args, **_kwargs: {"status": "PASS", "reason": "clean", "domain_pack": ""},
    )

    rts.main()

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["selected_pack_id"] == "support_operator_override"
    assert summary["effective_pack_id"] == "support_operator_override"
    assert summary["pack_id"] == "support_operator_override"
