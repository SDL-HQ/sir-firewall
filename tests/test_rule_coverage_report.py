import importlib.util
import json
from pathlib import Path


def _load_module():
    module_path = Path(__file__).resolve().parents[1] / "tools" / "rule_coverage_report.py"
    spec = importlib.util.spec_from_file_location("rule_coverage_report", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _by_id(report):
    return {pack["pack_id"]: pack for pack in report["packs"]}


def test_report_covers_fully_matched_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    full = packs["support_operator_override"]
    assert full["deterministic_rule_matched"] == full["block_rows"] == 26
    assert full["full_gate_matched"] == 26


def test_report_covers_partially_matched_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    partial = packs["eu_ai_act_compliance_pressure"]
    assert partial["deterministic_rule_matched"] == 74
    assert partial["full_gate_matched"] == 74
    assert partial["block_rows"] == 100
    assert partial["deterministic_rule_unmatched_ids"] == ["eua-116"] + [f"eua-{i}" for i in range(126, 151)]


def test_report_decodes_encoded_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    encoded = packs["mental_health_clinical"]
    assert encoded["block_rows"] == 15
    assert encoded["deterministic_rule_matched"] == 2
    assert encoded["full_gate_matched"] == 5


def test_report_handles_placeholder_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    placeholder = packs["pii_protection"]
    assert placeholder["block_rows"] == 0
    assert placeholder["deterministic_rule_matched"] == 0
    assert placeholder["full_gate_matched"] == 0


def test_cli_writes_machine_readable_json_and_markdown(tmp_path, monkeypatch):
    module = _load_module()
    json_out = tmp_path / "coverage.json"
    markdown_out = tmp_path / "coverage.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "rule_coverage_report.py",
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
    )

    assert module.main() == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert len(payload["packs"]) == 16
    table = markdown_out.read_text(encoding="utf-8")
    assert "| Pack | Status | Visibility |" in table
    assert "`generic_safety`" in table
