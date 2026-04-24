import json
from pathlib import Path

from sir_firewall import core


_FIXTURE_PATH = Path(__file__).resolve().parent / "domain_packs" / "tool_result_ingress_benchmark.json"


def _load_cases():
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert data.get("mode") == "exploratory"
    assert data.get("request_surface") == "tool_result_v1"
    cases = data.get("cases")
    assert isinstance(cases, list) and cases

    for case in cases:
        tool_result = case.get("input", {}).get("tool_result")
        if isinstance(tool_result, dict) and tool_result.get("content") == "REPEAT_4001_CHARS":
            tool_result["content"] = "a" * 4001

    return cases


def test_tool_result_benchmark_fixture_cases_match_expected_outcomes():
    cases = _load_cases()

    for case in cases:
        out = core.validate_sir(case["input"])
        expected = case["expected"]

        assert out["status"] == expected["status"], case["id"]
        assert out["reason"] == expected["reason"], case["id"]
        if "type" in expected:
            assert out["type"] == expected["type"], case["id"]


def test_tool_result_benchmark_fixture_is_exploratory_not_acceptance_surface():
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))

    assert data["mode"] == "exploratory"
    assert "acceptance" in data["notes"].lower()
    assert "not" in data["notes"].lower()
