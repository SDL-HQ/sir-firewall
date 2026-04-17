import json
from pathlib import Path

from sir_firewall import core


_FIXTURE_PATH = Path(__file__).resolve().parent / "domain_packs" / "structured_account_recovery_benchmark.json"


def _load_cases():
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert data.get("mode") == "exploratory"
    assert data.get("request_surface") == "account_recovery_challenge_request_v1"
    cases = data.get("cases")
    assert isinstance(cases, list) and cases

    for case in cases:
        structured = case.get("input", {}).get("structured_request")
        if isinstance(structured, dict) and structured.get("request_text") == "REPEAT_4100_CHARS":
            structured["request_text"] = "a" * 4100

    return cases


def test_structured_benchmark_fixture_cases_match_expected_outcomes():
    cases = _load_cases()

    for case in cases:
        out = core.validate_sir(case["input"])
        expected = case["expected"]

        assert out["status"] == expected["status"], case["id"]
        assert out["reason"] == expected["reason"], case["id"]
        if "type" in expected:
            assert out["type"] == expected["type"], case["id"]


def test_structured_benchmark_fixture_is_exploratory_not_acceptance_surface():
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))

    assert data["mode"] == "exploratory"
    assert "acceptance" in data["notes"].lower()
    assert "not" in data["notes"].lower()
