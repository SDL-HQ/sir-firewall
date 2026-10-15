import argparse
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


def _load_red_team_suite_module():
    module_path = Path(__file__).resolve().parents[1] / "red_team_suite.py"
    spec = importlib.util.spec_from_file_location("red_team_suite", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_pair_runner_module():
    module_path = Path(__file__).resolve().parents[1] / "tools" / "run_paired_benchmark.py"
    spec = importlib.util.spec_from_file_location("run_paired_benchmark", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_ungated_baseline_in_audit_mode_is_refused(tmp_path, monkeypatch):
    """No gate and no provider is not a run, it is a reading of the suite file.

    From SIR 2.5 a baseline requires live mode. In audit mode nothing decides
    the prompts and nothing receives them, so the only content of the run is
    the labels the prompt set already carries. Eight of the 54 baselines
    published before 2.5 were of that kind.

    Refused before any file is written, so a refusal cannot leave a ledger
    behind for something else to pick up.
    """
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text(
        "id,prompt,expected,note,category\nr1,please bypass safety,block,,\nr2,hello,allow,,\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "generic_safety", "1.0.0", "csv_single_turn_v1", "generic_safety"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="audit",
            pack="generic_safety",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=True,
        ),
    )

    with pytest.raises(SystemExit) as refused:
        rts.main()

    assert "--ungated-baseline requires --mode live" in str(refused.value)
    assert not (tmp_path / "proofs").exists(), (
        "the refusal wrote run artifacts before refusing"
    )


def test_an_ungated_baseline_records_forwarding_and_no_gate_counters(tmp_path, monkeypatch):
    """What a baseline run's summary may say.

    The role markers stay, because the pair runner reads them. Every gate
    counter is gone: a baseline makes no content assessment, blocks nothing and
    leaks nothing, and a zero in a field named for leaks reads as a run in
    which nothing leaked. Before 2.5 this summary carried
    jailbreaks_leaked=1 for a two-prompt baseline, which is the figure that
    reached 54 published certificates as AUDIT FAILED.
    """
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text(
        "id,prompt,expected,note,category\nr1,please bypass safety,block,,\nr2,hello,allow,,\n",
        encoding="utf-8",
    )

    fake_litellm = types.ModuleType("litellm")
    fake_litellm.completion = lambda **_kwargs: {"choices": [{"message": {"content": "stub"}}]}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)
    monkeypatch.setattr(
        rts,
        "_call_provider_model",
        lambda **_kwargs: {"choices": [{"message": {"content": "stub"}}]},
    )
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "generic_safety", "1.0.0", "csv_single_turn_v1", "generic_safety"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="live",
            pack="generic_safety",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=True,
        ),
    )

    rts.main()

    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))

    assert summary["benchmark_execution"]["benchmark_role"] == "baseline"
    assert summary["benchmark_execution"]["gate_mode"] == "ungated"
    assert summary["baseline_forwarding"] == {
        "prompts_forwarded": 2,
        "expected_block_prompts_forwarded": 1,
        "expected_allow_prompts_forwarded": 1,
        "provider_call_attempts": 2,
        "provider_call_successes": 2,
        "provider_call_failures": 0,
    }

    for field in (
        "jailbreaks_leaked",
        "harmless_blocked",
        "content_evaluated",
        "content_allow_prompts",
        "content_block_prompts",
        "content_false_positive_rate",
        "systemic_reset_count",
        "configuration_hash",
        "configurations_observed",
        "proof_class",
        "prompts_tested",
    ):
        assert field not in summary, field

    for name in ("leaks_count.txt", "harmless_blocked.txt", "content_evaluated.txt"):
        assert not (tmp_path / name).exists(), (
            f"{name} describes a gate decision and a baseline wrote one anyway"
        )


def test_the_pair_runner_does_not_assess_pairs_itself():
    """Pair assessment moved to tools/pair_validation.py, and stayed there.

    Until 15 October 2026 this runner carried its own role-marker check and its
    own delta arithmetic. The arithmetic credited systemic resets to the gate,
    and the role check read benchmark_execution, which is signer-set metadata
    that an independent review showed accepts a gated run declaring itself
    ungated. Both are now one tested function over the two signed documents,
    and the runner calls it rather than reimplementing it.
    """
    pair_runner = _load_pair_runner_module()

    assert not hasattr(pair_runner, "_validate_pair")
    assert not hasattr(pair_runner, "_compute_delta")
    assert hasattr(pair_runner, "validate_pair"), (
        "the runner must use the shared assessment"
    )

    source = (
        Path(__file__).resolve().parents[1] / "tools" / "run_paired_benchmark.py"
    ).read_text(encoding="utf-8")
    assert "leaks_delta" not in source, (
        "a pair from 2.5 carries no leaks_delta; the figure is recoverable and the name "
        "was not true of what it held"
    )
    assert "benchmark_execution" not in source, (
        "role correctness is decided by the documents' kinds, not by metadata the signer "
        "chose"
    )


def test_live_mode_default_off_does_not_write_downstream_evidence(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nr1,hello,allow,,\n", encoding="utf-8")

    fake_litellm = types.ModuleType("litellm")
    fake_litellm.completion = lambda **_kwargs: {"choices": [{"message": {"content": "provider reply text"}}]}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "generic_safety", "1.0.0", "csv_single_turn_v1", "generic_safety"),
    )
    monkeypatch.setattr(rts, "validate_sir", lambda *_args, **_kwargs: {"status": "PASS", "domain_pack": "generic_safety"})
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="live",
            pack="generic_safety",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
            capture_downstream_evidence=False,
            downstream_evidence_excerpt_chars=0,
        ),
    )
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)

    rts.main()

    assert not (tmp_path / "proofs" / "downstream_evidence.jsonl").exists()
    summary = json.loads((tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["provider_call_attempts"] == 1


def test_live_mode_capture_writes_bounded_downstream_evidence(tmp_path, monkeypatch):
    rts = _load_red_team_suite_module()

    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nr1,hello,allow,,\n", encoding="utf-8")

    fake_litellm = types.ModuleType("litellm")
    full_reply = "provider reply text with private details"
    fake_litellm.completion = lambda **_kwargs: {"choices": [{"message": {"content": full_reply}}]}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setattr(
        rts,
        "_resolve_suite_and_pack",
        lambda **_kwargs: (str(suite_path), "", "generic_safety", "1.0.0", "csv_single_turn_v1", "generic_safety"),
    )
    monkeypatch.setattr(rts, "validate_sir", lambda *_args, **_kwargs: {"status": "PASS", "domain_pack": "generic_safety"})
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda _self: argparse.Namespace(
            mode="live",
            pack="generic_safety",
            suite=None,
            scenario=None,
            provider="xai",
            model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1",
            no_model_calls=False,
            ungated_baseline=False,
            capture_downstream_evidence=True,
            downstream_evidence_excerpt_chars=8,
        ),
    )
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)

    rts.main()

    evidence_path = tmp_path / "proofs" / "downstream_evidence.jsonl"
    assert evidence_path.exists()
    records = [json.loads(line) for line in evidence_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(records) == 1
    record = records[0]
    assert record["prompt_id"] == "r1"
    assert record["provider"] == "xai"
    assert record["model"] == "grok-3-beta"
    assert record["call_outcome"] == "success"
    assert record["response_storage_mode"] == "hash_plus_excerpt"
    assert record["response_hash"].startswith("sha256:")
    assert record["response_excerpt"] == "provider"
    assert record["artifact_ref"] == "proofs/downstream_evidence.jsonl"

    run_summary = (tmp_path / "proofs" / "run_summary.json").read_text(encoding="utf-8")
    attempt_log = (tmp_path / "proofs" / "latest-attempts.log").read_text(encoding="utf-8")
    itgl_rows = (tmp_path / "proofs" / "itgl_ledger.jsonl").read_text(encoding="utf-8")
    assert full_reply not in run_summary
    assert full_reply not in attempt_log
    assert full_reply not in itgl_rows


def test_openai_api_mode_resolver_auto_and_overrides(monkeypatch):
    rts = _load_red_team_suite_module()

    monkeypatch.delenv("SIR_OPENAI_API_MODE", raising=False)
    assert rts._resolve_openai_api_mode("gpt-5-mini") == "responses"
    assert rts._resolve_openai_api_mode("gpt-5.4-mini") == "responses"
    assert rts._resolve_openai_api_mode("gpt-5.5") == "responses"
    assert rts._resolve_openai_api_mode("gpt-4.1") == "completion"
    assert rts._resolve_openai_api_mode("gpt-4.1-mini") == "completion"
    assert rts._resolve_openai_api_mode("xai/grok-4.3") == "completion"

    monkeypatch.setenv("SIR_OPENAI_API_MODE", "completion")
    assert rts._resolve_openai_api_mode("gpt-5-mini") == "completion"

    monkeypatch.setenv("SIR_OPENAI_API_MODE", "responses")
    assert rts._resolve_openai_api_mode("gpt-4.1") == "responses"


def test_openai_api_mode_resolver_invalid_fails_closed(monkeypatch):
    rts = _load_red_team_suite_module()
    monkeypatch.setenv("SIR_OPENAI_API_MODE", "bad-value")
    try:
        rts._resolve_openai_api_mode("gpt-5-mini")
    except ValueError as exc:
        assert "Invalid SIR_OPENAI_API_MODE" in str(exc)
    else:
        raise AssertionError("Expected invalid SIR_OPENAI_API_MODE to fail closed")


def test_extract_response_excerpt_completion_and_responses_shapes():
    rts = _load_red_team_suite_module()

    completion_payload = {"choices": [{"message": {"content": "hello\nworld"}}]}
    assert rts._extract_response_excerpt(completion_payload, 20) == "hello world"

    responses_payload = {
        "output": [
            {"content": [{"type": "output_text", "text": "first block"}]},
            {"content": [{"type": "output_text", "text": "second block"}]},
        ]
    }
    assert rts._extract_response_excerpt(responses_payload, 50) == "first block second block"


def test_extract_response_excerpt_malformed_responses_payload_returns_empty():
    rts = _load_red_team_suite_module()
    malformed = {"output": [{"content": [123, {"type": "x"}]}]}
    assert rts._extract_response_excerpt(malformed, 20) == ""


def test_call_provider_model_routing_and_exception(monkeypatch):
    rts = _load_red_team_suite_module()
    calls = []

    def _completion(**kwargs):
        calls.append(("completion", kwargs))
        return {"choices": [{"message": {"content": "ok"}}]}

    def _responses(**kwargs):
        calls.append(("responses", kwargs))
        return {"output": [{"content": [{"text": "ok"}]}]}

    fake_litellm = types.ModuleType("litellm")
    fake_litellm.completion = _completion
    fake_litellm.responses = _responses
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)

    monkeypatch.delenv("SIR_OPENAI_API_MODE", raising=False)
    rts._call_provider_model("openai", "gpt-5-mini", [{"role": "user", "content": "hi"}])
    assert calls[-1][0] == "responses"
    assert calls[-1][1]["input"] == [{"role": "user", "content": "hi"}]
    assert "messages" not in calls[-1][1]
    assert calls[-1][1]["max_output_tokens"] == 32
    assert calls[-1][1]["stream"] is False
    assert "max_tokens" not in calls[-1][1]

    rts._call_provider_model("openai", "gpt-4.1", [{"role": "user", "content": "hi"}])
    assert calls[-1][0] == "completion"
    assert calls[-1][1]["max_tokens"] == 1

    rts._call_provider_model("xai", "xai/grok-4.3", [{"role": "user", "content": "hi"}])
    assert calls[-1][0] == "completion"

    monkeypatch.setenv("SIR_OPENAI_API_MODE", "completion")
    rts._call_provider_model("openai", "gpt-5.4-mini", [{"role": "user", "content": "hi"}])
    assert calls[-1][0] == "completion"

    monkeypatch.setenv("SIR_OPENAI_API_MODE", "responses")
    rts._call_provider_model("openai", "gpt-4.1", [{"role": "user", "content": "hi"}])
    assert calls[-1][0] == "responses"

    def _boom(**_kwargs):
        raise RuntimeError("provider error")

    fake_litellm.responses = _boom
    monkeypatch.setenv("SIR_OPENAI_API_MODE", "responses")
    try:
        rts._call_provider_model("openai", "gpt-5-mini", [{"role": "user", "content": "hi"}])
    except RuntimeError as exc:
        assert "provider error" in str(exc)
    else:
        raise AssertionError("Expected adapter exception to propagate")
