import importlib.util
import json
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    path = ROOT / "tools" / "latency_report.py"
    spec = importlib.util.spec_from_file_location("latency_report", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_published_latency_tables_match_generator():
    module = _load_module()
    report = json.loads((ROOT / "docs/latency-results.json").read_text())
    document = (ROOT / "docs/latency.md").read_text()
    generated = module.render_tables(report)
    assert generated in document
    assert document.count(module.BEGIN) == document.count(module.END) == 1


def test_measurement_record_has_required_distributions_and_sweep():
    report = json.loads((ROOT / "docs/latency-results.json").read_text())
    for group in ("terminating_paths", "decode_paths", "length_sweep", "pathological_probes"):
        for row in report[group]:
            assert {"n", "p50_us", "p95_us", "p99_us", "max_us", "stdev_us"} <= row.keys()
            assert row["n"] > 1
    assert len(report["length_sweep"]) >= 5
    assert {row["case"] for row in report["decode_paths"]} == {
        "decode: Base64", "decode: ROT13", "decode: hex", "decode: hex-escape"
    }
    assert len(report["linear_fit"]["residuals"]) == len(report["length_sweep"])
    assert {row["component"] for row in report["safe_pass_decomposition"]["components"]} == {
        "normalisation", "rule evaluation after normalisation", "ITGL construction and hashing",
        "template and policy lookup", "ISC envelope handling",
        "result construction and orchestration", "instrumentation overhead",
    }


def test_effective_limit_table_covers_every_installed_enforcement_pack():
    module = _load_module()
    report = json.loads((ROOT / "docs/latency-results.json").read_text())
    expected = module._effective_limits()
    assert report["effective_input_limits"] == expected
    assert len(expected) == 18
    assert {row["effective_character_limit"] for row in expected} == {
        3600, 4000, 4800, 6000, 6400, 7200, 8000
    }


def test_benchmark_is_read_only_with_respect_to_proofs():
    source = (ROOT / "tools/latency_report.py").read_text()
    assert "proofs/" not in source
    assert "validate_sir(request)" in source


def test_8001_character_input_is_blocked_without_content_evaluation(monkeypatch):
    module = _load_module()
    monkeypatch.setattr(
        module.core,
        "_check_jailbreak",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("content evaluated")),
    )
    result = module.core.validate_sir(module._isc("x" * 8001))
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "friction_limit_exceeded"


def test_archived_provider_wall_clock_inputs_match_report():
    expected = [
        ("20260921-134707-359329-gh35607761858-a8a5ade8f6ed", 186, 150),
        ("20260921-135018-029319-gh35607761858-f3dd66376a01", 82, 76),
    ]
    for run_id, elapsed_seconds, calls in expected:
        run = ROOT / "docs" / "runs" / run_id
        header = (run / "proofs" / "latest-attempts.log").read_text().splitlines()[1]
        started = datetime.fromisoformat(header.removeprefix("Date: "))
        audit = json.loads((run / "audit.json").read_text())
        ended = datetime.fromisoformat(audit["timestamp_utc"])
        assert (ended - started).total_seconds() == elapsed_seconds
        assert audit["provider_call_attempts"] == calls
