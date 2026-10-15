import importlib.util

import pytest


def _load_monitor_summary_module():
    spec = importlib.util.spec_from_file_location(
        "generate_monitor_summary",
        "tools/generate_monitor_summary.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_monitor_summary_uses_index_truth_with_window_counts():
    monitor = _load_monitor_summary_module()

    index_payload = {
        "updated_at_utc": "2026-04-24T00:00:00Z",
        "runs": [
            {
                "run_id": "run-4",
                "result": "AUDIT FAILED",
                "date": "2026-04-24T00:00:00Z",
                "ci_run_url": "https://ci/r/4",
            },
            {
                "run_id": "run-3",
                "result": "INCONCLUSIVE",
                "date": "2026-04-23T00:00:00Z",
                "ci_run_url": "https://ci/r/3",
            },
            {
                "run_id": "run-2",
                "result": "AUDIT PASSED",
                "date": "2026-04-22T00:00:00Z",
                "ci_run_url": "https://ci/r/2",
            },
            {
                "run_id": "run-1",
                "result": "AUDIT PASSED",
                "date": "2026-04-21T00:00:00Z",
                "ci_run_url": "https://ci/r/1",
            },
        ],
    }

    summary = monitor.build_monitor_summary(index_payload, window_size=3)

    assert summary["updated_at_utc"] == "2026-04-24T00:00:00Z"
    assert summary["window_size"] == 3

    assert summary["latest_run"] == {
        "run_id": "run-4",
        "result": "AUDIT FAILED",
        "date": "2026-04-24T00:00:00Z",
    }
    assert summary["latest_passing_run"] == {
        "run_id": "run-2",
        "result": "AUDIT PASSED",
        "date": "2026-04-22T00:00:00Z",
    }

    assert summary["counts"] == {
        "audit_passed": 1,
        "audit_failed": 1,
        "inconclusive": 1,
    }
    assert summary["latest_ci_run_url"] == "https://ci/r/4"


def test_build_monitor_summary_is_deterministic_for_same_index_payload():
    monitor = _load_monitor_summary_module()

    index_payload = {
        "updated_at_utc": "2026-04-24T00:00:00Z",
        "runs": [
            {"run_id": "run-b", "result": "AUDIT FAILED", "date": "2026-04-24T00:00:00Z", "ci_run_url": "https://ci/r/b"},
            {"run_id": "run-a", "result": "AUDIT PASSED", "date": "2026-04-23T00:00:00Z", "ci_run_url": "https://ci/r/a"},
        ],
    }

    first = monitor.build_monitor_summary(index_payload, window_size=2)
    second = monitor.build_monitor_summary(index_payload, window_size=2)

    assert first == second


def test_build_monitor_summary_handles_missing_passing_run():
    monitor = _load_monitor_summary_module()

    index_payload = {
        "updated_at_utc": "2026-04-24T00:00:00Z",
        "runs": [
            {"run_id": "run-x", "result": "AUDIT FAILED", "date": "2026-04-24T00:00:00Z", "ci_run_url": "https://ci/r/x"},
            {"run_id": "run-y", "result": "INCONCLUSIVE", "date": "2026-04-23T00:00:00Z", "ci_run_url": "https://ci/r/y"},
        ],
    }

    summary = monitor.build_monitor_summary(index_payload, window_size=10)

    assert summary["window_size"] == 2
    assert summary["latest_passing_run"] is None
    assert summary["counts"] == {
        "audit_passed": 0,
        "audit_failed": 1,
        "inconclusive": 1,
    }


def _load_declared_results():
    """The declaration as the monitor itself holds it.

    Loading tools/certificate_results.py a second time by file location would
    give a different UnrecognisedResult class from the one the monitor raises,
    and the tests below would pass for the wrong reason.
    """
    return _load_monitor_summary_module()


def _row(run_id, result):
    return {
        "run_id": run_id,
        "result": result,
        "date": "2026-10-15T00:00:00Z",
        "ci_run_url": f"https://ci/r/{run_id}",
    }


def test_every_row_in_the_window_is_counted_exactly_once():
    """The counts add up to the window size, which is what stops a silent hole.

    Until 15 October 2026 tools/generate_monitor_summary.py counted only the
    three results it recognised and dropped anything else, so an unfamiliar
    result occupied the window and appeared in no count. The sum is the
    invariant that defect broke.

    Mutations applied to tools/generate_monitor_summary.py, both detected:
    skipping a row whose result is not declared instead of raising, 1 failure
    (test_an_undeclared_result_stops_the_summary); counting with a literal
    key map instead of the declared set, 1 failure
    (test_a_fourth_declared_result_would_be_counted).
    """
    monitor = _load_monitor_summary_module()
    results = _load_declared_results()

    rows = [
        _row(f"run-{position}", result)
        for position, result in enumerate(results.KNOWN_RESULTS * 3)
    ]
    summary = monitor.build_monitor_summary({"runs": rows}, window_size=7)

    assert summary["window_size"] == 7
    assert sum(summary["counts"].values()) == 7


def test_each_declared_result_has_a_count_of_its_own():
    """No declared result can be dropped, because the keys come from the set."""
    monitor = _load_monitor_summary_module()
    results = _load_declared_results()

    for result in results.KNOWN_RESULTS:
        summary = monitor.build_monitor_summary({"runs": [_row("run-1", result)]}, window_size=1)
        assert sum(summary["counts"].values()) == 1
        assert summary["counts"][result.lower().replace(" ", "_")] == 1

    assert set(monitor.empty_counts()) == {
        result.lower().replace(" ", "_") for result in results.KNOWN_RESULTS
    }


def test_a_fourth_declared_result_would_be_counted(monkeypatch):
    """The count keys are derived, so declaring a result is enough to count it.

    This is what distinguishes the derivation from a literal key map: with the
    declared set as it stands the two are indistinguishable, because the three
    derived keys are the three that used to be written out here.

    Mutation applied to tools/generate_monitor_summary.py: replacing
    empty_counts with a literal three-key map, 1 failure (this test).
    """
    monitor = _load_monitor_summary_module()

    declared = (*monitor.KNOWN_RESULTS, "BASELINE COMPLETE")
    monkeypatch.setattr(monitor, "KNOWN_RESULTS", declared)
    monkeypatch.setitem(
        monitor.status_for.__globals__["RESULT_STATUS"],
        "BASELINE COMPLETE",
        monitor.status_for("INCONCLUSIVE")._replace(status="BASELINE"),
    )

    summary = monitor.build_monitor_summary({"runs": [_row("run-1", "BASELINE COMPLETE")]})

    assert summary["counts"]["baseline_complete"] == 1
    assert sum(summary["counts"].values()) == 1


def test_the_summary_says_what_its_counts_cover():
    """Baseline records are not in this window, so the window names its subject.

    Mutation applied to tools/generate_monitor_summary.py: removing
    counts_cover from the summary, 1 failure (this test).
    """
    monitor = _load_monitor_summary_module()

    summary = monitor.build_monitor_summary({"runs": [_row("run-1", "AUDIT PASSED")]})

    assert summary["counts_cover"] == "audit_certificates"


def test_a_baseline_record_row_stops_the_summary():
    """A record carries no result, and the monitor window is gate runs.

    D5: baseline records are not runs for the single-run truth surfaces. They
    are not written into proofs/runs/index.json, so this is the explicit check
    that the monitor would refuse one if it were.

    Mutation applied to tools/generate_monitor_summary.py: dropping the
    record_kind check, 1 failure (this test).
    """
    monitor = _load_monitor_summary_module()

    row = _row("run-baseline", "AUDIT PASSED")
    row["record_kind"] = "sir_ungated_baseline"

    with pytest.raises(monitor.NotAGateRun) as excinfo:
        monitor.build_monitor_summary({"runs": [row]})

    assert "sir_ungated_baseline" in str(excinfo.value)


def test_an_undeclared_result_stops_the_summary():
    """An unfamiliar result is refused, not dropped from the counts.

    The second case is the one that matters. The search for the latest passing
    run stops at the first pass, so a row behind a passing row is read only by
    the counting path. With the first case alone, removing the refusal from
    that path changed nothing observable: the summary still refused, by way of
    the row it validates on the way in.

    Mutation applied to tools/generate_monitor_summary.py: catching
    UnrecognisedResult in _count_results and continuing, 1 failure (the second
    case here).
    """
    monitor = _load_monitor_summary_module()
    results = _load_declared_results()

    with pytest.raises(results.UnrecognisedResult):
        monitor.build_monitor_summary({"runs": [_row("run-1", "BASELINE RECORDED")]})

    behind_a_pass = [_row("run-2", "AUDIT PASSED"), _row("run-1", "BASELINE RECORDED")]
    with pytest.raises(results.UnrecognisedResult):
        monitor.build_monitor_summary({"runs": behind_a_pass}, window_size=2)


def test_a_result_is_compared_exactly_and_not_repaired():
    """The marker and the result reader compare exactly; so does this.

    Until 15 October 2026 this module normalised with strip().upper(), so
    "audit passed" counted as a pass here and stopped the markers. One reader
    repairing its input and another refusing it is the divergence
    tools/certificate_results.py exists to remove.

    Mutations applied to tools/generate_monitor_summary.py, both detected:
    upper-casing the result before the lookup, 1 failure (this test);
    stripping it, 1 failure (this test).
    """
    monitor = _load_monitor_summary_module()
    results = _load_declared_results()

    for spelling in ("audit passed", "Audit Passed", " AUDIT PASSED "):
        with pytest.raises(results.UnrecognisedResult):
            monitor.build_monitor_summary({"runs": [_row("run-1", spelling)]})


def test_a_payload_that_is_not_the_run_index_stops_the_summary():
    """Pointing the monitor at the wrong file must fail, not publish zeroes.

    Until 15 October 2026 any payload without a "runs" array produced a
    summary of zero runs with a null latest run, which reads as a repository
    that has published nothing.

    Mutations applied to tools/generate_monitor_summary.py, both detected:
    returning [] instead of raising for a payload with no runs array, 1
    failure (this test); skipping rows that are not JSON objects, 1 failure
    (this test).
    """
    monitor = _load_monitor_summary_module()

    for payload in ({}, {"entries": []}, {"runs": {}}, [], {"runs": ["run-1"]}):
        with pytest.raises(monitor.NotTheRunIndex):
            monitor.build_monitor_summary(payload)


def test_an_index_with_no_runs_yet_is_not_a_refusal():
    """A repository that has published nothing is a state, not a malformed index."""
    monitor = _load_monitor_summary_module()

    summary = monitor.build_monitor_summary({"runs": []})

    assert summary["window_size"] == 0
    assert summary["latest_run"] is None
    assert summary["latest_passing_run"] is None
    assert sum(summary["counts"].values()) == 0
