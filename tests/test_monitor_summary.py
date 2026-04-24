import importlib.util


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
