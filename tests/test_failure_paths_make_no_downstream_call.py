"""Item 7's observed half, run in the suite so it cannot quietly stop working.

`tools/demonstrate_failure_paths.py` runs the real runner in live mode with a
counterfeit provider client that records and raises on any invocation. This runs
it and holds the three properties that make its result mean something:

1. every failure path case reaches the path it claims to exercise,
2. no failure path attempts a downstream call,
3. the positive control does attempt one.

Three is not a formality. "Zero calls observed" is worth nothing if the harness
could not see a call, which is the same defect as a structural test that has
never been shown to fail. Four successive versions of the policy-load case
failed to reach its path, and two of them reported a result anyway: one declared
a fail-open defect that did not exist, because the corrupted policy was never
the one the gate read.

The scope is the paths listed in the harness and nothing else. The universal
form of item 7's condition rests on the topology, in
`tests/test_no_downstream_call_without_approval.py`.
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _harness():
    spec = importlib.util.spec_from_file_location(
        "demonstrate_failure_paths", ROOT / "tools/demonstrate_failure_paths.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HARNESS = _harness()
RESULTS = [HARNESS._run_case(case) for case in HARNESS.CASES]


def test_the_harness_has_cases_and_a_control():
    """Guard the guard. An empty case list would satisfy every assertion below."""
    assert len(RESULTS) >= 3, RESULTS
    assert sum(1 for row in RESULTS if row["control"]) == 1
    assert sum(1 for row in RESULTS if not row["control"]) >= 2


@pytest.mark.parametrize(
    "row", [r for r in RESULTS if r["expect_reason"]], ids=lambda r: r["path"]
)
def test_each_case_reaches_the_path_it_claims_to_exercise(row):
    assert row["expect_reason"] in row["reset_reasons"], (
        f"{row['path']} expected reason {row['expect_reason']!r} and saw "
        f"{row['reset_reasons'] or 'no systemic reset'}. Zero calls from a case "
        "that never reached its path is not evidence"
    )


@pytest.mark.parametrize(
    "row", [r for r in RESULTS if not r["control"]], ids=lambda r: r["path"]
)
def test_no_failure_path_attempts_a_downstream_call(row):
    assert row["observed_calls"] == 0, (
        f"{row['path']} reached the provider client {row['observed_calls']} time(s)"
    )
    assert row["attempts_reported"] == 0, (
        f"{row['path']} reports provider_call_attempts="
        f"{row['attempts_reported']}, so the runner counted an attempt the "
        "counterfeit client did not see, or the reverse"
    )


def test_the_positive_control_fires():
    """Without this, zero on the failure paths means only that nothing was watched."""
    control = next(row for row in RESULTS if row["control"])

    assert control["observed_calls"] == 1, (
        "an approved prompt in live mode attempted no downstream call, so this "
        "harness cannot detect one and its zeros are meaningless"
    )
    assert control["attempts_reported"] == 1


def test_the_harness_exits_zero():
    """The one command another engineer runs."""
    assert HARNESS.main() == 0


def test_the_unreachable_paths_are_named_rather_than_omitted():
    """A list of exercised paths that drops the rest is the universal again."""
    assert len(HARNESS.NOT_REACHABLE_THROUGH_THE_RUNNER) >= 3
    for name, why in HARNESS.NOT_REACHABLE_THROUGH_THE_RUNNER:
        assert name and len(why) > 40, (name, why)
