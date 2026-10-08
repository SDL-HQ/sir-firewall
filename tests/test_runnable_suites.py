"""Every registry suite can be executed, or declares why it cannot.

Four of the nine registry entries could not be run at all, and had not been
runnable since `e0ee45d` on 16 April 2026.

The cause was one field doing two jobs. `_resolve_suite_and_pack` matched the
selected suite against the registry and returned that entry's `pack_id`, which
was then handed to `load_domain_pack` as an **explicit** ISC policy pack
identifier. Selecting a suite therefore demanded a policy pack of the same name.
Four entries had none, so every row of those runs became a systemic reset.

Before `e0ee45d` a missing pack fell back silently to `generic_safety`, which is
why the archive holds real results for two of these suites: `account_recovery_fraud`
at 8 prompts and 5 leaks, `scenario_injection_chain` at 6 prompts and 0 leaks,
published on 5 and 16 April 2026. That commit made an explicit missing pack a hard
failure, which is right, because silently enforcing a policy other than the one
named is the defect class this release exists to remove. What it did not do was
check which entries it had just made unenforceable.

Nothing noticed for nearly six months, for two reasons now closed: R1 CLI
acceptance asserts `pack_id`, `suite_name` and `scenario_id`, all of which a
fully reset run satisfies; and until item 1 landed, a fully reset run printed and
exited exactly like a clean one.

So the registry now names the enforcement pack separately from the suite, a
selection that cannot be enforced fails at resolution rather than one row at a
time, and the one suite whose enforcement is meant to fail says so.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec/packs/pack_registry.v1.json"
ISC_PACKS = ROOT / "src/sir_firewall/policy/isc_packs"


def _runner():
    spec = importlib.util.spec_from_file_location("red_team_suite_runnable", ROOT / "red_team_suite.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = _runner()
ENTRIES = json.loads(REGISTRY.read_text(encoding="utf-8"))["packs"]
PACK_IDS = [entry["pack_id"] for entry in ENTRIES]


def _entry(pack_id):
    return next(e for e in ENTRIES if e["pack_id"] == pack_id)


# --- the registry says what each suite enforces under -------------------------


@pytest.mark.parametrize("pack_id", PACK_IDS)
def test_every_entry_names_its_enforcement_pack(pack_id):
    """Separately from the suite, even where the two coincide.

    Stating it is the point. An entry that says nothing is an entry that falls
    back, and a silent fallback is how four suites became unenforceable without
    anyone deciding they should be.
    """
    assert _entry(pack_id).get("enforcement_pack"), pack_id


@pytest.mark.parametrize("pack_id", PACK_IDS)
def test_every_declared_enforcement_pack_exists_or_is_declared_to_fail(pack_id):
    entry = _entry(pack_id)
    pack = entry["enforcement_pack"]
    exists = (ISC_PACKS / f"{pack}.json").is_file()

    if entry.get("enforcement_expected_to_fail"):
        assert not exists, (
            f"{pack_id} declares that enforcement fails, but {pack} exists"
        )
        assert entry.get("enforcement_pack_reason"), (
            f"{pack_id} declares a deliberate failure without saying why"
        )
    else:
        assert exists, f"{pack_id} enforces under {pack}, which does not exist"


def test_exactly_one_entry_is_deliberately_unenforceable():
    """canary_fail, and it should stay that way.

    Its pack-load failure is the fixture that proves a run evaluating no content
    cannot resemble a clean one. A second such entry is far more likely to be
    someone silencing the resolution check than a second deliberate canary.
    """
    deliberate = [e["pack_id"] for e in ENTRIES if e.get("enforcement_expected_to_fail")]

    assert deliberate == ["canary_fail"], deliberate


@pytest.mark.parametrize("pack_id", PACK_IDS)
def test_a_pairing_that_differs_from_the_suite_name_states_its_reason(pack_id):
    entry = _entry(pack_id)
    if entry["enforcement_pack"] == pack_id:
        return

    assert entry.get("enforcement_pack_reason"), (
        f"{pack_id} enforces under {entry['enforcement_pack']} with no reason recorded"
    )


# --- resolution ---------------------------------------------------------------


def test_resolution_returns_the_suite_and_the_enforcement_pack_separately():
    """Two values, not one widened value.

    The defect was `pack_id` doing both jobs. Fixing it by making `pack_id` mean
    the enforcement pack would repeat the mistake in the other direction: 292
    published certificates mean the suite by that name, and R1 CLI acceptance
    asserts it. So resolution returns both, and the first attempt at this fix,
    which returned only the enforcement pack, is what this test exists to stop.
    """
    suite, _scenario, pack_id, _version, _schema, enforcement_pack = (
        RUNNER._resolve_suite_and_pack(
            suite_arg=None, scenario_arg=None, pack_arg="mental_health_clinical",
            env_suite="", default_suite="", registry_path=str(REGISTRY),
        )
    )

    assert suite.endswith("mental_health_clinical.csv")
    assert pack_id == "mental_health_clinical", "pack_id is the suite"
    assert enforcement_pack == "generic_safety", "and the policy pack is its own value"


def test_the_path_route_resolves_the_same_way_as_the_pack_route():
    """A suite selected by path must enforce under the same pack as --pack.

    Two resolution branches set this value, and only one of them was wrong for
    the --pack route. Both are checked.
    """
    by_pack = RUNNER._resolve_suite_and_pack(
        suite_arg=None, scenario_arg=None, pack_arg="account_recovery_fraud",
        env_suite="", default_suite="", registry_path=str(REGISTRY),
    )
    by_path = RUNNER._resolve_suite_and_pack(
        suite_arg="tests/domain_packs/account_recovery_fraud.csv", scenario_arg=None,
        pack_arg=None, env_suite="", default_suite="", registry_path=str(REGISTRY),
    )

    assert by_pack[2] == by_path[2] == "account_recovery_fraud"
    assert by_pack[5] == by_path[5] == "generic_safety"


def test_a_missing_enforcement_pack_fails_at_selection(tmp_path):
    """Not one row at a time, and not after writing a run.

    Before this, the run completed with every row a systemic reset, and the
    archive kept the result.
    """
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    for entry in registry["packs"]:
        if entry["pack_id"] == "mental_health_clinical":
            entry["enforcement_pack"] = "a_pack_that_does_not_exist"
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(ValueError) as caught:
        RUNNER._resolve_suite_and_pack(
            suite_arg=None, scenario_arg=None, pack_arg="mental_health_clinical",
            env_suite="", default_suite="", registry_path=str(path),
        )

    message = str(caught.value)
    assert "a_pack_that_does_not_exist" in message
    assert "systemic reset" in message, "the message must say what running it would do"


def test_the_deliberate_failure_is_not_refused_at_selection():
    """canary_fail must still run, and still reset every row.

    An earlier version of the resolution check refused it, which broke the
    verdict canary landed the same day. The suite's whole purpose is to produce
    a run that evaluated nothing.
    """
    suite, _scenario, pack_id, _version, _schema, enforcement_pack = (
        RUNNER._resolve_suite_and_pack(
            suite_arg=None, scenario_arg=None, pack_arg="canary_fail",
            env_suite="", default_suite="", registry_path=str(REGISTRY),
        )
    )

    assert suite.endswith("canary_fail.csv")
    assert pack_id == "canary_fail"
    assert enforcement_pack == "canary_fail"
    assert not (ISC_PACKS / "canary_fail.json").is_file()


def test_the_path_the_runner_checks_is_the_path_the_gate_loads_from():
    """Selection mirrors load_domain_pack's lookup, so the two cannot disagree.

    A fast failure that checked a different directory than the loader would
    either refuse runnable suites or let unenforceable ones through.
    """
    sys.path.insert(0, str(ROOT / "src"))
    import sir_firewall.core as core

    expected = Path(core.__file__).resolve().parent / "policy" / "isc_packs" / "generic_safety.json"

    assert RUNNER._isc_pack_path("generic_safety") == expected
    assert RUNNER._isc_pack_exists("generic_safety")
    assert not RUNNER._isc_pack_exists("a_pack_that_does_not_exist")


# --- end to end ---------------------------------------------------------------


def _working_tree(tmp_path: Path) -> Path:
    """A cwd the runner can resolve its inputs from, without touching the repo.

    The registry's suite_path values are repository-relative and are resolved
    against the working directory, and the runner writes proofs/ into it. So the
    inputs are symlinked in and the outputs land in the temporary directory.
    """
    for name in ("tests", "spec", "policy", "src"):
        (tmp_path / name).symlink_to(ROOT / name)
    (tmp_path / "proofs").mkdir()
    return tmp_path


def _run(pack_id: str, tmp_path: Path) -> tuple[subprocess.CompletedProcess, dict]:
    work = _working_tree(tmp_path)
    result = subprocess.run(
        [sys.executable, str(ROOT / "red_team_suite.py"), "--pack", pack_id, "--no-model-calls"],
        cwd=work, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(work)},
    )
    summary_path = work / "proofs/run_summary.json"
    assert summary_path.is_file(), (
        f"the runner wrote no summary for {pack_id}\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}"
    )
    return result, json.loads(summary_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("pack_id", PACK_IDS)
def test_every_registry_entry_runs_or_refuses_for_its_stated_reason(pack_id, tmp_path):
    """The condition itself, exercised through the real runner.

    canary_fail runs and reports INCONCLUSIVE at exit 2, because it evaluated no
    content. Every other entry evaluates content and exits 0 or 2 according to
    its own result, never because it could not be enforced.
    """
    result, summary = _run(pack_id, tmp_path)
    evaluated = summary.get("content_evaluated")

    if _entry(pack_id).get("enforcement_expected_to_fail"):
        assert evaluated == 0, "canary_fail must evaluate nothing; that is the fixture"
        assert result.returncode == 2
        return

    assert evaluated and evaluated > 0, (
        f"{pack_id} evaluated no content, which is what being unenforceable looks like"
        f"\n{result.stdout[-800:]}"
    )
    assert summary.get("systemic_reset_count") == 0, summary.get("systemic_reset_counts_by_reason")


def test_the_suites_that_stopped_running_reproduce_their_published_result(tmp_path):
    """account_recovery_fraud published 8 prompts and 5 leaks in April 2026.

    Those runs used generic_safety by silent fallback. The registry now declares
    that pairing, so the published archive becomes reproducible rather than
    merely historical. If this diverges, either the suite or the gate changed and
    the archived certificate no longer describes what the code does.
    """
    _result, summary = _run("account_recovery_fraud", tmp_path)

    assert summary["content_evaluated"] == 8
    assert summary["jailbreaks_leaked"] == 5
    assert summary["harmless_blocked"] == 0


def test_the_summary_reports_the_suite_and_the_enforcement_pack_separately(tmp_path):
    """A published field must not change meaning underneath a reader.

    All 292 published certificates carry `pack_id` as a suite identity, and R1
    CLI acceptance asserts it. The enforcement pack gets its own field rather
    than widening that one.
    """
    _result, summary = _run("scenario_injection_chain", tmp_path)

    assert summary["pack_id"] == "scenario_injection_chain"
    assert summary["suite_name"] == "scenario_injection_chain"
    assert summary["enforcement_pack"] == "generic_safety"
    assert summary["effective_pack_id"] == "generic_safety", (
        "what the gate reports loading, which should agree with the declaration"
    )
