"""The quorum reference implementation, which had never run and never been tested.

``tools/quorum_firewall.py`` imported ``sir_firewall.sir_firewall``, a module gone
since the move to ``core.py``, so from the commit that created it until 8 October
2026 it raised ``ImportError`` on every invocation in every environment. Nothing
in the repository referenced it, so nothing noticed.

It matters more than an unused script, because it is offered to a reader as a
pattern to copy: "This is a reference implementation showing how to ... apply
strict quorum semantics". A reader copying a fail-open aggregation into a real
deployment inherits the defect rather than the pattern.

Which is what it had. An empty result list returned ``status: PASS`` with
``reason: all_firewalls_passed``, so a run in which **no firewall was consulted**
was reported identically to one in which every firewall allowed the request, and
the reason string stated something that had not happened. That is the execution
accounting defect of item 1, in the file that demonstrates the idea.

The shipped ``FIREWALLS`` list has one entry, so every multi-firewall rule below
is unexercised by the tool's own configuration. These tests exercise the
aggregation directly, which is where the semantics live.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("quorum_firewall", ROOT / "tools/quorum_firewall.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUORUM = _load()


def _pass(name="a"):
    return {"status": "PASS", "_firewall_id": name}


def _blocked(name="b"):
    return {"status": "BLOCKED", "_firewall_id": name, "reason": "rule"}


def _reset(name="c"):
    return {"status": "PASS", "_firewall_id": name,
            "sr": {"sr_triggered": True, "sr_reason": "policy_load_failed", "sr_scope": "global"}}


# --- the defect --------------------------------------------------------------


def test_a_quorum_of_nobody_is_not_a_pass():
    """The whole reason this file exists. Before 8 October this returned PASS."""
    aggregated = QUORUM.aggregate_quorum([])

    assert aggregated["status"] == "BLOCKED"
    assert aggregated["reason"] == "no_firewalls_consulted"
    assert aggregated["quorum_size"] == 0


def test_the_empty_reason_does_not_claim_firewalls_passed():
    """The status alone is not the fix. The reason string is read by people."""
    assert QUORUM.aggregate_quorum([])["reason"] != "all_firewalls_passed"


# --- the semantics the module documents --------------------------------------


def test_all_passing_is_a_pass():
    aggregated = QUORUM.aggregate_quorum([_pass("a"), _pass("b")])

    assert aggregated["status"] == "PASS"
    assert aggregated["reason"] == "all_firewalls_passed"
    assert aggregated["quorum_size"] == 2


@pytest.mark.parametrize("position", [0, 1, 2])
def test_any_block_blocks_the_quorum(position):
    results = [_pass("a"), _pass("b"), _pass("c")]
    results[position] = _blocked("blocker")
    aggregated = QUORUM.aggregate_quorum(results)

    assert aggregated["status"] == "BLOCKED"
    assert aggregated["reason"] == "one_or_more_firewalls_blocked"
    assert [event["firewall_id"] for event in aggregated["blocked_events"]] == ["blocker"]


def test_a_systemic_reset_blocks_even_where_that_firewall_reported_pass():
    """A reset is not a decision about content, so its PASS is not an allow."""
    aggregated = QUORUM.aggregate_quorum([_pass("a"), _reset("resetter")])

    assert aggregated["status"] == "BLOCKED"
    assert aggregated["reason"] == "systemic_reset_triggered"
    assert aggregated["sr_events"] == [
        {"firewall_id": "resetter", "reason": "policy_load_failed", "scope": "global"}
    ]


def test_a_reset_outranks_a_block_in_the_reason():
    """Both block. The reason must name the reset, which is the more serious of
    the two: a block is the gate working, a reset is the gate not having
    decided."""
    aggregated = QUORUM.aggregate_quorum([_blocked("b"), _reset("c")])

    assert aggregated["status"] == "BLOCKED"
    assert aggregated["reason"] == "systemic_reset_triggered"
    assert aggregated["blocked_events"] and aggregated["sr_events"]


def test_a_result_with_no_status_at_all_blocks():
    """Fail closed on a malformed result rather than reading absence as PASS."""
    assert QUORUM.aggregate_quorum([{"_firewall_id": "a"}])["status"] == "BLOCKED"


def test_every_decision_is_carried_into_the_aggregate():
    """The aggregate is a verdict plus its evidence, not a verdict alone."""
    results = [_pass("a"), _blocked("b"), _reset("c")]
    aggregated = QUORUM.aggregate_quorum(results)

    assert aggregated["decisions"] == results
    assert aggregated["quorum_size"] == 3


# --- the tool as a process ---------------------------------------------------


def test_the_tool_runs_end_to_end_on_a_payload(tmp_path):
    """It imports, loads an ISC payload, runs the shipped quorum and emits JSON.

    This is the invocation that raised ImportError for the whole life of the
    file. No assertion is made about the verdict: the point is that the tool
    executes and produces a parseable aggregate.
    """
    payload = tmp_path / "isc.json"
    payload.write_text(json.dumps({"isc": {"text": "hello"}}), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/quorum_firewall.py"), str(payload)],
        cwd=ROOT, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    aggregated = json.loads(result.stdout)
    assert aggregated["quorum_size"] == len(QUORUM.FIREWALLS)
    assert aggregated["status"] in ("PASS", "BLOCKED")


def test_a_payload_without_an_isc_key_is_refused(tmp_path):
    payload = tmp_path / "bad.json"
    payload.write_text(json.dumps({"not_isc": {}}), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/quorum_firewall.py"), str(payload)],
        cwd=ROOT, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert result.returncode == 1
    assert "isc" in result.stderr


def test_the_shipped_quorum_is_one_firewall():
    """Recorded, not asserted as desirable.

    Every multi-firewall rule above is unexercised by the tool's own
    configuration. If a second entry is added, this fails and whoever added it
    confirms the semantics still hold for the deployment rather than only for
    the unit tests.
    """
    assert len(QUORUM.FIREWALLS) == 1
    assert QUORUM.FIREWALLS[0].domain_pack == "generic_safety"
