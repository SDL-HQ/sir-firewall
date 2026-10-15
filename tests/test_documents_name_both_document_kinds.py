"""The documents that describe the evidence are held to the code that makes it.

Nothing tested docs/benchmark-cycle.v1.md, which is why its valid-cycle
criteria still required audit.json of every archive six months after the
archives stopped all being certificates, and why its locked list of pair
figures still named two deltas the pair validator no longer computes. A
document that locks a contract and drifts from it is worse than one that locks
nothing: a reader has no way to tell which of the two is current.

What is pinned here is every list in those documents that has a counterpart in
code. Prose is not pinned, and should not be: a test that asserts a sentence is
present only guarantees the sentence, and the sentence can be true of nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import _module

ROOT = Path(__file__).resolve().parents[1]
CYCLE = ROOT / "docs/benchmark-cycle.v1.md"
TERMS = ROOT / "docs/terminology.md"


def _cycle() -> str:
    return CYCLE.read_text(encoding="utf-8")


def _backticked_list(document: str, heading: str) -> list[str]:
    """The bullet list under a heading, as the identifiers it names."""
    start = document.index(heading) + len(heading)
    rest = document[start:]
    end = rest.find("\n#")
    section = rest if end < 0 else rest[:end]
    return re.findall(r"^- `([a-z_]+)`", section, flags=re.MULTILINE)


def test_the_locked_pair_statuses_are_the_validator_s_statuses():
    """A locked list of statuses that the validator cannot produce is not locked.

    Mutation applied to docs/benchmark-cycle.v1.md: removing
    invalid_evidence_gap from the locked list, 1 failure (this test).
    """
    validation = _module("pair_validation_documents", "tools/pair_validation.py")
    documented = set(_backticked_list(_cycle(), "### Pair status values (locked)"))

    in_code = {
        value
        for name, value in vars(validation).items()
        if name.isupper() and isinstance(value, str) and name.startswith(("VALID_", "INCOMPLETE_", "INVALID_"))
    }

    assert in_code, "no pair status constants found, so this test proves nothing"
    assert in_code <= documented, sorted(in_code - documented)
    # historical_unpaired is a label for pre-E rows and has no constant; the
    # document may carry it and nothing else beyond the validator's set.
    assert documented - in_code <= {"historical_unpaired"}, sorted(documented - in_code)


def test_the_documented_gate_figures_are_the_figures_computed():
    """The five names in the document are the five keys the validator returns.

    Mutation applied to docs/benchmark-cycle.v1.md: dropping
    expected_block_prompts_reset from the list, 1 failure (this test).
    """
    validation = _module("pair_validation_figures", "tools/pair_validation.py")

    figures, reason = validation.gate_figures(
        {
            "counters": {"expected_block_prompts_forwarded": 40},
        },
        {"content_block_prompts": 38, "jailbreaks_leaked": 2},
    )
    assert figures is not None, reason

    documented = set(_backticked_list(_cycle(), "And, for pairs published before SIR 2.5"))
    assert set(figures) <= documented, sorted(set(figures) - documented)


def test_the_documented_baseline_counters_are_the_counters_derived(published_pair):
    """terminology.md names what a baseline record carries, from the deriver.

    The rows come from a real published baseline ledger rather than a
    fabricated one, because the deriver dispatches on whether the ledger
    classifies as a baseline, and a hand-made row set that failed that
    classification would send this test down the gated branch and pass for the
    wrong reason.

    Mutation applied to docs/terminology.md: removing
    expected_allow_prompts_forwarded from the list, 1 failure (this test).
    """
    import json

    itgl = _module("itgl_documents", "tools/itgl.py")
    terms = TERMS.read_text(encoding="utf-8")

    ledger = (
        published_pair["runs_dir"]
        / published_pair["baseline_run_id"]
        / "proofs/itgl_ledger.jsonl"
    )
    rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert itgl.is_baseline_ledger(rows), "the fixture's baseline ledger no longer classifies"

    counters = itgl.derive_counters(rows)
    assert counters, "the deriver returned nothing for a baseline ledger"

    for counter in counters:
        assert f"`{counter}`" in terms, counter

    # And the gated counters are not named as a record's, because it has none.
    for absent in ("jailbreaks_leaked", "harmless_blocked", "content_evaluated"):
        assert absent not in counters, absent


def test_the_valid_cycle_requires_one_signed_document_of_either_kind():
    """It required audit.json of every archive, which no longer describes one.

    Mutations applied to docs/benchmark-cycle.v1.md, both detected: restoring
    the bare audit.json requirement, 1 failure (this test); dropping the
    mention of baseline.json from the criteria, 1 failure (this test).
    """
    document = _cycle()
    criteria_start = document.index("## Valid benchmark cycle criteria")
    criteria = document[criteria_start : document.index("\n## ", criteria_start)]

    assert "`baseline.json`" in criteria
    assert "`audit.json`" in criteria
    assert re.search(r"^  - `audit\.json`$", criteria, flags=re.MULTILINE) is None, (
        "the criteria require audit.json of every archive, which an ungated "
        "baseline does not have"
    )
    assert "benchmark_index.v3.json" in criteria
    assert "spec/benchmark_index.v3.schema.json" in criteria


def test_benchmark_is_still_not_a_proof_class():
    """The line stays. 2.5 gives the baseline its own document, not a class.

    An earlier design would have added a fourth proof class for baselines. It
    was not taken, and the reason is in
    claude/2.5-decision-baseline-record-2026-10-14.md: a proof class is a claim
    about firewall behaviour, and a run with no gate in it makes none.
    """
    assert "Benchmark is not a proof class" in _cycle()


@pytest.mark.parametrize("term", ["FORWARDED", "baseline.json", "audit.json"])
def test_terminology_names_what_a_reader_will_meet(term):
    """The vocabulary the archives use is defined where the vocabulary lives."""
    assert term in TERMS.read_text(encoding="utf-8")


def test_the_record_is_named_as_carrying_no_result_in_both_documents():
    """The one property every reader of these documents has to come away with."""
    for path in (CYCLE, TERMS):
        text = path.read_text(encoding="utf-8")
        assert "no result and no proof class" in text, path.name
