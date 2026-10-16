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


def test_every_locked_pair_status_says_what_produces_it():
    """A locked label with no stated cause tells a reader nothing.

    The statuses were locked as a bare list of six labels, with nothing saying
    which case reaches which, so the two cases 2.5 added, a baseline half that
    is not a record and halves that cover different row counts, had no stated
    home. The
    table is pinned to the locked list in both directions: a status gaining a
    row it does not have, or a row for a status that does not exist, fails
    here.

    Checked on 15 October 2026 against three mutations of docs/benchmark-cycle.v1.md,
    each applied in place and reverted in a `finally` whose revert was
    confirmed by hashing the file before and after. Each count is this file's:

        1. a status loses its row in the table       1 failed
        2. a row names a status nothing produces     1 failed
        3. a cause is reduced to one word            1 failed
    """
    document = _cycle()
    locked = set(_backticked_list(document, "### Pair status values (locked)"))
    assert locked, "the locked list was not found, so this test proves nothing"

    start = document.index("| Status | Produced when |")
    rest = document[start:]
    end = rest.find("\n\n")
    table = rest if end < 0 else rest[:end]
    rows = re.findall(r"^\| `([a-z_]+)` \| (.+?) \|$", table, flags=re.MULTILINE)
    described = {status for status, _ in rows}

    assert described == locked, {
        "in the table and not locked": sorted(described - locked),
        "locked and not in the table": sorted(locked - described),
    }
    for status, cause in rows:
        assert len(cause.split()) >= 8, (status, cause)


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


PERIMETER = ROOT / "docs/evidence-perimeter.v6.md"
REGISTER = ROOT / "docs/claims-register.md"


def test_the_perimeter_reports_no_baseline_leak_count():
    """A leak is a gated-run figure. On an ungated run it is the label count.

    The perimeter carried "ungated leaks 100", "ungated leaks 27" and
    "ungated leaks 26" as current evidence while its own method note said a
    pre-2.5 baseline result described a gate that was not in the path. The
    document disclaimed the reading at the top and relied on it below, which
    is the E7 defect restated inside a published document. Found by a parallel
    review on 15 October 2026, after the method note was added without the
    body being read.

    Mutations applied to the perimeter, v5 at the time and carried into v6
    unchanged, both detected:
    restoring an "ungated leaks" figure, 1 failure (this test); restoring the
    "SIR off vs on" conclusion, 1 failure (this test).
    """
    text = PERIMETER.read_text(encoding="utf-8")

    assert "ungated leaks" not in text
    assert "ungated baseline leaks" not in text
    assert "distinguish SIR off vs on" not in text
    # And the figures that replaced them say what they count.
    assert "prompts labelled for blocking" in text


def test_the_perimeter_withdraws_the_cross_model_reading():
    """Both ID sets are model-independent by construction, so neither observes one.

    Mutation applied to the perimeter, v5 at the time and carried into v6
    unchanged: restoring
    "common-mode prompt-layer vulnerability" as something the finding
    supports, 1 failure (this test).
    """
    text = PERIMETER.read_text(encoding="utf-8")

    assert "identical across models" in text
    assert "by construction" in text
    # The withdrawn readings may be named as withdrawn, never as supported.
    supported = text.split("What this supports:", 1)[1].split("What this does not support:", 1)[0]
    for withdrawn in ("common-mode", "model selection"):
        assert withdrawn not in supported, withdrawn


def test_the_register_covers_the_published_cross_model_finding():
    """The register opens by claiming every public technical claim, and had no row.

    The finding was published externally on 3 May 2026 and cited in the
    perimeter as current. A register that claims that coverage and omits a
    published claim is the defect it exists to find.

    Mutation applied to docs/claims-register.md: removing the row, 1 failure
    (this test).
    """
    text = REGISTER.read_text(encoding="utf-8")

    assert "Every public technical claim SIR makes" in text
    assert "identical failure sets" in text
    assert "x.com/SDL_HQ/status/2049438575574364279" in text
    # And it is not recorded as holding.
    row = text.split('### "Seven models, two providers, identical failure sets"', 1)[1]
    row = row.split("\n### ", 1)[0].split("\n## ", 1)[0]
    assert "**corrected" in row
    assert "by construction" in row
