"""The counter names mean less than they sound like, and the docs must say so.

SIR is a pre-inference gate and never reads model output. `jailbreaks_leaked`
counts expected-block benchmark rows the gate allowed; "leak" ordinarily means a
downstream disclosure, which is a class of event this system cannot observe.
`harmless_blocked` counts allow-labelled rows the gate blocked, over a corpus's
denominator rather than any real workload. `AUDIT PASSED` describes one run.

Until 13 October 2026 no surface defined any of the three, while all three
appeared in the repository description, in every signed certificate and on every
published run page. An independent review named it as the terminology change
most likely to improve the project's credibility.

These names cannot be corrected cheaply: they are evidence-contract fields and
signed counters inside the published archive, so renaming is a contract change
with an archive migration behind it. Defining them is free. This file holds the
definitions in place, and holds the surfaces that publish the figures pointing
at them, because every other published figure in this project drifted the moment
its correctness depended on someone remembering.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TERMINOLOGY = ROOT / "docs" / "terminology.md"

# Surfaces that present a counter figure to a reader and must point at the
# definition. Not every file mentioning the word: the ones where a reader meets
# the number and could carry the stronger meaning away.
POINTING_SURFACES = (
    Path("README.md"),
    Path("docs/assurance-kit.md"),
)


def _terminology() -> str:
    return TERMINOLOGY.read_text(encoding="utf-8")


def _flowed(text: str) -> str:
    """Collapse whitespace before matching a phrase.

    Markdown wraps. The first version of the surface assertion below looked for
    a phrase that the README carries across a line break, so it failed on
    correct prose. A test keyed to where a sentence happens to wrap is noise.
    """
    return " ".join(text.split())


def test_the_terminology_note_states_that_sir_never_observes_model_output():
    """The fact the whole distinction rests on."""
    text = _flowed(_terminology()).lower()
    assert "never observes model output" in text, (
        "docs/terminology.md no longer states that SIR does not observe model "
        "output, which is the premise that makes 'leak' the wrong word"
    )


@pytest.mark.parametrize(
    "counter,must_say",
    [
        ("jailbreaks_leaked", ("expected-block", "allowed")),
        ("harmless_blocked", ("allow", "blocked")),
    ],
)
def test_each_counter_is_defined_by_what_it_counts(counter, must_say):
    text = _terminology()
    assert f"### `{counter}`" in text, (
        f"docs/terminology.md carries no definition section for {counter}"
    )
    section = text[text.index(f"### `{counter}`") :]
    section = section[: section.index("\n### ")] if "\n### " in section else section

    assert "**What it counts:**" in section, (
        f"{counter}'s section does not say what it counts"
    )
    assert "**What it does not mean:**" in section, (
        f"{counter}'s section does not say what it does not mean, which is the "
        "half that removes the misreading"
    )
    for phrase in must_say:
        assert phrase in section.lower(), (
            f"{counter}'s definition does not mention {phrase!r}"
        )


def test_the_passing_verdict_is_defined_as_being_about_one_run():
    text = _terminology()
    assert "### `AUDIT PASSED`" in text, (
        "docs/terminology.md does not define the passing verdict, which is the "
        "figure most likely to be read as an adequacy claim"
    )
    section = text[text.index("### `AUDIT PASSED`") :]
    assert "**What it does not mean:**" in section
    assert "adequate" in section.lower(), (
        "the verdict's definition does not address adequacy, which is the "
        "inference a reader draws from it"
    )


@pytest.mark.parametrize("surface", POINTING_SURFACES, ids=lambda p: str(p))
def test_a_surface_publishing_the_counters_points_at_their_definition(surface):
    """A figure published without its definition is the misreading, restored."""
    text = _flowed((ROOT / surface).read_text(encoding="utf-8"))

    assert "terminology.md" in text, (
        f"{surface} publishes the counters without pointing at their definition"
    )
    assert "never observes model output" in text, (
        f"{surface} does not state that SIR never observes model output, so a "
        "reader meeting the leak figure there carries the stronger meaning away"
    )


def test_the_rename_is_recorded_as_a_contract_change_rather_than_promised():
    """So the definition is not read as an intention to rename.

    The proof class name is handled the same way in this file: kept, with the
    conditions a rename would have to satisfy written down. A counter rename is
    strictly more expensive, because the old values are inside signed
    certificates rather than only in the contract.
    """
    text = _terminology()
    section = text[text.index("### `jailbreaks_leaked`") :]
    section = section[: section.index("### `harmless_blocked`")]

    assert "contract" in section.lower(), (
        "the note does not record why the name is kept, so a reader cannot tell "
        "whether it is an oversight or a decision"
    )
    assert "certificates" in section.lower()
