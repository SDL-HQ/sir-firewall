"""The release notes state this suite's size, so the suite checks it.

docs/release-notes-2.4.0.md said "the suite is 754 tests" in two places on the
day it was prepared for tagging, by which time it was 913. The figure had been
correct when typed and nothing re-derived it, which is the defect this release
spent four review rounds removing from the archive figures, the coverage table
and the specification's suite table. It survived in the release notes' own
description of itself.

Collected count rather than passed count, because a skip is still a test the
reader is being told about, and because the passed count depends on the
environment while the collected count depends on the repository.

This runs pytest as a subprocess. That costs a few seconds and is the price of
a published figure that cannot drift. If the collection cost ever matters more
than the figure, delete the figure from the notes rather than this test.

It counts itself. Adding this file moved the figure it guards by three, which
is correct rather than awkward: the stated number is the size of the suite a
reader would run, and that includes this. It also means the first run after
adding or removing any test fails here, which is the intended behaviour and not
a flake.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTES = ROOT / "docs" / "release-notes-2.4.0.md"


def _stated_counts() -> list[int]:
    text = NOTES.read_text(encoding="utf-8")
    return [int(match) for match in re.findall(r"(?:suite is|It is) ([\d,]+) tests", text.replace(",", ""))]


def _collected() -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"(\d+) tests collected", completed.stdout)
    assert match, (
        "could not read a collected count from pytest, so this test cannot "
        f"establish anything:\n{completed.stdout[-600:]}\n{completed.stderr[-400:]}"
    )
    return int(match.group(1))


def test_the_release_notes_state_a_suite_size():
    """Guard the guard. If the figure is removed, this says so rather than passing."""
    stated = _stated_counts()
    assert stated, (
        "the release notes no longer state a suite size in a form this test "
        "recognises. If the figure was removed deliberately, remove this test "
        "with it; if it was reworded, update the pattern here"
    )


def test_every_stated_suite_size_agrees_with_the_collected_count():
    collected = _collected()
    stated = _stated_counts()

    assert set(stated) == {collected}, (
        f"the release notes state {sorted(set(stated))} tests and the suite "
        f"collects {collected}. Correct the notes rather than this assertion: a "
        "figure in a published document that nothing re-derives is the defect "
        "this release is about."
    )


def test_the_stated_size_is_consistent_wherever_it_appears():
    """Two places said 754 and both were wrong, which one pass would have caught."""
    stated = _stated_counts()
    assert len(set(stated)) == 1, (
        f"the release notes state more than one suite size: {stated}"
    )
