"""Release notes state this suite's size, so the suite checks that statement.

docs/release-notes-2.4.0.md said "the suite is 754 tests" in two places on the
day it was prepared for tagging, by which time it was 913. The figure had been
correct when typed and nothing re-derived it, which is the defect that release
spent four review rounds removing from the archive figures, the coverage table
and the specification's suite table. It survived in the release notes' own
description of itself.

Until 14 October 2026 this file held every stated figure against the live
collected count. That is right for notes being written and wrong for notes
already published. The first commit after the 2.4.0 tag to add a test turned
these notes red, and the only way to green was to retype a published
document's account of a release it no longer described. A test that makes the
honest state of the repository red, and a false statement green, is pointed
the wrong way round.

So a figure in released notes is now written as what it is: a fact about a
tag. What this file holds is that such a figure has not moved since that tag,
which is cheap and needs no collection. Notes for a version with no tag yet
are still live, and their figure is held against the collected count.

The figure's truth at the tag is established once, when the release is cut,
by collecting in the tree being released. This file does not re-derive it:
that would mean building a worktree at the tag on every run, and the tag is
the thing any reader can check it against. What this file prevents is the
figure changing afterwards while the tag does not.

Collected count rather than passed count, because a skip is still a test the
reader is being told about, and because the passed count depends on the
environment while the collected count depends on the repository.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOTES_DIR = ROOT / "docs"

# "The suite was 916 tests at the v2.4.0 tag": a fact about a tag.
FROZEN = re.compile(r"(?:suite was|It was) ([\d,]+) tests at the (v[\d.]+) tag")
# "The suite is 916 tests": a claim about the tree the reader is holding.
LIVE = re.compile(r"(?:suite is|It is) ([\d,]+) tests")
# Any figure at all, used to compare a file against its own tag without
# depending on how the sentence around it is phrased.
ANY_FIGURE = re.compile(r"([\d,]+) tests")


def _notes_files() -> list[Path]:
    return sorted(NOTES_DIR.glob("release-notes-*.md"))


def _version_of(path: Path) -> str:
    return "v" + path.name[len("release-notes-"):-len(".md")]


def _tags() -> set[str]:
    completed = subprocess.run(
        ["git", "tag", "--list"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def _figures(text: str, pattern: re.Pattern[str]) -> list[str]:
    return [match[0] if isinstance(match, tuple) else match
            for match in pattern.findall(text.replace(",", ""))]


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


TAGS = _tags()
NOTES = _notes_files()


def test_the_notes_state_a_suite_size_somewhere():
    """Guard the guard. If every figure goes, this says so rather than passing."""
    stated = [path.name for path in NOTES
              if _figures(path.read_text(encoding="utf-8"), ANY_FIGURE)]

    assert stated, (
        "no release-notes file states a suite size in a form this test "
        "recognises. If the figures were removed deliberately, remove this "
        "test with them; if they were reworded, update the patterns here"
    )


def test_this_clone_can_see_its_tags():
    """Guard the guard. Without tags the frozen check below establishes nothing.

    A checkout with no tags cannot tell a released note from an unreleased one,
    and would read every published figure as a live claim. The workflows that
    run this suite fetch the full history for that reason.
    """
    assert TAGS, (
        "this clone has no tags, so a released note cannot be told from an "
        "unreleased one. The checkout needs fetch-depth: 0"
    )


@pytest.mark.parametrize("path", NOTES, ids=[path.name for path in NOTES])
def test_a_released_note_states_its_figure_as_a_fact_about_its_tag(path: Path):
    """A published document should not describe a tree that has moved past it."""
    if _version_of(path) not in TAGS:
        pytest.skip(f"{_version_of(path)} is not tagged, so its notes are still live")

    text = path.read_text(encoding="utf-8")
    live = _figures(text, LIVE)

    assert not live, (
        f"{path.name} is published at {_version_of(path)} and states {live} as a "
        "present-tense suite size. Every test added afterwards makes that "
        "sentence false, and correcting it rewrites what the release said. "
        "State it as the figure at the tag instead"
    )


@pytest.mark.parametrize("path", NOTES, ids=[path.name for path in NOTES])
def test_a_figure_in_released_notes_has_not_moved_since_its_tag(path: Path):
    """The point of anchoring a figure to a tag is that the tag can be checked."""
    tag = _version_of(path)
    if tag not in TAGS:
        pytest.skip(f"{tag} is not tagged")

    relative = path.relative_to(ROOT).as_posix()
    completed = subprocess.run(
        ["git", "show", f"{tag}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip(f"{relative} does not exist at {tag}")

    now = sorted(_figures(path.read_text(encoding="utf-8"), ANY_FIGURE))
    at_tag = sorted(_figures(completed.stdout, ANY_FIGURE))

    assert now == at_tag, (
        f"{path.name} states {now} tests and the same file at {tag} states "
        f"{at_tag}. The release is what it was; correct the sentence around the "
        "figure rather than the figure"
    )


@pytest.mark.parametrize("path", NOTES, ids=[path.name for path in NOTES])
def test_an_unreleased_note_states_the_size_of_the_suite_it_describes(path: Path):
    """Notes still being written describe this tree, so they are held to it."""
    if _version_of(path) in TAGS:
        pytest.skip(f"{_version_of(path)} is tagged, so its figures are history")

    stated = {int(figure) for figure in _figures(path.read_text(encoding="utf-8"), LIVE)}
    if not stated:
        pytest.skip(f"{path.name} states no live suite size")

    collected = _collected()
    assert stated == {collected}, (
        f"{path.name} states {sorted(stated)} tests and the suite collects "
        f"{collected}. Correct the notes rather than this assertion: a figure "
        "in a document that nothing re-derives is the defect this guards"
    )


@pytest.mark.parametrize("path", NOTES, ids=[path.name for path in NOTES])
def test_the_stated_size_is_consistent_wherever_it_appears(path: Path):
    """Two places said 754 and both were wrong, which one pass would have caught."""
    stated = set(_figures(path.read_text(encoding="utf-8"), ANY_FIGURE))

    assert len(stated) <= 1, (
        f"{path.name} states more than one suite size: {sorted(stated)}"
    )
