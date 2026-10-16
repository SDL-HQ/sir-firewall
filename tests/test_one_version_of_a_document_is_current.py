"""Exactly one version of a versioned document is current, and everything agrees.

On 15 October 2026 four documents were found to have drifted from the code
they described, in one session. Two of those were this shape: three documents
each named a different benchmark index as current, and two named a superseded
evidence contract. Nothing was wrong with any individual file. What was wrong
was that no single thing decided which version a reader should open, so each
document answered for itself and they diverged.

Versioned families in this repository are `docs/evidence-perimeter.vN.md` and
`proofs/runs/benchmark_index.vN.json`. This holds three properties for each:

- the highest version present is the current one, and it does not call itself
  historical or superseded;
- every lower version says it is not current and points at the highest one, so
  a reader who opens an old file is told where to go in the file itself rather
  than having to compare filenames;
- every statement anywhere in the repository about which version is current
  names the same version.

The third is the one that catches the 15 October case, and it is deliberately
narrower than "no document mentions an old version". Mentioning one is normal
and necessary: the release notes record which perimeter a release added, the
backlog records a defect in v4, `docs/archive/README.md` is an index of the
archived versions, and several tests record a mutation applied to the document
a release ago. A first draft of this test forbade all of those and flagged five
legitimate files, which is how a guard becomes something people route around.
What is held instead is the narrow thing that actually went wrong: a line that
tells a reader which version to read now must not name a superseded one.

Mutations measured on 16 October 2026, each run against the full file:

- point a document's live reference back at the superseded perimeter:
  `test_every_statement_of_currency_names_the_same_version` fails (1 failed).
- remove the superseded banner from the previous perimeter:
  `test_every_superseded_version_says_so_and_points_forward` fails (1 failed).
- leave a superseded version's banner pointing at the version before the
  current one: that test and the currency test fail (2 failed).
- add a superseded banner to the current perimeter:
  `test_the_highest_version_does_not_call_itself_historical` fails, and so does
  the currency test, because the banner then offers the previous version
  (2 failed).

Writing it found one live instance.
`docs/archive/d5-benchmark-first-cycle-review.md` told a reader that for the
current benchmark contract and surfaces they should use
`docs/runs/benchmark_index.v2.json`. v3 has been current since 2.5. It is the
same defect as the three documents on 15 October, sitting in an archived
document nobody had cause to re-read, which is where this one will keep
appearing.
"""

import re
from pathlib import Path


def pathlib_name(path: str) -> str:
    return Path(path).name


def pathlib_suffix(pattern: str) -> str:
    return Path(pattern).suffix

import pytest

ROOT = Path(__file__).resolve().parents[1]

FAMILIES = {
    "evidence perimeter": (ROOT / "docs", "evidence-perimeter.v*.md"),
    "benchmark index": (ROOT / "proofs/runs", "benchmark_index.v*.json"),
}

HISTORICAL = ("historical", "not the current authoritative state", "superseded")

# A mention that records what a version said, or what was changed in it, rather
# than offering it to a reader as current. Each is here because removing it
# would make a true record unwritable, not to get a file past this test.
# A line is a currency statement when it contains one of these next to a
# version of the family. Everything else is a mention, and mentions are fine.
# "latest" is deliberately absent: it appears inside quotations of what an
# older document said, and matching it flagged a backlog row that records
# exactly that.
CURRENCY = ("current", "authoritative", "up to date")

def _versions(directory: Path, pattern: str) -> dict:
    found = {}
    for path in sorted(directory.glob(pattern)):
        matched = re.search(r"\.v(\d+)\.", path.name)
        if matched:
            found[int(matched.group(1))] = path
    return found


FAMILY_CASE = pytest.mark.parametrize("family", sorted(FAMILIES))


def test_each_family_has_versions_to_compare():
    """Guard the guard. A moved directory must not make this vacuous."""
    for family, (directory, pattern) in FAMILIES.items():
        versions = _versions(directory, pattern)
        assert len(versions) >= 2, f"{family}: found {sorted(versions)}"


@FAMILY_CASE
def test_the_highest_version_does_not_call_itself_historical(family):
    directory, pattern = FAMILIES[family]
    versions = _versions(directory, pattern)
    current = versions[max(versions)]
    head = current.read_text(encoding="utf-8")[:1200].lower()

    for marker in HISTORICAL:
        assert marker not in head, (
            f"{current.name} is the highest version of the {family} and so is "
            f"the current one, but its opening says {marker!r}"
        )


@FAMILY_CASE
def test_every_superseded_version_says_so_and_points_forward(family):
    directory, pattern = FAMILIES[family]
    versions = _versions(directory, pattern)
    if not any(path.suffix == ".md" for path in versions.values()):
        pytest.skip(f"{family} carries no prose to hold a banner")
    highest = max(versions)
    current = versions[highest].name

    for number, path in sorted(versions.items()):
        if number == highest:
            continue
        head = path.read_text(encoding="utf-8")[:1200]
        assert any(marker in head.lower() for marker in HISTORICAL), (
            f"{path.name} is superseded by {current} and does not say so in its "
            "opening, so a reader who opens it is not told"
        )
        assert current in head, (
            f"{path.name} says it is superseded but points at something other "
            f"than {current}"
        )


@FAMILY_CASE
def test_every_statement_of_currency_names_the_same_version(family):
    """The 15 October case: three documents, three different current versions."""
    directory, pattern = FAMILIES[family]
    versions = _versions(directory, pattern)
    highest = max(versions)
    stem = pattern.split(".v*")[0]
    named = re.compile(rf"{re.escape(stem)}[. ]?v(\d+)", re.IGNORECASE)
    # A line that has already named the family often continues in shorthand,
    # as docs/engineer-guide.md does with "`.v2.json` and `.v3.json`". Reading
    # only the qualified form saw one version where the line listed three.
    shorthand = re.compile(rf"\.v(\d+){re.escape(pathlib_suffix(pattern))}")

    searched = [
        path
        for path in [
            *(ROOT / "docs").rglob("*.md"),
            *(ROOT / "tests").glob("*.py"),
            *(ROOT / "tools").glob("*.py"),
            ROOT / "README.md",
        ]
        if path.is_file()
        and path.name != pathlib_name(__file__)
        and "runs/" not in str(path.relative_to(ROOT))
    ]

    offenders = {}
    for path in searched:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            if not any(word in lowered for word in CURRENCY):
                continue
            mentioned = {int(v) for v in named.findall(line)}
            if mentioned:
                mentioned |= {int(v) for v in shorthand.findall(line)}
            if not mentioned or highest in mentioned:
                continue
            offenders.setdefault(str(path.relative_to(ROOT)), []).append(
                f"{number}: {line.strip()[:110]}"
            )

    assert not offenders, (
        f"these state which {family} version is current and name one that is "
        f"not v{highest}. Either point them at the current version, or reword "
        f"the line so it records what that version said rather than offering "
        f"it to a reader now: {offenders}"
    )


def test_the_searched_set_is_not_empty():
    """Guard the guard again: a bad filter would make the sweep pass silently."""
    searched = [p for p in (ROOT / "docs").rglob("*.md") if p.is_file()]

    assert len(searched) > 30, len(searched)
    assert (ROOT / "README.md").is_file()
