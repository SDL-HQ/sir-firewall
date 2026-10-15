"""No tracked file ships with merge conflict markers in it.

On 15 October 2026 a `git stash pop` left conflict markers in
`docs/backlog.md`, and the whole suite passed with them there: 1,410 tests, and
not one of them reads that document. The markers would have been committed, and
`docs/backlog.md` is a published document.

Nothing in the repository checked for this. It is the cheapest possible check
and it covers every tracked text file rather than the one that happened to be
hit, because the next one will be a different file.

The markers are built here rather than written literally, so this file does not
match itself.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Git's own markers are seven characters followed by a space or end of line.
MARKERS = ("<" * 7, "=" * 7, ">" * 7)

# Files whose content legitimately contains long runs of these characters.
TEXT_SUFFIXES = {
    ".md", ".py", ".json", ".yml", ".yaml", ".html", ".js", ".mjs", ".txt",
    ".csv", ".toml", ".cfg", ".sh", ".jsonl",
}


def _tracked_text_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\n")
    return [
        ROOT / rel
        for rel in listed
        if rel and (ROOT / rel).suffix in TEXT_SUFFIXES and (ROOT / rel).is_file()
    ]


def test_the_marker_shapes_are_what_git_writes():
    """Guard the guard: a typo in the markers would pass everything."""
    assert MARKERS == ("<<<<<<<", "=======", ">>>>>>>")
    sample = "a\n" + MARKERS[0] + " HEAD\nb\n" + MARKERS[1] + "\nc\n" + MARKERS[2] + " other\n"
    assert _conflicted(sample) == [2, 4, 6]


def _conflicted(text: str) -> list[int]:
    """Line numbers that begin a conflict marker, 1-based."""
    found = []
    for number, line in enumerate(text.split("\n"), start=1):
        for marker in MARKERS:
            if line == marker or line.startswith(marker + " "):
                found.append(number)
                break
    return found


def test_no_tracked_text_file_carries_a_conflict_marker():
    files = _tracked_text_files()
    assert len(files) > 100, f"only {len(files)} tracked text files found, so this proves little"

    offences = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        lines = _conflicted(text)
        if lines:
            offences[str(path.relative_to(ROOT))] = lines

    assert not offences, f"merge conflict markers in tracked files: {offences}"
