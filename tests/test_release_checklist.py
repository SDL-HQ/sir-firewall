"""The release checklist gate must fail closed, and must not accept prose as evidence."""

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "check_release_checklist.py"


def _run(checklist: Path, root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), "--checklist", str(checklist), "--root", str(root), *extra],
        capture_output=True,
        text=True,
    )


def _write(tmp_path: Path, items: list[dict]) -> Path:
    path = tmp_path / "checklist.json"
    path.write_text(
        json.dumps({"checklist_version": "v1", "target_version": "test", "items": items}),
        encoding="utf-8",
    )
    return path


def test_open_item_blocks_the_merge(tmp_path):
    checklist = _write(tmp_path, [{"id": 0, "name": "x", "status": "open", "evidence": []}])
    assert _run(checklist, REPO).returncode == 1


def test_met_without_evidence_blocks_the_merge(tmp_path):
    checklist = _write(tmp_path, [{"id": 0, "name": "x", "status": "met", "evidence": []}])
    result = _run(checklist, REPO)
    assert result.returncode == 1
    assert "no evidence" in result.stderr


def test_prose_is_not_evidence(tmp_path):
    """A document explaining why an item is acceptable must not tick it."""
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "doc", "ref": "docs/key-custody.md"}],
            }
        ],
    )
    result = _run(checklist, REPO)
    assert result.returncode == 2
    assert "not permitted" in result.stderr


def test_missing_test_does_not_resolve(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "test", "ref": "tests/test_release_checklist.py::test_absent"}],
            }
        ],
    )
    result = _run(checklist, REPO)
    assert result.returncode == 2
    assert "test not defined" in result.stderr


def test_missing_artefact_does_not_resolve(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "artefact", "ref": "no/such/path"}],
            }
        ],
    )
    result = _run(checklist, REPO)
    assert result.returncode == 2
    assert "artefact not found" in result.stderr


def test_command_must_reach_its_stated_exit_code(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "command", "ref": "python3 -c \"raise SystemExit(3)\"", "expect_exit": 0}],
            }
        ],
    )
    result = _run(checklist, REPO, "--run-commands")
    assert result.returncode == 2
    assert "expected 0" in result.stderr


def test_resolving_evidence_passes(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [
                    {"type": "test", "ref": "tests/test_release_checklist.py::test_prose_is_not_evidence"},
                    {"type": "artefact", "ref": "tools/check_release_checklist.py"},
                    {"type": "command", "ref": "python3 -c \"pass\"", "expect_exit": 0},
                ],
            }
        ],
    )
    assert _run(checklist, REPO, "--run-commands").returncode == 0


def test_summary_only_never_fails(tmp_path):
    """The release branch reports status without blocking day-to-day work."""
    checklist = _write(tmp_path, [{"id": 0, "name": "x", "status": "open", "evidence": []}])
    assert _run(checklist, REPO, "--summary-only").returncode == 0


def test_the_real_checklist_is_wellformed():
    result = _run(REPO / "release-checklist.json", REPO, "--summary-only")
    assert result.returncode == 0
    assert "Release checklist for 2.4.0" in result.stdout


def test_command_evidence_never_reaches_a_shell(tmp_path):
    """The checklist is editable by anyone who can open a pull request.

    Command evidence is split into an executable and its arguments, so a shell
    metacharacter in the checklist is an argument rather than a second command.
    """
    marker = tmp_path / "side-effect"
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [
                    {
                        "type": "command",
                        "ref": f'python3 -c "pass" ; touch {marker}',
                        "expect_exit": 0,
                    }
                ],
            }
        ],
    )
    _run(checklist, REPO, "--run-commands")
    assert not marker.exists(), "a shell interpreted the checklist entry"


def test_a_tick_means_the_evidence_resolved_not_that_the_status_says_met(tmp_path):
    """The checkbox list and the count above it must not disagree.

    The mark was read from the status field alone, so an item claiming 'met'
    with evidence that did not resolve printed as [x] while the count said
    otherwise, and nothing in the list said which item was at fault. A tick that
    can be wrong is precisely what this file exists to prevent, and this one was
    wrong on item 9 on 8 October 2026 after a test was renamed.
    """
    checklist = _write(tmp_path, [
        {"id": 0, "name": "resolves", "status": "met",
         "evidence": [{"type": "artefact", "ref": "present.txt"}]},
        {"id": 1, "name": "claims met, does not resolve", "status": "met",
         "evidence": [{"type": "artefact", "ref": "absent.txt"}]},
        {"id": 2, "name": "open", "status": "open", "evidence": []},
    ])
    (tmp_path / "present.txt").write_text("x", encoding="utf-8")

    result = _run(checklist, tmp_path)
    # The mark is one character which may be a space, so the line is parsed by
    # shape rather than split on whitespace.
    marks = dict(
        (match.group(2), match.group(1))
        for match in (
            re.match(r"^  \[(.)\] (\S+)  ", line) for line in result.stdout.splitlines()
        )
        if match
    )

    assert "1 of 3 items met" in result.stdout
    assert marks == {"0": "x", "1": "!", "2": " "}, marks
    assert "marked met, but its evidence does not resolve" in result.stdout
    assert result.returncode != 0


def test_the_marks_and_the_count_always_agree(tmp_path):
    """Derived rather than asserted: the number of ticks is the number counted."""
    checklist = _write(tmp_path, [
        {"id": 0, "name": "a", "status": "met",
         "evidence": [{"type": "artefact", "ref": "present.txt"}]},
        {"id": 1, "name": "b", "status": "met",
         "evidence": [{"type": "artefact", "ref": "absent.txt"}]},
        {"id": 2, "name": "c", "status": "met", "evidence": []},
        {"id": 3, "name": "d", "status": "open", "evidence": []},
    ])
    (tmp_path / "present.txt").write_text("x", encoding="utf-8")

    result = _run(checklist, tmp_path)
    ticks = sum(1 for line in result.stdout.splitlines() if line.startswith("  [x]"))
    counted = int(result.stdout.split("items met")[0].split(":")[-1].strip().split(" of ")[0])

    assert ticks == counted == 1
