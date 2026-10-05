"""The release checklist gate must fail closed, and must not accept prose as evidence."""

import json
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
