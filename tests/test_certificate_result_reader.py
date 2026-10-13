"""tools/read_certificate_result.py, executed rather than reconstructed.

The workflow's finalize step fails CI unless the certificate's own result is
exactly "AUDIT PASSED". Everything else must therefore be something other than
that string, and must say which failure it was: until 13 October 2026 this was
an inline `python -c` that raised on malformed JSON and printed an empty string
for a missing result, so two different failures looked the same and one of them
arrived as a traceback.

These run the real script as a subprocess, the way the job does.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "read_certificate_result.py"


def run(path: str | Path) -> str:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, (
        "the reader exited non-zero, so under set -e the job fails before the "
        f"step can report what the certificate said: {completed.stderr}"
    )
    return completed.stdout.strip()


def test_a_passing_certificate_reports_its_own_result(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps({"result": "AUDIT PASSED"}), encoding="utf-8")
    assert run(path) == "AUDIT PASSED"


@pytest.mark.parametrize("result", ["AUDIT FAILED", "INCONCLUSIVE"])
def test_a_non_passing_certificate_reports_its_own_result(tmp_path, result):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps({"result": result}), encoding="utf-8")
    assert run(path) == result


def test_malformed_json_names_the_parse_failure_rather_than_raising(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text("{not json", encoding="utf-8")

    output = run(path)

    assert output.startswith("UNREADABLE"), (
        "a malformed certificate must report that it was unreadable; printing "
        "nothing would make it indistinguishable from a missing result"
    )
    assert "JSONDecodeError" in output, (
        "the reason a certificate could not be read is the actionable part"
    )
    assert output != "AUDIT PASSED"


def test_an_absent_file_is_unreadable_and_not_a_pass(tmp_path):
    output = run(tmp_path / "does-not-exist.json")
    assert output.startswith("UNREADABLE")
    assert output != "AUDIT PASSED"


def test_a_directory_is_unreadable_and_not_a_pass(tmp_path):
    target = tmp_path / "audit.json"
    target.mkdir()
    output = run(target)
    assert output.startswith("UNREADABLE")
    assert output != "AUDIT PASSED"


def test_a_json_document_that_is_not_an_object_is_unreadable(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(["AUDIT PASSED"]), encoding="utf-8")
    output = run(path)
    assert output.startswith("UNREADABLE")
    assert output != "AUDIT PASSED"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"result": ""},
        {"result": "   "},
        {"result": None},
        {"result": True},
        {"result": 0},
    ],
)
def test_a_certificate_with_no_usable_result_reports_absent(tmp_path, payload):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    output = run(path)

    assert output == "ABSENT", (
        "a certificate carrying no result must say so; an empty string reads as "
        "a value and would be reported as a disagreement with no cause named"
    )


def test_a_truthy_non_string_result_is_not_read_as_a_pass(tmp_path):
    """A JSON `true` is truthy, and must not become a verdict."""
    path = tmp_path / "audit.json"
    path.write_text(json.dumps({"result": True}), encoding="utf-8")
    assert run(path) != "AUDIT PASSED"


def test_the_workflow_invokes_the_script_rather_than_carrying_a_copy():
    """Same contract as tests/test_execution_accounting.py keeps for the verdict script."""
    workflow = (ROOT / ".github" / "workflows" / "audit-and-sign.yml").read_text(encoding="utf-8")

    assert "tools/read_certificate_result.py" in workflow, (
        "the finalize step does not call the reader, so whatever it calls "
        "instead is untested"
    )
    assert "json.load(open(" not in workflow, (
        "the finalize step parses the certificate inline again, which is the "
        "copy this script exists to remove"
    )
