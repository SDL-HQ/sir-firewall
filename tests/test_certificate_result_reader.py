"""tools/read_certificate_result.py, executed rather than reconstructed.

The workflow's finalize step fails CI unless this script's output is exactly
"AUDIT PASSED". Everything else must therefore be a value that cannot equal it,
must say which failure it was, and must not raise.

Three defects are recorded in these tests, all found by an independent review on
13 October 2026 and none by the first version of this file:

  the reader returned result.strip(), so " \\nAUDIT PASSED\\t" was reported as a
  pass and the job went green on a malformed field;

  print() raised UnicodeEncodeError on a lone surrogate, exiting non-zero under
  set -e before the step could report anything, while the docstring said the
  script never raises;

  the subprocess helper here called .strip() on stdout, so no test could have
  observed either of the above.

Nothing here strips. Output is compared raw, and the line count is asserted,
because "prints exactly one line" is the property the shell comparison rests on.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "read_certificate_result.py"
PASS = "AUDIT PASSED"


def run_raw(path: str | Path) -> str:
    """Exactly what the shell's command substitution would capture."""
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
    assert completed.stdout.endswith("\n"), "output is not a terminated line"
    assert completed.stdout.count("\n") == 1, (
        "the reader printed more than one line, so the shell comparison is "
        f"against text whose shape the caller does not control: {completed.stdout!r}"
    )
    return completed.stdout[:-1]


def write(tmp_path, payload_text: str) -> Path:
    path = tmp_path / "audit.json"
    path.write_text(payload_text, encoding="utf-8")
    return path


@pytest.mark.parametrize("result", ["AUDIT PASSED", "AUDIT FAILED", "INCONCLUSIVE"])
def test_each_real_verdict_is_reported_unchanged(tmp_path, result):
    """The three strings _compute_audit_result can return, and no others."""
    assert run_raw(write(tmp_path, json.dumps({"result": result}))) == result


@pytest.mark.parametrize(
    "result",
    [
        " AUDIT PASSED",
        "AUDIT PASSED ",
        "\nAUDIT PASSED",
        "AUDIT PASSED\t",
        " \nAUDIT PASSED\t",
        "audit passed",
        "Audit Passed",
        "AUDIT  PASSED",
        "AUDIT PASSED\nINCONCLUSIVE",
        "INCONCLUSIVE\nAUDIT PASSED",
    ],
)
def test_a_result_that_is_not_exactly_a_verdict_is_not_a_pass(tmp_path, result):
    """Whitespace, case and extra lines are not repaired into a verdict.

    The reader returned result.strip() until 13 October 2026, so the first five
    of these were reported as AUDIT PASSED and the job went green. A malformed
    result field is not evidence of a passing run.
    """
    output = run_raw(write(tmp_path, json.dumps({"result": result})))

    assert output != PASS, (
        f"a result of {result!r} was normalised into a pass; the gate accepts "
        "exactly one string and must not be the thing that repairs its input"
    )
    assert output.startswith("UNEXPECTED"), output


def test_an_unexpected_result_is_reported_with_its_actual_value(tmp_path):
    """So a failure says what was in the certificate, not merely that it failed."""
    output = run_raw(write(tmp_path, json.dumps({"result": "AUDIT PASSED "})))
    assert "AUDIT PASSED " in output or "AUDIT PASSED\\x20" in output or "'AUDIT PASSED '" in output


def test_a_lone_surrogate_does_not_raise(tmp_path):
    """print() raised UnicodeEncodeError on this and exited 1.

    Failing closed is the safe direction, but the script said it never raises
    and these tests asserted returncode zero, so the claim and the test agreed
    with each other and not with the code.
    """
    path = tmp_path / "audit.json"
    path.write_text('{"result":"\\ud800"}', encoding="utf-8")

    output = run_raw(path)

    assert output != PASS
    assert output.startswith("UNEXPECTED")
    assert output.isascii(), (
        "the reader emitted a character stdout may not be able to encode"
    )


@pytest.mark.parametrize(
    "payload_text",
    [
        "{}",
        '{"result": ""}',
        '{"result": "   "}',
        '{"result": null}',
    ],
)
def test_a_certificate_with_no_usable_result_reports_absent(tmp_path, payload_text):
    assert run_raw(write(tmp_path, payload_text)) == "ABSENT"


@pytest.mark.parametrize("payload_text", ['{"result": true}', '{"result": 0}', '{"result": 1}'])
def test_a_non_string_result_is_not_read_as_a_pass(tmp_path, payload_text):
    """A JSON true is truthy and 1 equals True in Python; neither is a verdict."""
    output = run_raw(write(tmp_path, payload_text))
    assert output != PASS
    assert output.startswith("UNEXPECTED"), output


def test_malformed_json_names_the_parse_failure(tmp_path):
    output = run_raw(write(tmp_path, "{not json"))
    assert output.startswith("UNREADABLE")
    assert "JSONDecodeError" in output
    assert output != PASS


def test_an_absent_file_is_unreadable(tmp_path):
    output = run_raw(tmp_path / "does-not-exist.json")
    assert output.startswith("UNREADABLE")
    assert output != PASS


def test_a_directory_is_unreadable(tmp_path):
    target = tmp_path / "audit.json"
    target.mkdir()
    output = run_raw(target)
    assert output.startswith("UNREADABLE")
    assert output != PASS


def test_a_json_document_that_is_not_an_object_is_unreadable(tmp_path):
    output = run_raw(write(tmp_path, json.dumps(["AUDIT PASSED"])))
    assert output.startswith("UNREADABLE")
    assert output != PASS


def test_a_nested_result_is_not_found(tmp_path):
    """Only the top-level field is a verdict."""
    output = run_raw(write(tmp_path, json.dumps({"certificate": {"result": "AUDIT PASSED"}})))
    assert output == "ABSENT"


def test_no_argument_and_too_many_arguments_are_reported(tmp_path):
    for argv in ([], [str(tmp_path / "a.json"), str(tmp_path / "b.json")]):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), *argv], capture_output=True, text=True, check=False
        )
        assert completed.returncode == 0
        assert completed.stdout.strip().startswith("UNREADABLE")


def test_the_workflow_runs_the_script_in_the_step_that_compares_the_result():
    """Keyed to the invocation, not to the filename appearing anywhere.

    The first version asserted the filename was present in the workflow text,
    which this file's own explanatory comments satisfy. Replacing the call with
    inline parsing under another name, leaving the comments, passed it.
    """
    workflow = (ROOT / ".github" / "workflows" / "audit-and-sign.yml").read_text(encoding="utf-8")
    finalize = workflow[workflow.index("Finalize CI status"):]
    finalize = finalize[: finalize.index("\n  benchmark-dispatch:")]

    invocations = [
        line for line in finalize.splitlines()
        if "read_certificate_result.py" in line and "#" not in line.split("read_certificate_result.py")[0]
    ]
    assert invocations, (
        "the finalize step does not run the reader outside a comment, so "
        "whatever it uses to read the certificate is untested"
    )
    assert any("cert_result=" in line for line in invocations), (
        "the reader's output is not what cert_result is assigned from"
    )
    assert "json.load(" not in finalize, (
        "the finalize step parses the certificate inline as well, which is the "
        "copy the script exists to remove"
    )
