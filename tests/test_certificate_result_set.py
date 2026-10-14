"""tools/certificate_results.py is the only declaration of the recognised results.

The markers are exercised against it in
tests/test_audit_workflow_cannot_pass_without_verifying.py. This file holds the
declaration itself to two things: it names exactly what the certificate
generator can produce, and the result reader accepts exactly what it names.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from certificate_results import (  # noqa: E402
    KNOWN_RESULTS,
    RESULT_STATUS,
    UnrecognisedResult,
    status_for,
)

UNDECLARED = (
    "audit passed",
    " AUDIT PASSED",
    "AUDIT PASSED\n",
    "Inconclusive",
    "BASELINE COMPLETE",
    "PASS",
    "",
    None,
    17,
    ["AUDIT PASSED"],
)


def _generator_results() -> set[str]:
    """Every string _compute_audit_result can return, read from its source."""
    tree = ast.parse((TOOLS / "generate_certificate.py").read_text(encoding="utf-8"))
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_compute_audit_result"
    )
    results = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Return):
            assert isinstance(node.value, ast.Constant) and isinstance(node.value.value, str), (
                "_compute_audit_result returns something other than a string literal, "
                f"so its result set can no longer be read from source (line {node.lineno})"
            )
            results.add(node.value.value)
    return results


def test_the_declaration_is_exactly_what_the_generator_produces():
    """A declared value the generator never emits is an authorised verdict with no source.

    Adding a result to the generator without declaring it fails here as well,
    which is the point: a certificate result no reader recognises stops every
    marker, and should be caught before a run, not during one.
    """
    assert set(RESULT_STATUS) == _generator_results()
    assert KNOWN_RESULTS == tuple(RESULT_STATUS)


def test_only_one_result_passes():
    passing = [result for result, status in RESULT_STATUS.items() if status.audit_pass]
    assert passing == ["AUDIT PASSED"]


def test_inconclusive_is_never_a_pass():
    for result, status in RESULT_STATUS.items():
        assert not (status.audit_pass and status.inconclusive), result


@pytest.mark.parametrize("result", list(RESULT_STATUS))
def test_status_for_maps_each_declared_result(result):
    assert status_for(result) == RESULT_STATUS[result]


@pytest.mark.parametrize("result", UNDECLARED, ids=repr)
def test_status_for_refuses_everything_else(result):
    with pytest.raises(UnrecognisedResult):
        status_for(result)


def _reader(tmp_path, result) -> str:
    import json

    path = tmp_path / "audit.json"
    path.write_text(json.dumps({"result": result}), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(TOOLS / "read_certificate_result.py"), str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.rstrip("\n")


def test_the_reader_accepts_exactly_the_declared_results(tmp_path):
    """The CI finalize step's reader, run as the workflow runs it."""
    for result in RESULT_STATUS:
        assert _reader(tmp_path, result) == result
    for result in UNDECLARED:
        # Not "not in RESULT_STATUS": a reader with its own fourth value would
        # echo it back, and that echo is not in the declared set either.
        reported = _reader(tmp_path, result)
        assert reported.startswith(("UNEXPECTED (", "ABSENT")), (result, reported)


def test_the_reader_does_not_carry_its_own_copy():
    source = (TOOLS / "read_certificate_result.py").read_text(encoding="utf-8")
    assert "from certificate_results import KNOWN_RESULTS" in source
    assert '"AUDIT FAILED"' not in source and '"INCONCLUSIVE"' not in source
