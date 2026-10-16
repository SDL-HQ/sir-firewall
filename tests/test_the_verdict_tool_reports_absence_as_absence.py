"""A helper that is not there has not found anything.

`verify_evidence.py` runs four other tools as subprocesses and maps their exit
codes to statements about the archive. The tables are keyed on small integers,
and Python's own exit code for a file it cannot open is 2, which in
`CONTRACT_CODES` means "the certificate violates its applicable evidence
contract". So a copy of the tool without `validate_certificate_contract.py`
beside it reported that our own evidence breaks our own contract, when the
truth was that it could not find its own helper.

Found by shipping the tool into the evidence window without the helper, where
the wrong answer would have been public and would have been the most damaging
one available: a stranger running our verifier and being told by it that our
evidence is invalid. The failure is worse than the thing it falsely reports,
because a tool that calls sound evidence broken makes us look dishonest rather
than limited.

The tool's own docstring already had the rule: "Absence of evidence is
reported, not skipped" and "a missing receipt or manifest leaves the custody
property unestablished. It does not reduce the number of checks that had to
pass." The receipt path obeyed it. The contract path did not, because nothing
distinguished a helper's exit code from a helper that never ran.

Mutations measured on 16 October 2026:

- remove the `TOOL_MISSING` branch from `_classify`, leaving the sentinel to
  fall through to the table: 3 failed, 1 passed. The contract property goes
  back to "failed" and the verdict to FAILED.
- remove the `is_file` check from `_run`, so a missing helper is executed and
  exits 2: 3 failed, 1 passed. This is the original defect exactly.
- return `TOOL_MISSING` for a helper that is present: 4 failed, the control
  among them, because no property can then be established at all.

Predicted 2, 2 and 1 before measuring, and all three were higher: the
parametrised test covers two more helpers than the contract one, which is the
point of its existing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIGURES = json.loads((ROOT / "docs" / "archive-figures.json").read_text(encoding="utf-8"))

#: Everything the verdict tool needs to reach ESTABLISHED on a sound archive.
NEEDED = (
    "verify_evidence.py",
    "verify_certificate.py",
    "verify_baseline_record.py",
    "verify_archive_receipt.py",
    "validate_certificate_contract.py",
    "key_registry.py",
    "itgl.py",
    "document_signing.py",
)


def _sound_archive() -> str:
    """An archive whose every property the verdict tool can establish.

    Derived rather than named: the signed counters must have been recomputed,
    which is what separates ESTABLISHED from NOT ESTABLISHED for a
    certificate, and nothing incomplete or ungated qualifies.
    """
    pool = (
        set(FIGURES["binding_checked_and_holds"])
        - set(FIGURES["incomplete"])
        - set(FIGURES["receipt_signature_failed"])
        - set(FIGURES["legacy_ungated_certificates"])
    ) & set(FIGURES["counters_true"])
    assert pool, "no archive in the published figures establishes every property"
    return sorted(pool)[0]


def _rig(tmp_path: Path, *, omit: tuple = ()) -> tuple:
    """A copy of the tools and the one archive, outside the repository.

    Outside, because the point is a tool that does not have the repository
    around it. `verify_evidence.py` derives its root from its own location, so
    a copy run inside the checkout would find every helper regardless.
    """
    window = tmp_path / "window"
    (window / "tools").mkdir(parents=True)
    for name in NEEDED:
        if name in omit:
            continue
        shutil.copy2(ROOT / "tools" / name, window / "tools" / name)
    for directory in ("spec", "src"):
        shutil.copytree(
            ROOT / directory,
            window / directory,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    run = _sound_archive()
    shutil.copytree(
        ROOT / "docs" / "runs" / run,
        window / "archive",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    return window, run


def _verdict(window: Path) -> tuple:
    result = subprocess.run(
        [sys.executable, "-B", "tools/verify_evidence.py", "archive"],
        cwd=window,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(window / "src"), "PATH": "/usr/bin:/bin",
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    text = result.stdout + result.stderr
    verdict = next(
        (l.split(":", 1)[1].strip() for l in text.splitlines() if l.startswith("VERDICT:")),
        f"<none, exit {result.returncode}>",
    )
    return verdict, text


def test_the_archive_this_test_uses_does_establish_every_property(tmp_path):
    """The control. Without it, the test below passes for the wrong reason."""
    window, run = _rig(tmp_path)
    verdict, text = _verdict(window)
    assert verdict == "ESTABLISHED", (run, verdict, text[-600:])


def test_a_missing_helper_is_unknown_and_not_a_contract_violation(tmp_path):
    """The defect. Exit 2 from a missing file is not the certificate's fault."""
    window, run = _rig(tmp_path, omit=("validate_certificate_contract.py",))
    verdict, text = _verdict(window)

    assert verdict == "NOT ESTABLISHED", (run, verdict, text[-600:])
    assert "violates its applicable evidence contract" not in text, text[-600:]
    contract = [l for l in text.splitlines() if "evidence contract" in l]
    assert contract, text[-600:]
    assert "UNKNOWN" in contract[0], contract
    assert "validate_certificate_contract.py is not present" in contract[0], contract


@pytest.mark.parametrize("missing", ["verify_archive_receipt.py", "verify_certificate.py"])
def test_no_missing_helper_reads_as_a_finding_about_the_archive(tmp_path, missing):
    """The same hazard applies to every helper the tool executes, not one."""
    window, _ = _rig(tmp_path, omit=(missing,))
    verdict, text = _verdict(window)

    assert verdict != "FAILED", (missing, verdict, text[-600:])
    assert f"{missing} is not present" in text, text[-600:]
