"""The commands the reviewer documents print are commands that exist.

These documents are instructions, not snapshots: a reviewer copies a line out
of them and runs it. A line naming a tool that was renamed, a flag that was
removed, or the wrong verifier for a document kind fails in the reviewer's
terminal, which is the worst place to find out.

So every `python3 tools/...` line in them is checked against the tool itself:
the file exists, and every long flag it passes is a flag that tool accepts,
read from the tool's own --help. The pairing of verifier to document kind is
checked too, because from SIR 2.5 pointing one verifier at the other kind's
document exits non-zero by design.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REVIEWER_DOCUMENTS = (
    "docs/assurance-kit.md",
    "docs/evaluator-technical-explainer.md",
    "docs/minimal-pilot-runbook.md",
    "RETENTION.md",
    "docs/evidence-perimeter.v6.md",
    "docs/benchmark-cycle.v1.md",
)

COMMAND = re.compile(r"python3? (tools/[a-z_]+\.py)((?:[^\n`]|\\\n)*)")

# Flags a reviewer is shown that belong to the shell line rather than the tool.
NOT_A_TOOL_FLAG = {"--"}


def _commands():
    found = []
    for relative in REVIEWER_DOCUMENTS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for match in COMMAND.finditer(text):
            found.append((relative, match.group(1), match.group(2)))
    return found


def _help_text(tool: str) -> str:
    completed = subprocess.run(
        [sys.executable, str(ROOT / tool), "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert completed.returncode == 0, f"{tool} --help failed: {completed.stderr}"
    return completed.stdout


def test_there_are_commands_to_check():
    """Guard the guard. A rename of these documents must not make this vacuous."""
    commands = _commands()
    assert len(commands) >= 8, [(doc, tool) for doc, tool, _ in commands]
    assert {tool for _, tool, _ in commands} >= {
        "tools/verify_certificate.py",
        "tools/verify_baseline_record.py",
        "tools/verify_archive_receipt.py",
        "tools/verify_evidence.py",
    }


@pytest.mark.parametrize(
    "document,tool,arguments",
    _commands(),
    ids=[f"{doc}:{tool}" for doc, tool, _ in _commands()],
)
def test_every_documented_command_names_a_real_tool_and_real_flags(document, tool, arguments):
    """A reviewer's copied line must not fail on a flag the tool never had.

    Mutations applied to docs/assurance-kit.md, both detected: naming
    tools/verify_baseline.py, a tool that does not exist, 2 failures (the case
    for that line and test_there_are_commands_to_check, which no longer finds
    the record's verifier among the documented commands); passing
    --require-registy to the record verifier, 1 failure (the case for that
    line).
    """
    assert (ROOT / tool).is_file(), f"{document} names a tool that does not exist: {tool}"

    flags = {flag for flag in re.findall(r"(--[a-z][a-z-]*)", arguments)} - NOT_A_TOOL_FLAG
    if not flags:
        return

    help_text = _help_text(tool)
    for flag in sorted(flags):
        assert flag in help_text, f"{document} passes {flag} to {tool}, which does not accept it"


@pytest.mark.parametrize("document,tool,arguments", _commands(), ids=[f"{doc}:{tool}" for doc, tool, _ in _commands()])
def test_no_document_points_a_verifier_at_the_other_kind(document, tool, arguments):
    """Each verifier establishes the document's type first, so this would fail.

    Mutation applied to docs/assurance-kit.md: showing
    verify_certificate.py on baseline.json, 1 failure (the case for that line).
    """
    if tool == "tools/verify_certificate.py":
        assert "baseline.json" not in arguments, (
            f"{document} runs the certificate verifier over a baseline record"
        )
    if tool == "tools/verify_baseline_record.py":
        assert "audit.json" not in arguments, (
            f"{document} runs the record verifier over a certificate"
        )


def test_the_reviewer_documents_name_the_record_s_verifier():
    """A reviewer handed a baseline archive has to be told what verifies it."""
    for relative in ("docs/assurance-kit.md", "docs/evidence-perimeter.v6.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "verify_baseline_record.py" in text, relative
        assert "baseline.json" in text, relative


def test_the_compact_reference_table_covers_both_document_kinds():
    """The table is the one-glance summary, so a kind missing from it is missing.

    Asserting the verifier appears somewhere in the document was not enough:
    removing the table's baseline row left the name in the worked example
    above it and the test passed. A reviewer scanning the table would have
    seen certificates only.

    Mutation applied to docs/assurance-kit.md: removing the baseline row from
    the table, 1 failure (this test).
    """
    kit = (ROOT / "docs/assurance-kit.md").read_text(encoding="utf-8")
    start = kit.index("## Compact reference table")
    table = kit[start : kit.index("\n## ", start)]

    rows = [line for line in table.splitlines() if line.startswith("| `docs/runs/")]
    assert any("audit.json" in row and "verify_certificate.py" in row for row in rows), rows
    assert any(
        "baseline.json" in row and "verify_baseline_record.py" in row for row in rows
    ), rows


def test_the_archive_file_lists_do_not_require_a_certificate_of_every_run():
    """Retention and the kit describe an archive, and not every archive has one.

    Mutation applied to RETENTION.md: restoring the bare per-run audit.json
    line, 1 failure (this test).
    """
    for relative in ("RETENTION.md", "docs/assurance-kit.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "baseline.json" in text, relative
        assert not re.search(
            r"^  - `proofs/runs/<run_id>/audit\.json`$", text, flags=re.MULTILINE
        ), f"{relative} lists audit.json as a file every archive holds"
