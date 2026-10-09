"""The published errata figures are the figures the report actually produces.

docs/archive-errata.md exists because the archive is offered for independent
verification and a reviewer who runs the verifiers will find records that do not
verify. It is therefore read as a statement about the archive, and a figure in it
that has drifted is worse than no figure, because a reviewer compares their own
output against it.

Two ways it had drifted by 8 October 2026. It said 290 archives where there were
292, because two had been published since. And the script that produces the
numbers, tools/archive_verification_report.py, invoked the verifier with the
certificate alone: no ledger, so it relied on discovery, which resolves against
the working directory and returned nothing for most archives; and no
--require-registry, so signing trust was never established. Checks that were not
performed were being counted as checks that found nothing wrong.

This runs the report and compares. It is slow, a minute or so, because it
executes two verifier subprocesses per archive, which is the point: the figures
come from the real tools over the real archive, not from a fixture.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ERRATA = ROOT / "docs/archive-errata.md"


@pytest.fixture(scope="module")
def report() -> str:
    result = subprocess.run(
        [sys.executable, "tools/archive_verification_report.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _reported_counts(report: str, section: str) -> dict:
    """{label: count} for one section of the report."""
    body = report.split(section, 1)[1].split("\n\n", 1)[0]
    counts = {}
    for line in body.splitlines():
        match = re.match(r"\s*exit\s+(\S+)\s+(\d+)\s+(.*)", line)
        if match:
            counts[match.group(3).strip()] = int(match.group(2))
    return counts


def _errata_counts() -> dict:
    """{result text: count} from the Current figures table."""
    table = ERRATA.read_text(encoding="utf-8").split("## Current figures", 1)[1]
    table = table.split("\n\n##", 1)[0]
    counts = {}
    for line in table.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[2].isdigit():
            counts[f"{cells[0]} {cells[1]}"] = int(cells[2])
    return counts


def test_the_errata_states_the_number_of_archives_the_report_examined(report):
    examined = int(re.search(r"Published run archives examined: (\d+)", report).group(1))
    text = ERRATA.read_text(encoding="utf-8")

    assert f"all {examined} published run archives" in text, (
        f"the report examined {examined} archives and the errata does not say so"
    )


def test_every_errata_count_matches_the_report(report):
    """Each number in the published table against the run that produced it.

    Compared per tool as a multiset of counts rather than by label, because the
    table's wording is for a human reader and need not match the report's
    strings. Every count must appear, and the totals must agree, so a stale or
    missing row fails.
    """
    errata = _errata_counts()
    assert errata, "the Current figures table could not be parsed"

    for tool, section in (
        ("verify_certificate.py", "Certificate verification"),
        ("verify_archive_receipt.py", "Archive receipt verification"),
    ):
        reported = sorted(_reported_counts(report, section).values())
        published = sorted(
            count for label, count in errata.items() if tool in label
        )
        assert published == reported, (
            f"the errata and the report disagree for {tool}\n"
            f"  errata: {published}\n  report: {reported}"
        )

    examined = int(re.search(r"Published run archives examined: (\d+)", report).group(1))
    for tool in ("verify_certificate.py", "verify_archive_receipt.py"):
        total = sum(count for label, count in errata.items() if tool in label)
        assert total == examined, (
            f"the errata's {tool} rows total {total} across {examined} archives; "
            "every archive takes exactly one outcome"
        )


def test_the_report_passes_a_ledger_and_requires_the_registry():
    """The correction that moved the numbers, pinned so it cannot be undone.

    Without these the report measures less than it claims. Passing the ledger
    explicitly moved 41 archives from exit 9 to exit 0: bindings that were always
    sound and had never been checked.
    """
    source = (ROOT / "tools/archive_verification_report.py").read_text(encoding="utf-8")

    assert "--require-registry" in source
    assert '"--ledger"' in source
    assert '"--no-ledger"' in source, (
        "an archive with no ledger must be invoked explicitly rather than left "
        "to discovery, which can resolve to a copy elsewhere on disk"
    )


def test_a_skipped_binding_is_not_counted_as_a_checked_one(report):
    """--no-ledger exits 0. Counting that beside a checked binding reports a
    skipped check as a passed one, which is the defect this whole release is
    about."""
    certificate = _reported_counts(report, "Certificate verification")
    skipped = [label for label in certificate if "no binding was checked" in label]

    assert len(skipped) == 1, certificate
    assert certificate[skipped[0]] > 0
    assert "verified" in certificate, (
        "the row for a binding that was checked and holds is gone"
    )
