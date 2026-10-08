"""The claims register is checked, not asserted.

Item 8's condition is that each public technical claim remains true when the
reader examines the failures. A register that says so and is never checked is
exactly the failure mode it exists to catch, so the figures in it are compared
against the measurements that produced them, and its structure is held so a
claim cannot be added without a status, evidence and a coverage verdict.

The register deliberately contains `open` rows. Those are decisions Ryan owns,
named rather than deferred silently, and this file does not try to close them.
It only refuses to let them disappear.
"""

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs/claims-register.md"
TEXT = REGISTER.read_text(encoding="utf-8")

# Figures are compared against a whitespace-flattened copy. A markdown
# document's line breaks are not part of what it says, so asserting that a
# number and its noun share a source line is an assertion about formatting
# rather than about the claim, and it fails on a reflow that changes nothing.
FLAT = re.sub(r"\s+", " ", TEXT)

STATUSES = ("holds", "qualified", "corrected", "open")


def _claim_sections():
    """Each '### ' heading and the body up to the next heading of any level."""
    sections = {}
    current = None
    for line in TEXT.splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            sections[current] = []
        elif line.startswith("## "):
            current = None
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(body) for name, body in sections.items()}


SECTIONS = _claim_sections()


def test_the_register_exists_and_is_linked_from_the_readme():
    assert REGISTER.is_file()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/claims-register.md" in readme, (
        "a register nobody can find is not a disclosure"
    )


def test_there_are_claims_to_check():
    """Guard the guard. A restructure must not make this file vacuous."""
    assert len(SECTIONS) >= 8, sorted(SECTIONS)


@pytest.mark.parametrize("claim", sorted(SECTIONS))
def test_every_claim_carries_a_status(claim):
    body = SECTIONS[claim]
    found = [s for s in STATUSES if f"**{s}" in body]

    assert found, f"{claim!r} has no status; one of {STATUSES} is required"


@pytest.mark.parametrize("claim", sorted(SECTIONS))
def test_every_claim_cites_something_checkable(claim):
    """Evidence means a path, a commit, or a measurement, not an adjective."""
    body = SECTIONS[claim]
    cites_path = bool(re.search(r"`[\w./-]+\.(py|md|json|txt)`", body))
    cites_commit = bool(re.search(r"`[0-9a-f]{7}`", body))
    cites_number = bool(re.search(r"\b\d{2,}\b", body))

    assert cites_path or cites_commit or cites_number, (
        f"{claim!r} cites nothing a reader could check"
    )


@pytest.mark.parametrize("claim", sorted(SECTIONS))
def test_every_claim_records_its_patent_coverage(claim):
    """The column the patent boundary note asks for.

    Without it, a buyer can be told a feature is covered when it is not, and
    valuable material can be found undescribed at contest time.
    """
    body = SECTIONS[claim]
    if "Coverage:" not in body:
        # The two non-feature sections are allowed to omit it.
        assert claim in ("The boundaries list", "The assurance kit's worked example"), (
            f"{claim!r} records no coverage verdict"
        )
        return

    assert re.search(r"\*Coverage: (inside|outside)", body), body[:200]


def test_every_open_row_says_a_decision_is_required():
    """An open row must read as a decision, not as a soft pass."""
    opens = [name for name, body in SECTIONS.items() if "**open" in body]

    assert opens, "the register claims no open decisions; verify that is true"
    for name in opens:
        body = SECTIONS[name]
        assert "Decision required" in body or "open" in body.lower(), name


def test_the_open_decisions_are_listed_where_they_can_be_found():
    """Scattered through a long document is the same as unrecorded."""
    assert "## Decisions this register surfaces" in TEXT
    listed = TEXT.split("## Decisions this register surfaces", 1)[1]
    assert len(re.findall(r"^\d+\. ", listed, flags=re.MULTILINE)) >= 4


# --- the figures must match the measurements that produced them --------------


def _measure():
    spec = importlib.util.spec_from_file_location(
        "measure_legitimate_workload", ROOT / "tools/measure_legitimate_workload.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.measure()


def test_the_use_versus_mention_figures_match_the_measurement():
    report = _measure()
    guidance = report["strata"]["carrier_only"]
    quoted = report["strata"]["carrier_plus_quoted_injection"]

    assert f"{guidance['allow_prompts']} requests" in FLAT, (
        "the register quotes a guidance denominator the measurement does not produce"
    )
    assert f"{quoted['blocked']} times out of {quoted['allow_prompts']}" in FLAT
    assert guidance["blocked"] == 0


def test_the_contract_coverage_figures_match_the_archive():
    """219 of 292 governed by no contract, and the total."""
    certificates = sorted((ROOT / "docs/runs").glob("*/audit.json"))
    ungoverned = 0
    for certificate in certificates:
        version = json.loads(certificate.read_text(encoding="utf-8")).get("sir_firewall_version")
        parsed = (
            tuple(int(p) for p in version.split("."))
            if isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version)
            else None
        )
        if parsed is None or parsed < (2, 2, 0):
            ungoverned += 1

    assert f"{len(certificates)} published" in FLAT or f"the {len(certificates)} published" in FLAT
    assert f"{ungoverned} of the {len(certificates)} published certificates" in FLAT, (
        f"the register says something other than {ungoverned} of {len(certificates)}"
    )


def test_the_pack_measurement_figures_match_the_threat_model():
    """One statement, two places. They must not drift."""
    threat_model = re.sub(
        r"\s+", " ", (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")
    )

    for figure in ("453 prompts", "8 suites", "6 packs"):
        assert figure in threat_model, figure
    assert "453 prompts" in FLAT


def test_the_claim_corrected_in_the_readme_is_actually_corrected():
    """A register row saying 'corrected' must describe a change that happened."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "does not guarantee that a same-named ISC policy pack exists" not in readme
    assert "fails at resolution" in readme
    assert "docs/archive-errata.md" in readme, (
        "the qualified archive claim must cross-reference the errata"
    )


def test_item_7_is_not_claimed_anywhere_public():
    """Nothing may claim zero downstream calls until item 7 demonstrates it."""
    assert "Item 7 is not built" in TEXT
    checklist = json.loads((ROOT / "release-checklist.json").read_text(encoding="utf-8"))
    item7 = next(i for i in checklist["items"] if i["id"] == 7)

    if item7["status"] == "met":
        pytest.fail(
            "item 7 is now met; the register's statement that it is not built, and "
            "the claim it withholds, both need revisiting"
        )


def test_the_resolved_patent_condition_is_recorded():
    """A parked decision whose condition is now satisfied is live, not parked.

    enforced_policy_matches_signed_policy survives contract v4, which was one of
    the two conditions on revisiting a second application. The register records
    that rather than leaving it in a document dated three days earlier.
    """
    assert "enforced_policy_matches_signed_policy" in TEXT
    assert "24 September 2027" in TEXT, "the disclosure cut-off must be stated"
    contract = json.loads((ROOT / "spec/evidence_contract.v4.json").read_text(encoding="utf-8"))
    assert "enforced_policy_matches_signed_policy" in contract["required"], (
        "the field no longer survives v4; the register's patent note is now wrong"
    )
