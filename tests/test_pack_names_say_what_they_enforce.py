"""The two renamed packs are gone from code and configuration, and mapped.

An ISC policy pack configures admissible templates, per-template token
ceilings, enforcement flags and whether a structured request schema is
declared. It does not change which phrases the gate blocks: the deterministic
rules are one global set. ``pci_payments`` and ``hipaa_mental_health``
therefore named properties they had no mechanism to deliver, and a reader meets
an identifier long before any perimeter document. Decided 13 October 2026 in
``docs/backlog.md``, done in 2.5.0.

The rename was safe for a measured reason rather than an assumed one: neither
identifier appears in any published archive, and ``policy_hash`` is computed
over the baseline policy document rather than over the pack directory. The four
pack names that do appear in published certificates are not renamed, and that
asymmetry is held here so a later tidy-up does not quietly extend the rename
into the archive.

This holds four things rather than grepping for a string:

- the retired identifiers resolve to no pack, and the new ones resolve;
- every installed pack's ``pack_id`` equals its filename stem, so a rename
  cannot land half done;
- ``docs/terminology.md`` carries both directions of the mapping;
- ``docs/release-notes-2.4.0.md`` still names the retired identifiers, because
  it describes what 2.4.0 shipped and rewriting it would falsify history.

Mutations measured on 16 October 2026, each run against the full file:

- restore ``pack_id`` to the retired value inside the renamed file: the stem
  check, both ceiling checks and the source scan fail (4 failed).
- re-add the retired pack file beside the renamed one: the resolution check,
  the source scan and the guard-the-guard count fail (3 failed).
- drop the mapping table from ``docs/terminology.md``:
  ``test_the_mapping_is_recorded_in_both_directions`` fails (1 failed).
- rewrite the retired names out of the last release's notes:
  ``test_the_2_4_0_release_notes_keep_the_names_2_4_0_shipped`` fails
  (1 failed).
- name a retired identifier in a comment in ``tools/latency_report.py``:
  ``test_no_code_or_configuration_names_a_retired_pack`` fails (1 failed).
"""

import json
from pathlib import Path

import pytest

from sir_firewall.core import load_domain_pack

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "src/sir_firewall/policy/isc_packs"

RETIRED = {
    "pci_payments": "pci_template_reduced_limits",
    "hipaa_mental_health": "hipaa_template_reduced_limits",
}

# Signed into published certificates as pack_id, selected_pack_id and
# effective_pack_id, so renaming these is permanent dual naming rather than a
# migration. Counts measured at 86b1a6c on 16 October 2026.
SIGNED_INTO_THE_ARCHIVE = {
    "generic_safety",
    "data_exfiltration_pressure",
    "eu_ai_act_compliance_pressure",
    "support_operator_override",
}


def _installed() -> dict:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(PACKS.glob("*.json"))
    }


def test_the_retired_identifiers_resolve_to_no_pack():
    for retired in RETIRED:
        assert not (PACKS / f"{retired}.json").exists()
        with pytest.raises(FileNotFoundError):
            load_domain_pack(retired)


def test_the_new_identifiers_resolve_and_reduce_the_baseline_ceilings():
    baseline = load_domain_pack("generic_safety")["templates"]

    for new in RETIRED.values():
        pack = load_domain_pack(new)
        assert pack["pack_id"] == new
        assert set(pack["templates"]) == set(baseline)
        assert all(
            pack["templates"][name]["max_tokens"] < baseline[name]["max_tokens"]
            for name in baseline
        ), f"{new} is named for reduced limits and must declare them"


def test_each_name_clamps_the_template_it_is_named_for_hardest():
    """The name points at a template, so the name has to be earned."""
    baseline = load_domain_pack("generic_safety")["templates"]
    named = {
        "pci_template_reduced_limits": "PCI-DSS-ISC-v1",
        "hipaa_template_reduced_limits": "HIPAA-ISC-v1",
    }

    for pack_id, template in named.items():
        templates = load_domain_pack(pack_id)["templates"]
        reductions = {
            name: 1 - templates[name]["max_tokens"] / baseline[name]["max_tokens"]
            for name in baseline
        }
        assert max(reductions, key=reductions.get) == template, reductions


def test_every_pack_id_equals_its_filename_stem():
    mismatched = {
        stem: pack.get("pack_id")
        for stem, pack in _installed().items()
        if pack.get("pack_id") != stem
    }

    assert not mismatched, (
        "load_domain_pack resolves a pack by filename, so a pack_id that "
        f"disagrees with its stem is a half-finished rename: {mismatched}"
    )


def test_the_mapping_is_recorded_in_both_directions():
    terminology = (ROOT / "docs/terminology.md").read_text(encoding="utf-8")

    for retired, new in RETIRED.items():
        assert retired in terminology, retired
        assert new in terminology, new


def test_the_2_4_0_release_notes_keep_the_names_2_4_0_shipped():
    """History is not tidied. 2.4.0 shipped these names and says so."""
    notes = (ROOT / "docs/release-notes-2.4.0.md").read_text(encoding="utf-8")

    for retired in RETIRED:
        assert retired in notes, retired


def test_the_four_archived_pack_names_are_installed_and_unrenamed():
    installed = set(_installed())

    assert SIGNED_INTO_THE_ARCHIVE <= installed, sorted(
        SIGNED_INTO_THE_ARCHIVE - installed
    )


def test_no_code_or_configuration_names_a_retired_pack():
    """Prose may record the rename. Code and configuration may not carry it."""
    searched = sorted(
        {
            *(ROOT / "src").rglob("*.py"),
            *(ROOT / "src").rglob("*.json"),
            *(ROOT / "tools").glob("*.py"),
            *(ROOT / "tests").glob("*.py"),
            *PACKS.glob("*.json"),
            ROOT / "red_team_suite.py",
        }
    )
    offenders = {}
    for path in searched:
        if path == Path(__file__):
            continue
        text = path.read_text(encoding="utf-8")
        named = [retired for retired in RETIRED if retired in text]
        if named:
            offenders[str(path.relative_to(ROOT))] = named

    assert not offenders, offenders


def test_the_scan_looks_at_something():
    """Guard the guard: the file set must not silently become empty."""
    assert len(_installed()) == 6, sorted(_installed())
    assert len(list((ROOT / "tools").glob("*.py"))) > 20
    assert len(list((ROOT / "tests").glob("*.py"))) > 80
    assert (ROOT / "src/sir_firewall/core.py").is_file()
