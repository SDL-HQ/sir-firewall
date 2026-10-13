"""spec/packs/PACKS.md's two suite tables, one generated and one editorial.

That file carried a single six-column table until 13 October 2026. Its preamble
said the values were "sourced from the generated report"; all six were typed.
Five days after tools/rule_coverage_report.py was corrected to derive runner
evaluability through each registry entry's enforcement_pack, and after
docs/rule-coverage.md and docs/domain-packs.html were regenerated, this table
still marked account_recovery_fraud, mental_health_clinical,
scenario_injection_chain and scenario_tool_injection as not runner-evaluable.
An independent review found it; nothing in the suite could have.

The derivable columns are a generated region now. The taxonomy column is not:
PACKS.md defines taxonomy as an editorial readability label, explicitly not a
score or ranking, and declares no mapping from the suites' own category values
to those labels. Generating it would publish an invented judgement as derived.
What is held here instead is its membership, so a suite cannot be added to or
removed from the registry and leave the list quietly wrong.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS_SPEC = ROOT / "spec" / "packs" / "PACKS.md"
REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"


def _module():
    spec = importlib.util.spec_from_file_location(
        "rule_coverage_report", ROOT / "tools" / "rule_coverage_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _taxonomy_rows() -> dict[str, str]:
    text = PACKS_SPEC.read_text(encoding="utf-8")
    section = text[text.index("### Taxonomy labels (editorial)") :]
    section = section[: section.index("## Rule-to-suite explainability mapping")]
    rows = {}
    for line in section.splitlines():
        if line.startswith("| `"):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            rows[cells[0].strip("`")] = cells[1]
    return rows


def test_the_generated_posture_region_matches_the_generator():
    """The whole point: this table cannot be retyped into disagreement."""
    module = _module()
    expected = module.render_spec_posture_region(module.build_report())

    document = PACKS_SPEC.read_text(encoding="utf-8")
    begin = f"<!-- {module.BEGIN} -->"
    end = f"<!-- {module.END} -->"
    assert document.count(begin) == 1 and document.count(end) == 1, (
        "spec/packs/PACKS.md does not carry exactly one generated region, so "
        "the generator cannot own its table"
    )
    present = document[document.index(begin) : document.index(end) + len(end)]

    assert present == expected, (
        "the posture table in spec/packs/PACKS.md disagrees with the generator. "
        "Regenerate it rather than editing it:\n"
        "  python3 tools/rule_coverage_report.py --json-out <path> "
        "--markdown-out <path> --update-published-surfaces"
    )


def test_the_generated_region_reports_the_runner_evaluability_the_runner_has():
    """The specific claim that was wrong, asserted against the resolver.

    Four suites enforce under a pack of another name. A table that marks them
    not runner-evaluable is the defect this file exists for, so it is checked
    directly and not only through region equality.
    """
    module = _module()
    document = PACKS_SPEC.read_text(encoding="utf-8")

    for pack in module.build_report()["packs"]:
        row = next(
            (line for line in document.splitlines()
             if line.startswith(f"| `{pack['pack_id']}` |") and "Runner-evaluable" in line
             or line.startswith(f"| `{pack['pack_id']}` |") and "Not runner-evaluable" in line),
            None,
        )
        assert row is not None, f"{pack['pack_id']} has no posture row"
        claims_evaluable = "Not runner-evaluable" not in row
        assert claims_evaluable == pack["runner_evaluable"], (
            f"{pack['pack_id']} is published as "
            f"{'runner-evaluable' if claims_evaluable else 'not runner-evaluable'} "
            f"and the resolver says {pack['runner_evaluable']}"
        )


def test_the_editorial_taxonomy_list_covers_every_registry_suite():
    """Membership, not labels. The labels are a person's call; the set is not."""
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    declared = {str(entry["pack_id"]) for entry in registry["packs"]}
    listed = set(_taxonomy_rows())

    assert listed == declared, (
        "the editorial taxonomy list in spec/packs/PACKS.md does not cover the "
        "registry.\n"
        f"  in the registry, unlabelled: {sorted(declared - listed)}\n"
        f"  labelled, not in the registry: {sorted(listed - declared)}"
    )


def test_every_editorial_label_is_a_category_the_spec_declares():
    """A label outside the declared set is a typo or an undeclared category."""
    text = PACKS_SPEC.read_text(encoding="utf-8")
    section = text[text.index("Current categories in active use:") :]
    section = section[: section.index("Two tables.")]
    declared = set(re.findall(r"^- `([a-z_]+)`$", section, re.MULTILINE))
    assert declared, "the spec no longer declares its categories in a readable list"

    used = set()
    for labels in _taxonomy_rows().values():
        used.update(re.findall(r"`([a-z_]+)`", labels))

    assert used <= declared, (
        f"labels used but not declared as categories: {sorted(used - declared)}"
    )


def test_the_spec_does_not_claim_the_editorial_table_is_generated():
    """The preamble that made the old table look derived.

    "sourced from the generated report" was the sentence that let a typed table
    be read as a measurement. Nothing in the editorial section may say that
    again.
    """
    text = PACKS_SPEC.read_text(encoding="utf-8")
    section = text[text.index("### Taxonomy labels (editorial)") :]
    section = section[: section.index("## Rule-to-suite explainability mapping")]

    # The exact affirmative claim, not any sentence containing its words. A
    # first version banned the substring "derived from", which this section's
    # own "not derived from the suites' own category values" contains, so the
    # test failed on correct prose. Banning a word is not the same as banning a
    # claim, and the broader assertion was wrong about the text it guards.
    assert "sourced from the generated report" not in section, (
        "the editorial taxonomy section says it is sourced from the generated "
        "report, which is the sentence that let the previous typed table be "
        "read as a measurement"
    )
    assert re.search(r"\beditorial\b", section), (
        "the taxonomy section no longer says it is editorial, so a reader has "
        "nothing distinguishing it from the generated table above it"
    )
    assert "(editorial)" in section.splitlines()[0], (
        "the taxonomy heading no longer marks the table editorial"
    )
