"""A suite and a policy pack are different things with different names.

ISC policy packs configure the runtime gate. Benchmark suites supply the
prompts a run executes. docs/backlog.md has said they are distinct artefacts
for some time, and `hipaa_mental_health` and `pci_payments` are policy packs
with no suite at all, so the namespaces genuinely differ in size.

Every one of the nine registry entries nonetheless names both the same thing.
That is a convention, not a constraint, and until 7 October 2026 three things
leaned on it: run_summary.json reported the pack id in a field called
suite_name, the published audit pages looked up rule coverage by that field,
and the lookup table they indexed was keyed by pack id while being named
coverageBySuite.
"""

import argparse
import importlib.util
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_suite_name_is_the_suite_not_the_pack(tmp_path, monkeypatch):
    """The case the convention hides: a suite whose filename differs from the
    pack id of the policy that judged it."""
    runner = _load("rts_identity", "red_team_suite.py")
    suite = tmp_path / "prompts-v2.csv"
    suite.write_text(
        "id,prompt,expected,note,category\nallow-1,Hello,allow,,benign\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        runner, "_resolve_suite_and_pack",
        lambda **_k: (str(suite), "", "generic_safety", "1.0.0", "csv_single_turn_v1", "generic_safety"),
    )
    monkeypatch.setattr(
        argparse.ArgumentParser, "parse_args",
        lambda _s: argparse.Namespace(
            mode="audit", pack="generic_safety", suite=None, scenario=None,
            provider="xai", model="xai/grok-3-beta",
            template="EU-AI-Act-ISC-v1", no_model_calls=True,
            ungated_baseline=False,
        ),
    )
    monkeypatch.setattr(
        runner, "validate_sir",
        lambda *_a, **_k: {
            "status": "PASS", "domain_pack": "generic_safety",
            "itgl_log": [{"hash": "a" * 64}],
        },
    )
    try:
        runner.main()
    except SystemExit as exc:
        assert int(exc.code or 0) == 0, "a clean run should not exit non-zero"

    summary = json.loads(
        (tmp_path / "proofs/run_summary.json").read_text(encoding="utf-8")
    )
    assert summary["suite_name"] == "prompts-v2"
    assert summary["selected_pack_id"] == "generic_safety"
    assert summary["suite_name"] != summary["selected_pack_id"]
    # The suite is still identified by content, not only by name.
    assert summary["suite_hash"].startswith("sha256:")


def test_every_registry_pack_still_names_its_suite_the_same_thing():
    """Not a requirement, a recorded fact. If this ever fails it means the two
    namespaces have diverged in practice, which is allowed, and the published
    pages must be checked rather than assumed."""
    registry = json.loads(
        (ROOT / "spec/packs/pack_registry.v1.json").read_text(encoding="utf-8")
    )
    packs = registry.get("packs", registry)
    entries = packs.values() if isinstance(packs, dict) else packs
    mismatched = {
        e["pack_id"]: e.get("suite_path", "")
        for e in entries
        if isinstance(e, dict)
        and e.get("pack_id")
        != os.path.splitext(os.path.basename(e.get("suite_path", "")))[0]
    }
    assert not mismatched, (
        "pack id and suite filename now differ for: "
        f"{mismatched}. That is permitted. Check that the published audit "
        "pages still resolve rule coverage correctly, because they key it by "
        "pack id and the two used to coincide."
    )


def test_every_published_page_looks_up_coverage_by_the_name_it_declares():
    """The drift this file exists for. The generator writes a lookup table into
    each page under a configured variable name; the page's own code indexes it.
    Nothing connected the two, and three pages ended up declaring
    coverageBySuite while a fourth declared coverageByPack."""
    report = _load("rule_coverage_identity", "tools/rule_coverage_report.py")

    for path, (variable, _indent) in report.PUBLISHED_LOOKUP_SURFACES.items():
        document = Path(path).read_text(encoding="utf-8")
        assert f"const {variable} = {{" in document, (
            f"{Path(path).name} does not declare {variable}; the generator "
            "would write a table the page never reads"
        )
        used = set(re.findall(r"\bconst (coverage\w+) = \{", document)) | set(
            re.findall(r"\b(coverage\w+)\[", document)
        )
        assert used == {variable}, (
            f"{Path(path).name} mixes coverage lookup names {sorted(used)}; "
            f"the generator writes {variable}"
        )


def test_coverage_is_looked_up_by_a_pack_field_not_a_suite_field():
    """The table is keyed by pack_id in rule_coverage_report.render_javascript_lookup.
    Indexing it with suite_name worked only while the namespaces coincided."""
    report = _load("rule_coverage_keying", "tools/rule_coverage_report.py")
    for path, _ in report.PUBLISHED_LOOKUP_SURFACES.items():
        document = Path(path).read_text(encoding="utf-8")
        for match in re.findall(r"coverage\w+\[([^\]]+)\]", document):
            assert "suite_name" not in match, (
                f"{Path(path).name} indexes the coverage table with {match!r}. "
                "That table is keyed by pack id."
            )
