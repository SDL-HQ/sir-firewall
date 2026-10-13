import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    module_path = ROOT / "tools" / "rule_coverage_report.py"
    spec = importlib.util.spec_from_file_location("rule_coverage_report", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _by_id(report):
    return {pack["pack_id"]: pack for pack in report["packs"]}


def _coverage_lookup(path, variable_name):
    page = path.read_text(encoding="utf-8")
    match = re.search(
        rf"const\s+{re.escape(variable_name)}\s*=\s*\{{(?P<body>.*?)\}};",
        page,
        flags=re.DOTALL,
    )
    assert match, f"coverage lookup {variable_name} not found in {path}"

    entries = re.findall(
        r'^\s*"?([a-z0-9_]+)"?:\s*"([^"]+)"\s*,?\s*$',
        match.group("body"),
        re.MULTILINE,
    )
    assert entries, f"coverage lookup {variable_name} is empty in {path}"
    assert len(entries) == len(dict(entries)), f"duplicate pack in {path}"
    return dict(entries)


def test_published_coverage_regions_match_generator():
    module = _load_module()
    report = module.build_report()
    expected = module.render_html_table_body(report)
    document = (ROOT / "docs/domain-packs.html").read_text(encoding="utf-8")
    assert expected in document
    assert document.count(module.BEGIN) == document.count(module.END) == 1

    # docs/rule-coverage.md carried this table by hand until 13 October 2026,
    # which is why its runner-evaluability column stayed wrong for the four
    # suites that enforce under a pack of another name. It is owned now.
    coverage_doc = (ROOT / "docs/rule-coverage.md").read_text(encoding="utf-8")
    assert module.render_markdown_region(report) in coverage_doc, (
        "docs/rule-coverage.md differs from fresh generator output. Run\n"
        "  python3 tools/rule_coverage_report.py --update-published-surfaces\n"
        "rather than editing the table, which the next publication would overwrite."
    )
    assert coverage_doc.count(module.BEGIN) == coverage_doc.count(module.END) == 1

    for path, (variable_name, indent) in module.PUBLISHED_LOOKUP_SURFACES.items():
        document = path.read_text(encoding="utf-8")
        expected = module.render_javascript_lookup(report, variable_name, indent)
        assert expected in document
        assert document.count(module.BEGIN) == document.count(module.END) == 1


def test_published_coverage_json_matches_generator_and_public_policy():
    module = _load_module()
    actual = json.loads(module.PUBLISHED_JSON.read_text(encoding="utf-8"))
    # Generation time is intentionally refreshed on publication; every derived
    # field must remain byte-for-byte equivalent to a fresh report.
    expected = module.build_published_json(
        module.build_report(), generated_at=actual["generated_at"]
    )

    assert actual == expected
    assert actual["sir_firewall_version"] == module.__version__
    assert len(actual["packs"]) == 8
    assert all(pack["is_public"] is True for pack in actual["packs"])
    assert all(pack["pack_version"] for pack in actual["packs"])
    assert "canary_fail" not in {pack["pack_id"] for pack in actual["packs"]}


def test_published_coverage_json_has_joinable_unique_pack_identity():
    payload = json.loads((ROOT / "docs/coverage.json").read_text(encoding="utf-8"))
    identities = [
        (pack["pack_id"], pack["pack_version"]) for pack in payload["packs"]
    ]
    assert len(identities) == len(set(identities))


def test_run_archive_publication_prepares_generated_coverage_region(tmp_path):
    module = _load_module()
    published_runs = tmp_path / "docs" / "runs"
    shutil.copytree(ROOT / "proofs" / "runs", published_runs)

    command = [
        sys.executable,
        str(ROOT / "tools" / "prepare_run_archive_page.py"),
        str(published_runs / "index.html"),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    subprocess.run(command, cwd=ROOT, check=True)

    document = (published_runs / "index.html").read_text(encoding="utf-8")
    expected = module.render_javascript_lookup(
        module.build_report(), "FULL_GATE_COVERAGE", 4
    )
    assert document.count(module.BEGIN) == document.count(module.END) == 1
    assert expected in document


def test_run_archive_preparation_fails_closed_when_coverage_build_fails(
    tmp_path, monkeypatch
):
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    module_path = ROOT / "tools" / "prepare_run_archive_page.py"
    spec = importlib.util.spec_from_file_location("prepare_run_archive_page", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    page = tmp_path / "index.html"
    shutil.copyfile(ROOT / "proofs" / "runs" / "index.html", page)
    original = page.read_bytes()

    def fail_build():
        raise RuntimeError("coverage unavailable")

    monkeypatch.setattr(module, "build_report", fail_build)
    monkeypatch.setattr(sys, "argv", ["prepare_run_archive_page.py", str(page)])
    with pytest.raises(RuntimeError, match="coverage unavailable"):
        module.main()

    assert page.read_bytes() == original


def test_archived_proof_coverage_matches_generated_report_without_rewriting_evidence():
    report = _load_module().build_report()
    expected = {
        pack["pack_id"]: f'{pack["full_gate_matched"]}/{pack["block_rows"]}'
        for pack in report["packs"]
        if pack["status"] == "active" and pack["visibility"] in {"public", "encoded"}
    }

    assert _coverage_lookup(ROOT / "proofs/runs/index.html", "FULL_GATE_COVERAGE") == expected


def test_public_surface_inclusion_rule_excludes_draft_and_internal_packs():
    module = _load_module()
    report = {"packs": [
        {"pack_id": "active_public", "status": "active", "visibility": "public"},
        {"pack_id": "active_encoded", "status": "active", "visibility": "encoded"},
        {"pack_id": "draft_public", "status": "draft", "visibility": "public"},
        {"pack_id": "active_internal", "status": "active", "visibility": "internal"},
    ]}

    assert [pack["pack_id"] for pack in module.public_packs(report)] == [
        "active_public",
        "active_encoded",
    ]


def test_current_public_surface_inclusion_adds_every_eligible_pack_automatically():
    module = _load_module()
    report = module.build_report()

    assert {pack["pack_id"] for pack in module.public_packs(report)} == {
        "generic_safety",
        "mental_health_clinical",
        "account_recovery_fraud",
        "support_operator_override",
        "data_exfiltration_pressure",
        "eu_ai_act_compliance_pressure",
        "scenario_injection_chain",
        "scenario_tool_injection",
    }


def test_report_covers_fully_matched_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    full = packs["support_operator_override"]
    assert full["deterministic_rule_matched"] == full["block_rows"] == 26
    assert full["full_gate_matched"] == 26


def test_report_covers_partially_matched_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    partial = packs["eu_ai_act_compliance_pressure"]
    assert partial["deterministic_rule_matched"] == 74
    assert partial["full_gate_matched"] == 74
    assert partial["block_rows"] == 100
    assert partial["deterministic_rule_unmatched_ids"] == ["eua-116"] + [f"eua-{i}" for i in range(126, 151)]


def test_report_decodes_encoded_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    encoded = packs["mental_health_clinical"]
    assert encoded["block_rows"] == 15
    assert encoded["deterministic_rule_matched"] == 2
    assert encoded["full_gate_matched"] == 5


def test_report_retains_canary_infrastructure_suite():
    module = _load_module()
    packs = _by_id(module.build_report())

    canary = packs["canary_fail"]
    assert canary["block_rows"] == 1
    assert canary["deterministic_rule_matched"] == 0
    assert canary["full_gate_matched"] == 0


def test_report_marks_pack_with_enforcement_policy_as_runner_evaluable():
    module = _load_module()
    pack = _by_id(module.build_report())["generic_safety"]

    assert pack["runner_evaluable"] is True
    assert pack["enforcement_policy_pack_path"] == str(
        (module.ROOT / "src/sir_firewall/policy/isc_packs/generic_safety.json").resolve()
    )


def test_report_marks_pack_without_enforcement_policy_as_not_runner_evaluable():
    """Keyed to canary_fail, the one entry that genuinely has no policy pack.

    This asserted mental_health_clinical until 13 October 2026, which encoded
    the pre-resolver behaviour: that suite declares enforcement_pack
    generic_safety and the runner has run it since the resolver landed. The
    test did not miss the divergence, it pinned it, and the published
    evaluability column was wrong for as long as it stood.
    """
    module = _load_module()
    pack = _by_id(module.build_report())["canary_fail"]

    assert pack["runner_evaluable"] is False
    assert pack["enforcement_policy_pack_path"] is None

    enforced = _by_id(module.build_report())["mental_health_clinical"]
    assert enforced["enforcement_pack"] == "generic_safety"
    assert enforced["runner_evaluable"] is True


def test_report_explains_missing_enforcement_policy_pack():
    module = _load_module()
    packs = _by_id(module.build_report())

    assert (
        packs["canary_fail"]["runner_evaluability_reason"]
        == "missing_enforcement_policy_pack"
    )
    assert packs["generic_safety"]["runner_evaluability_reason"] is None


def test_cli_writes_machine_readable_json_and_markdown(tmp_path, monkeypatch):
    module = _load_module()
    json_out = tmp_path / "coverage.json"
    markdown_out = tmp_path / "coverage.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "rule_coverage_report.py",
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
    )

    assert module.main() == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert len(payload["packs"]) == 9
    table = markdown_out.read_text(encoding="utf-8")
    assert "| Pack | Status | Visibility |" in table
    assert "`generic_safety`" in table
    assert "| Runner evaluability |" in table


def test_reversed_region_markers_are_refused_rather_than_silently_corrupting(tmp_path):
    """A region that closes before it opens has no extent.

    replace_generated checked that exactly one of each marker was present and
    then did slice arithmetic that is silent when the order is wrong. With the
    end marker first the prefix and suffix overlap, so the output keeps the text
    before the end marker, inserts the generated block, and then repeats
    everything between the two markers along with both markers. The corruption
    is a duplication, not a deletion: the first description of this said the
    intervening text was deleted, and running the old code showed it appearing
    twice instead.
    """
    module = _load_module()

    document = (
        "intro that must survive\n"
        f"<!-- {module.END} -->\n"
        "body between the markers\n"
        f"<!-- {module.BEGIN} -->\n"
        "tail\n"
    )

    with pytest.raises(ValueError, match="reverse order"):
        module.replace_generated(document, "GENERATED")


def test_a_correctly_ordered_region_is_still_rewritten():
    """The order check must not refuse the ordinary case."""
    module = _load_module()

    document = (
        "intro\n"
        f"<!-- {module.BEGIN} -->\n"
        "stale\n"
        f"<!-- {module.END} -->\n"
        "tail\n"
    )

    updated = module.replace_generated(document, "GENERATED")

    assert "intro\n" in updated
    assert "tail\n" in updated
    assert "GENERATED" in updated
    assert "stale" not in updated


def _recorded_writes(monkeypatch):
    """Intercept every write so this file can assert about writes, not content.

    The first version of the test below compared file contents before and after,
    on the live repository paths, while taking an unused tmp_path that advertised
    isolation it did not have. Two consequences, both found by an independent
    review on 13 October 2026: a regression that wrote a surface whose content
    was already current passed the comparison, and running the test under such a
    regression wrote into the repository it was testing.

    Nothing reaches the filesystem here. A recorded write is the assertion.
    """
    writes = []

    def recording_write_text(self, data, *args, **kwargs):
        writes.append((Path(self), data))
        return len(data)

    monkeypatch.setattr(Path, "write_text", recording_write_text)
    return writes


def test_every_surface_is_written_when_all_of_them_render(monkeypatch):
    """The companion to the test below, which would otherwise pass on a no-op.

    With writes intercepted, an updater that writes nothing at all satisfies
    "nothing was written when a surface failed". This fixes the expected set so
    that only the partial case is a failure.
    """
    module = _load_module()
    report = module.build_report()
    expected = set(module.render_published_surfaces(report))

    writes = _recorded_writes(monkeypatch)
    module.update_published_surfaces(report)

    assert {path for path, _ in writes} == expected, (
        "the updater did not write exactly the surfaces it renders"
    )
    assert len(writes) == len(expected), (
        f"a surface was written more than once: {[str(p) for p, _ in writes]}"
    )


def test_no_surface_is_written_when_another_surface_cannot_be_rendered(monkeypatch):
    """Rendering every surface before writing any is the point of the split.

    The previous implementation wrote coverage.json first and then each surface
    in turn, so a marker error in a later surface left the earlier ones updated
    and the rest stale. That is a publication set that disagrees with itself and
    gives no sign of it, which is the same failure shape as a figure nobody
    regenerated.
    """
    module = _load_module()
    report = module.build_report()
    surface_count = len(module.render_published_surfaces(report))
    assert surface_count >= 3, "too few surfaces for a partial update to mean anything"

    # Fail the last surface the updater reaches, leaving the earlier ones
    # renderable, so a write-as-you-go implementation would have written them.
    calls = {"n": 0}
    real_replace = module.replace_generated

    def replace_generated(document, generated):
        calls["n"] += 1
        if calls["n"] >= surface_count - 1:
            raise ValueError("deliberately unrenderable surface")
        return real_replace(document, generated)

    monkeypatch.setattr(module, "replace_generated", replace_generated)
    writes = _recorded_writes(monkeypatch)

    with pytest.raises(ValueError, match="deliberately unrenderable"):
        module.update_published_surfaces(report)

    assert writes == [], (
        "a surface was written even though the run could not render every "
        "surface, which leaves the published set disagreeing with itself: "
        f"{[str(path) for path, _ in writes]}"
    )


@pytest.mark.parametrize("flag", ["--json-out", "--markdown-out"])
def test_the_cli_refuses_to_write_a_whole_report_over_a_published_surface(tmp_path, flag):
    """The invocation that destroyed docs/rule-coverage.md on 12 October 2026.

    --json-out and --markdown-out write whole files. Each published surface is a
    generated region inside hand-written text. Pointing an out flag at one
    replaced the document with the bare report and destroyed the markers, after
    which publication rendering raised on a region that no longer existed, so
    the error arrived after the damage. Adding the generated region closed the
    drift that made someone reach for --markdown-out; it did not close this.

    Asserted per owned surface, so a new published surface is covered by being
    published rather than by being added here.
    """
    module = _load_module()

    for surface in sorted(module.owned_surfaces()):
        before = surface.read_text(encoding="utf-8")
        args = {
            "--json-out": str(tmp_path / "report.json"),
            "--markdown-out": str(tmp_path / "report.md"),
        }
        args[flag] = str(surface)

        completed = subprocess.run(
            [
                sys.executable,
                str(module.ROOT / "tools" / "rule_coverage_report.py"),
                "--json-out", args["--json-out"],
                "--markdown-out", args["--markdown-out"],
                "--update-published-surfaces",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=module.ROOT,
        )

        assert completed.returncode != 0, (
            f"{flag} {surface} was accepted, so a published surface can be "
            "overwritten with a bare report"
        )
        assert "publishes as a generated region" in completed.stderr, completed.stderr
        assert surface.read_text(encoding="utf-8") == before, (
            f"{surface} was modified by an invocation that was supposed to be "
            "refused, which means the refusal happens after the write"
        )


def test_the_ordinary_cli_invocation_still_works(tmp_path):
    """The refusal must not refuse the case it exists to protect."""
    module = _load_module()

    completed = subprocess.run(
        [
            sys.executable,
            str(module.ROOT / "tools" / "rule_coverage_report.py"),
            "--json-out", str(tmp_path / "report.json"),
            "--markdown-out", str(tmp_path / "report.md"),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=module.ROOT,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["packs"]
    assert (tmp_path / "report.md").read_text(encoding="utf-8").strip()


def test_every_published_surface_is_covered_by_the_refusal():
    """owned_surfaces must name the surfaces update_published_surfaces writes.

    The refusal is only as complete as this set. Derived from the updater's own
    rendering rather than from a list typed beside it.
    """
    module = _load_module()
    report = module.build_report()

    written = {path.resolve() for path in module.render_published_surfaces(report)}

    assert written == module.owned_surfaces(), (
        "owned_surfaces disagrees with what the updater writes, so a surface is "
        "either unprotected or wrongly refused.\n"
        f"  written but not owned: {sorted(written - module.owned_surfaces())}\n"
        f"  owned but not written: {sorted(module.owned_surfaces() - written)}"
    )
