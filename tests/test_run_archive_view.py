"""What the run archive page renders, run as the page's own code.

The page is a single self-contained HTML file, so until now the only
assertions about it in this suite were assertions about its text. The defect
this covers is a rendering outcome rather than a string: a document with no
result was put through a pass/fail pill, which styled the absence as a
failure, and a certificate of an ungated run was counted as a non-passing gate
run.

tests/run_archive_view_harness.mjs extracts the page's script, evaluates it
against element stubs and a stubbed fetch, and reports what the page wrote.
Node is present on the GitHub-hosted runners this project uses, and
test_the_view_is_exercised_in_ci fails rather than skips if it ever is not.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "run_archive_view_harness.mjs"
PAGE = ROOT / "proofs" / "runs" / "index.html"
PUBLISHED_INDEX = ROOT / "proofs" / "runs" / "benchmark_index.v3.json"

GATE_FIGURE_LABELS = (
    "expected-block prompts",
    "with a gate decision",
    "blocked by the gate",
    "passed by the gate",
    "reset before a decision",
)


def _node() -> str:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed; see test_the_view_is_exercised_in_ci")
    return node


def _render(index_payload, *, fetch_fails: bool = False, filters: dict | None = None, tmp_path=None):
    node = _node()
    if index_payload is None:
        index_arg = "-"
    elif isinstance(index_payload, Path):
        index_arg = str(index_payload)
    else:
        path = tmp_path / "benchmark_index.v3.json"
        path.write_text(json.dumps(index_payload), encoding="utf-8")
        index_arg = str(path)

    command = [node, str(HARNESS), str(PAGE), index_arg]
    if fetch_fails:
        command.append("--fetch-fails")
    for element_id, value in (filters or {}).items():
        command.append(f"--filter={element_id}={value}")

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    reported = json.loads(completed.stdout)
    assert reported["missing_element_ids"] == [], (
        "the page asked for an element the harness does not stub, so this "
        f"render is incomplete: {reported['missing_element_ids']}"
    )
    return reported["view"]


def _entry(run_id, **overrides):
    entry = {
        "entry_kind": "audit_certificate",
        "run_id": run_id,
        "run_timestamp_utc": "2026-10-01T00:00:00Z",
        "model": "test-model",
        "proof_class": "FIREWALL_ONLY_AUDIT",
        "result": "AUDIT PASSED",
        "row_identity": f"identity-{run_id}",
        "evaluation_target": {"target_kind": "domain_pack", "pack_id": "generic_safety"},
        "comparison": {"leaks": 0},
        "evidence": {"audit": f"runs/{run_id}/audit.json"},
    }
    entry.update(overrides)
    return entry


def _record_entry(run_id="run-record"):
    return {
        "entry_kind": "ungated_baseline_record",
        "run_id": run_id,
        "run_timestamp_utc": "2026-10-01T00:00:00Z",
        "model": "test-model",
        "row_identity": f"identity-{run_id}",
        "evaluation_target": {"target_kind": "domain_pack", "pack_id": "generic_safety"},
        "forwarding": {"prompts_forwarded": 100, "expected_block_prompts_forwarded": 40},
        "evidence": {"baseline": f"runs/{run_id}/baseline.json"},
    }


def _index():
    """One of each entry kind, and one pair of each form."""
    return {
        "version": "benchmark_index.v3",
        "entries": [
            _record_entry(),
            _entry("run-gated"),
            _entry("run-legacy-baseline", result="AUDIT FAILED"),
            _entry("run-legacy-gated"),
        ],
        "pairs": [
            {
                "pair_form": "record_and_certificate",
                "pair_id": "pair-new",
                "baseline_run_id": "run-record",
                "gated_run_id": "run-gated",
                "pair_status": "valid_complete",
                "required_dimensions": {"pack_id": "generic_safety", "model": "test-model"},
                "gate_figures": {
                    "expected_block_prompts": 40,
                    "expected_block_prompts_with_gate_decision": 38,
                    "expected_block_prompts_blocked_by_gate": 36,
                    "expected_block_prompts_passed_by_gate": 2,
                    "expected_block_prompts_reset": 2,
                },
                "deltas": {"provider_call_attempts_delta": -36},
            },
            {
                "pair_form": "certificate_pair_legacy",
                "pair_id": "pair-legacy",
                "baseline_run_id": "run-legacy-baseline",
                "gated_run_id": "run-legacy-gated",
                "pair_status": "valid_complete",
                "required_dimensions": {"pack_id": "generic_safety", "model": "test-model"},
                "deltas": {
                    "leaks_delta": -36,
                    "harmless_blocked_delta": 0,
                    "provider_call_attempts_delta": -36,
                },
            },
        ],
    }


def test_the_view_is_exercised_in_ci():
    """These are the project's only behavioural assertions about this page.

    They skip without node, which is right for a clone on a machine that has
    no node, and wrong for CI. GitHub-hosted ubuntu runners carry node, so if
    this ever fails the view has quietly stopped being tested where it counts.
    """
    if os.environ.get("CI") != "true":
        pytest.skip("not running in CI")
    assert shutil.which("node"), "node is required to exercise the archive view"


def test_a_baseline_record_is_not_rendered_as_a_non_passing_run(tmp_path):
    """A record has no result, and the absence is said rather than styled.

    Mutations applied to proofs/runs/index.html and its published copy, both
    detected: rendering a record through resultPill, 1 failure (this test);
    returning the pass pill from entryResultPill for a record, 1 failure
    (this test).
    """
    view = _render(_index(), tmp_path=tmp_path)
    recent = view["recent-rows"]["innerHTML"]

    assert "ungated baseline, no result" in recent
    assert "forwarded 100" in recent
    # The record's row carries no pass or fail pill at all.
    record_row = next(row for row in recent.split("<tr>") if "run-record" in row or "forwarded 100" in row)
    assert "pill pass" not in record_row
    assert "pill non-pass" not in record_row


def test_the_counters_separate_the_three_kinds_of_row(tmp_path):
    """Records, legacy baselines and gate runs are counted apart.

    The page used to report one non-pass figure over everything in view. On
    the published index that figure was 73, of which 54 were ungated baseline
    certificates: runs the gate was never in. It is now 19.

    Mutation applied to proofs/runs/index.html and its published copy:
    counting a legacy baseline certificate as a non-passing gate run, 2
    failures (this test and
    test_the_published_index_renders_with_every_entry_accounted_for).
    """
    view = _render(_index(), tmp_path=tmp_path)

    assert view["c-runs"]["textContent"] == "4"
    assert view["c-nonpass"]["textContent"] == "0"
    assert view["c-records"]["textContent"] == "1"
    assert view["c-legacy"]["textContent"] == "1"


def test_a_legacy_baseline_certificate_carries_its_qualification(tmp_path):
    """Section 11: the 54 stay published, and the qualification travels with them.

    Mutation applied to proofs/runs/index.html and its published copy:
    dropping the qualification pill from entryResultPill, 1 failure (this
    test).
    """
    view = _render(_index(), tmp_path=tmp_path)
    rendered = view["pair-rows"]["innerHTML"] + view["recent-rows"]["innerHTML"]

    assert "AUDIT FAILED" in rendered
    assert "legacy baseline, qualified" in rendered
    assert "It is not an audit of the gate." in rendered


def test_a_pair_from_this_release_shows_the_gate_figures_and_no_leak_delta(tmp_path):
    """D4: new pairs carry no leaks_delta, and the figures replace it.

    Mutations applied to proofs/runs/index.html and its published copy, both
    detected: rendering a record_and_certificate pair through the legacy delta
    branch, 2 failures (this test and
    test_a_pair_with_no_gate_figures_says_so); dropping the not-comparable
    notice when gate_figures is absent, 1 failure (that test).
    """
    view = _render(_index(), tmp_path=tmp_path)
    pairs = view["pair-rows"]["innerHTML"]

    for label in GATE_FIGURE_LABELS:
        assert f">{label} " in pairs, label
    assert ">blocked by the gate 36<" in pairs
    assert ">reset before a decision 2<" in pairs
    # The old label appears only on the legacy pair, and only as legacy.
    assert ">delta leaks " not in pairs
    assert ">legacy delta leaks -36<" in pairs


def test_a_pair_with_no_gate_figures_says_so(tmp_path):
    """Figures are present only on a comparable pair, so absence is reported."""
    index = _index()
    index["pairs"][0].pop("gate_figures")
    index["pairs"][0]["pair_status"] = "invalid_evidence_gap"

    view = _render(index, tmp_path=tmp_path)
    pairs = view["pair-rows"]["innerHTML"]

    assert "no gate figures: this pair is not comparable" in pairs
    for label in GATE_FIGURE_LABELS:
        assert f">{label} " not in pairs, label


def test_the_result_filter_does_not_describe_a_record(tmp_path):
    """Neither value of a result filter applies to a document with no result.

    Without this a record was excluded by AUDIT PASSED and included by
    Non-pass, which reported it as a non-passing run.

    Mutation applied to proofs/runs/index.html and its published copy:
    removing the record check from rowMatchesFilters, 1 failure (this test).
    """
    for value in ("AUDIT PASSED", "NON_PASS"):
        view = _render(_index(), filters={"f-status": value}, tmp_path=tmp_path)
        assert "ungated baseline, no result" not in view["recent-rows"]["innerHTML"], value
        assert view["c-records"]["textContent"] == "0", value


def test_the_page_reports_a_missing_index_rather_than_an_empty_archive(tmp_path):
    """A failed fetch is said, not rendered as a repository with no runs."""
    view = _render(None, fetch_fails=True, tmp_path=tmp_path)

    assert "Failed to load benchmark index" in view["recent-rows"]["innerHTML"]
    assert "Failed to load paired benchmark index" in view["pair-rows"]["innerHTML"]


def test_an_index_without_an_entries_array_is_a_failure_not_an_empty_view(tmp_path):
    """Pointing the page at the wrong file fails, and says what was wrong.

    The failure alone was already there: without the explicit check, reading
    entries off a payload that has none throws, and the page's own catch
    reports it. What the check adds is the reason. Asserting only the failure
    left the check uncovered, so the reason is asserted too.

    Mutation applied to proofs/runs/index.html and its published copy:
    removing the entries-array check, 1 failure (this test). Asserting the
    failure state alone, the same mutation was undetected: the page reported
    "Cannot read properties of undefined" in place of the reason, and both
    are a load failure.
    """
    view = _render({"version": "benchmark_index.v3", "pairs": []}, tmp_path=tmp_path)

    assert "Failed to load benchmark index" in view["recent-rows"]["innerHTML"]
    assert "v3 index has no entries array" in view["recent-rows"]["innerHTML"]


def test_the_published_index_renders_with_every_entry_accounted_for(tmp_path):
    """The real document, not a fixture: every row is counted as something.

    The three counts have to add up to the rows in view. A row counted in none
    of them is the hole this change removes, and the published index is the
    only place the mix of kinds is real.
    """
    view = _render(PUBLISHED_INDEX, tmp_path=tmp_path)

    rows = int(view["c-runs"]["textContent"])
    non_pass = int(view["c-nonpass"]["textContent"])
    records = int(view["c-records"]["textContent"])
    legacy = int(view["c-legacy"]["textContent"])
    passing = rows - non_pass - records - legacy

    assert rows > 0
    assert passing >= 0
    assert legacy == 54, "the 54 published ungated baseline certificates"
    assert records == 0, "no baseline record is published yet; step 7 opens that route"


def test_the_published_page_names_the_verifier_for_each_document(tmp_path):
    """The verify command the published page offers must match the document.

    tools/prepare_run_archive_page.py injects that command when docs/runs is
    published. It named tools/verify_certificate.py for every entry; on a
    baseline record that command exits non-zero by design, because the
    certificate verifier refuses a document that is not a certificate on every
    path including --no-ledger. The record's own verifier is named instead.

    Mutation applied to tools/prepare_run_archive_page.py: naming
    verify_certificate.py for both kinds, 1 failure (this test).
    """
    page = tmp_path / "index.html"
    page.write_text(PAGE.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(
        [sys.executable, str(ROOT / "tools" / "prepare_run_archive_page.py"), str(page)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )

    node = _node()
    index = tmp_path / "benchmark_index.v3.json"
    index.write_text(json.dumps(_index()), encoding="utf-8")
    completed = subprocess.run(
        [node, str(HARNESS), str(page), str(index)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    view = json.loads(completed.stdout)["view"]
    rendered = view["recent-rows"]["innerHTML"] + view["pair-rows"]["innerHTML"]

    assert "tools/verify_baseline_record.py docs/runs/run-record/baseline.json" in rendered
    assert "tools/verify_certificate.py docs/runs/run-gated/audit.json" in rendered
    assert "tools/verify_certificate.py docs/runs/run-record/" not in rendered


def test_the_published_page_is_the_prepared_source_page(tmp_path):
    """docs/runs/index.html is proofs/runs/index.html after preparation.

    The published page is a copy, so it can drift: a change to the source page
    that is not republished leaves the public surface rendering the old rules,
    and nothing else here would notice. tests/test_live_result_semantics.py
    holds the same property for the certificate pages.
    """
    prepared = tmp_path / "index.html"
    prepared.write_text(PAGE.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(
        [sys.executable, str(ROOT / "tools" / "prepare_run_archive_page.py"), str(prepared)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )

    published = ROOT / "docs" / "runs" / "index.html"
    assert published.read_text(encoding="utf-8") == prepared.read_text(encoding="utf-8"), (
        "docs/runs/index.html is not proofs/runs/index.html after preparation; "
        "republish it with tools/prepare_run_archive_page.py"
    )
