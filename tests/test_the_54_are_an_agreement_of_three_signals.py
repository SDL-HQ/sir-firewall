"""The published set of 54 ungated baselines is an agreement, not one field's word.

`tools/archive_verification_report.py` derived `legacy_ungated_certificates`
from `benchmark_execution.gate_mode == "ungated"` alone until 15 October 2026,
so a published figure moved with the issuer's own metadata. A parallel review
pointed out that this was the weakest of three signals already available.

All three are computed now and must agree:

    marker  the issuer's benchmark_execution.gate_mode
    pair    a published pair artefact naming the run as its baseline half
    rows    the ungated-baseline per-prompt digest on every row of its ledger

On the real archive all three select the same 54, which is why none of this is
testable against it: a fallback to the marker alone produces the same answer.
Measured on 15 October 2026, reverting the set to the marker, removing the
`FigureError`, and removing the restriction to certificate archives were all
undetected by the suite as it then stood. These cases are the disagreement the
real archive does not contain.

Five mutations measured with these cases in place, each applied in place and
reverted in a `finally` whose revert was confirmed by hashing the file before
and after. Counts are what pytest reported across this file,
tests/test_typed_evidence_readers.py and
tests/test_the_suite_does_not_stage_into_the_archive.py:

    1. the set falls back to the marker alone          undetected
    2. the disagreement no longer blocks publication   5 failed
    3. the row signal stops excluding record archives  3 failed
    4. the pair signal stops excluding record archives 1 failed
    5. the staging guard stops resolving assignments   1 failed

Mutation 1 is undetected and left so. Replacing the intersection with
`sorted(by_marker)` cannot change the answer, because the refusal above it has
already returned on any input where the three sets differ: by the time that
line runs the three are equal. It is written as the intersection because that
is what the figure is, so the set stays correct if the refusal is ever
weakened. A test for it would only be a test of the test.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import itgl  # noqa: E402


def _module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REPORT = _module("archive_report_for_signal_tests", "tools/archive_verification_report.py")


def _row(index: int, *, ungated_digest: bool) -> dict:
    row = {
        "chain_version": 2,
        "prompt_index": index,
        "prompt_id": f"r{index}",
        "prompt_hash": "sha256:" + f"{index}" * 64,
        "isc_template": "EU-AI-Act-ISC-v1",
        "domain_pack": "generic_safety",
        "scenario_id": "",
        "status": "FORWARDED",
    }
    row["final_hash"] = (
        itgl.ungated_row_final_hash(row) if ungated_digest else "0" * 64
    )
    return row


def _archive(
    runs_dir: Path,
    run_id: str,
    *,
    document: str = "audit.json",
    marker: bool,
    rows_ungated: bool,
    paired: bool,
) -> None:
    run_dir = runs_dir / run_id
    (run_dir / "proofs").mkdir(parents=True, exist_ok=True)

    payload = {"audit": "SIR Pre-Inference Governance Audit", "result": "AUDIT FAILED"}
    if document == "baseline.json":
        payload = {"record_kind": "sir_ungated_baseline"}
    if marker:
        payload["benchmark_execution"] = {"gate_mode": "ungated", "benchmark_role": "baseline"}
    (run_dir / document).write_text(json.dumps(payload), encoding="utf-8")

    rows = [_row(1, ungated_digest=rows_ungated), _row(2, ungated_digest=rows_ungated)]
    (run_dir / "proofs" / "itgl_ledger.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )

    if paired:
        pairs = runs_dir / "pairs"
        pairs.mkdir(parents=True, exist_ok=True)
        (pairs / f"{run_id}.json").write_text(
            json.dumps({"baseline_run_id": run_id, "gated_run_id": "other"}),
            encoding="utf-8",
        )


def _measured(runs_dir: Path) -> list[dict]:
    return [
        {
            "run_id": path.name,
            "certificate_exit": 0,
            "certificate_meaning": "verified",
            "receipt_exit": 0,
            "receipt_meaning": "verified",
            "record_exit": None,
            "record_meaning": "no baseline record in archive",
        }
        for path in sorted(p for p in runs_dir.iterdir() if p.is_dir() and p.name != "pairs")
    ]


def test_all_three_signals_agreeing_puts_the_archive_in_the_set(tmp_path):
    """Guard the guard: if this did not hold, every case below would pass
    because nothing reached the set at all."""
    runs = tmp_path / "runs"
    _archive(runs, "agreed", marker=True, rows_ungated=True, paired=True)

    figures = REPORT.build_figures(_measured(runs), runs)

    assert figures["legacy_ungated_certificates"] == ["agreed"]
    assert figures["legacy_ungated_signal_counts"] == {
        "marker": 1, "pair_artefact": 1, "ungated_rows": 1
    }


@pytest.mark.parametrize(
    ("case", "marker", "rows_ungated", "paired", "expected_signals"),
    [
        ("marker_and_pair_without_the_rows", True, False, True, "marker+pair"),
        ("rows_and_pair_without_the_marker", False, True, True, "pair+rows"),
        ("marker_and_rows_without_a_pair", True, True, False, "marker+rows"),
        ("the_marker_alone", True, False, False, "marker"),
        ("the_rows_alone", False, True, False, "rows"),
    ],
)
def test_any_disagreement_stops_the_figure(
    tmp_path, case, marker, rows_ungated, paired, expected_signals
):
    """A figure the three signals disagree about is not published at all.

    Not resolved in the marker's favour, which is what deriving the set from
    the marker alone amounted to. The generator raises and the workflow's
    publication step fails, so the archive and the documents that describe it
    stay consistent.
    """
    runs = tmp_path / "runs"
    _archive(runs, case, marker=marker, rows_ungated=rows_ungated, paired=paired)

    with pytest.raises(REPORT.FigureError) as excinfo:
        REPORT.build_figures(_measured(runs), runs)

    message = str(excinfo.value)
    assert "three signals" in message
    assert f"{case}: {expected_signals}" in message, message


def test_a_published_baseline_record_is_not_one_of_the_legacy_certificates(tmp_path):
    """The restriction that the first paired publication depends on.

    A correctly typed 2.5 baseline record has the ungated digest on every row
    because that is what it is for, and from 2.5 a pair artefact names its
    archive as the baseline half. Two of the three signals therefore hold for
    it, and the marker does not, so without restricting every signal to
    archives holding a certificate the first published pair would make the
    three disagree about its own baseline and block its own figures.
    """
    runs = tmp_path / "runs"
    _archive(
        runs, "a-real-record", document="baseline.json",
        marker=False, rows_ungated=True, paired=True,
    )

    figures = REPORT.build_figures(_measured(runs), runs)

    assert figures["legacy_ungated_certificates"] == []
    assert figures["legacy_ungated_signal_counts"] == {
        "marker": 0, "pair_artefact": 0, "ungated_rows": 0
    }
