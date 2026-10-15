#!/usr/bin/env python3
"""Generate a narrow monitoring summary from proofs/runs/index.json.

What this summarises is gate runs. Every row in proofs/runs/index.json is drawn
from an audit certificate and carries a result and a proof class. Ungated
baseline records are published as their own documents and are deliberately
absent from that index, under D5 of
claude/2.5-spec-baseline-record-2026-10-14.md: a row with no result would put a
verdict-shaped hole where every other row has a verdict, which is the shape
that made 54 published baselines read as failed audits. So the counts here
cover audit certificates, and the output says so rather than leaving a reader to
assume the window is every published run.

Three refusals, added 15 October 2026. Until then this module:

- normalised the result with strip().upper() and counted only the three results
  it recognised, so a row whose result was unfamiliar occupied the window and
  was counted nowhere. The counts stopped adding up to the window size and
  nothing said so;
- returned an empty run list for any payload with no "runs" array, so pointing
  it at the wrong file published a summary of zero runs instead of failing;
- skipped rows that were not JSON objects, which is the same silent hole.

Now the recognised results come from tools/certificate_results.py and are
compared exactly, as every other reader of that field does; anything else stops
the run. A payload that is not the run index stops the run, as does a row
carrying record_kind, which is how a baseline record would reach a surface that
reads a verdict.

The count keys are derived from the declared result set rather than written out
here, so each row increments exactly one key and a fourth declared result would
be counted rather than dropped.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from certificate_results import KNOWN_RESULTS, UnrecognisedResult, status_for

# A baseline record declares its kind. No row in the run index may carry it.
RECORD_KIND_KEY = "record_kind"


class NotTheRunIndex(ValueError):
    """The payload is not proofs/runs/index.json, or a row in it is malformed."""


class NotAGateRun(ValueError):
    """A row in the run index declares itself something other than a gate run."""


def _count_key(result: str) -> str:
    return result.lower().replace(" ", "_")


def empty_counts() -> Dict[str, int]:
    return {_count_key(result): 0 for result in KNOWN_RESULTS}


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _runs(index_payload: Any) -> List[Dict[str, Any]]:
    """The index's rows, or a refusal. An index with no runs yet is not a refusal."""
    if not isinstance(index_payload, dict):
        raise NotTheRunIndex("the run index must be a JSON object")
    runs = index_payload.get("runs")
    if not isinstance(runs, list):
        raise NotTheRunIndex('the run index must carry a "runs" array')
    for position, row in enumerate(runs):
        if not isinstance(row, dict):
            raise NotTheRunIndex(f"run index row {position} is not a JSON object")
    return list(runs)


def _check_is_a_gate_run(row: Dict[str, Any]) -> None:
    if RECORD_KIND_KEY in row:
        raise NotAGateRun(
            f"run index row {row.get('run_id', '<no run_id>')!r} carries "
            f"{RECORD_KIND_KEY}={row[RECORD_KIND_KEY]!r}; baseline records are not gate runs"
        )


def _result_status(row: Dict[str, Any]):
    """The row's declared status, or a refusal. Exact comparison, no repair."""
    _check_is_a_gate_run(row)
    result = row.get("result")
    try:
        return status_for(result)
    except UnrecognisedResult as exc:
        raise UnrecognisedResult(
            f"run index row {row.get('run_id', '<no run_id>')!r}: {exc}"
        ) from exc


def _slice_runs(runs: List[Dict[str, Any]], window_size: int) -> List[Dict[str, Any]]:
    size = max(1, int(window_size))
    return runs[:size]


def _pick_latest_passing_run(runs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for row in runs:
        if _result_status(row).audit_pass:
            return row
    return None


def _row_view(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {
        "run_id": row.get("run_id"),
        "result": row.get("result"),
        "date": row.get("date"),
    }


def _count_results(runs: List[Dict[str, Any]]) -> Dict[str, int]:
    """One increment per row, so the counts always add up to the window size."""
    counts = empty_counts()
    for row in runs:
        _result_status(row)  # refuses a record, and any result not declared
        counts[_count_key(row["result"])] += 1
    return counts


def build_monitor_summary(index_payload: Dict[str, Any], window_size: int = 20) -> Dict[str, Any]:
    runs = _runs(index_payload)
    window_rows = _slice_runs(runs, window_size)
    latest_run = runs[0] if runs else None
    if latest_run is not None:
        _result_status(latest_run)
    latest_passing_run = _pick_latest_passing_run(runs)

    return {
        "updated_at_utc": index_payload.get("updated_at_utc"),
        "window_size": len(window_rows),
        "counts_cover": "audit_certificates",
        "latest_run": _row_view(latest_run),
        "latest_passing_run": _row_view(latest_passing_run),
        "counts": _count_results(window_rows),
        "latest_ci_run_url": (latest_run or {}).get("ci_run_url"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="proofs/runs/index.json", help="Path to proofs/runs/index.json")
    ap.add_argument("--out", default="docs/monitor-summary.json", help="Output monitor summary path")
    ap.add_argument("--window", type=int, default=20, help="Number of latest runs to count")
    args = ap.parse_args()

    index_path = Path(args.index)
    out_path = Path(args.out)

    if not index_path.exists():
        raise SystemExit(f"Missing index: {index_path}")

    payload = _read_json(index_path)
    try:
        summary = build_monitor_summary(payload, window_size=args.window)
    except (NotTheRunIndex, NotAGateRun, UnrecognisedResult) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    _write_json(out_path, summary)
    print(f"OK: wrote monitor summary -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
