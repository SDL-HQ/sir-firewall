#!/usr/bin/env python3
"""Generate a narrow monitoring summary from proofs/runs/index.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _coerce_runs(index_payload: Any) -> List[Dict[str, Any]]:
    if isinstance(index_payload, dict):
        runs = index_payload.get("runs")
        if isinstance(runs, list):
            return [row for row in runs if isinstance(row, dict)]
    return []


def _normalized_result(value: Any) -> str:
    return str(value or "").strip().upper()


def _is_passing_result(value: Any) -> bool:
    return _normalized_result(value) == "AUDIT PASSED"


def _slice_runs(runs: List[Dict[str, Any]], window_size: int) -> List[Dict[str, Any]]:
    size = max(1, int(window_size))
    return runs[:size]


def _pick_latest_passing_run(runs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for row in runs:
        if _is_passing_result(row.get("result")):
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
    counts = {
        "audit_passed": 0,
        "audit_failed": 0,
        "inconclusive": 0,
    }
    for row in runs:
        result = _normalized_result(row.get("result"))
        if result == "AUDIT PASSED":
            counts["audit_passed"] += 1
        elif result == "AUDIT FAILED":
            counts["audit_failed"] += 1
        elif result == "INCONCLUSIVE":
            counts["inconclusive"] += 1
    return counts


def build_monitor_summary(index_payload: Dict[str, Any], window_size: int = 20) -> Dict[str, Any]:
    runs = _coerce_runs(index_payload)
    window_rows = _slice_runs(runs, window_size)
    latest_run = runs[0] if runs else None
    latest_passing_run = _pick_latest_passing_run(runs)

    return {
        "updated_at_utc": index_payload.get("updated_at_utc"),
        "window_size": len(window_rows),
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
    summary = build_monitor_summary(payload, window_size=args.window)
    _write_json(out_path, summary)
    print(f"OK: wrote monitor summary -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
