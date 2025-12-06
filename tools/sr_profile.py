#!/usr/bin/env python
"""
SR profiler for SIR ITGL ledger.

Usage:

    python tools/sr_profile.py                # uses default proofs/itgl_ledger.jsonl
    python tools/sr_profile.py path/to/ledger.jsonl

This is a diagnostic tool for ops / governance to see how often
Systemic Reset (SR) has been triggered and why.
"""

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_LEDGER_PATH = Path("proofs/itgl_ledger.jsonl")


def load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"ITGL ledger not found at {path}")
    entries: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip bad lines; ledger integrity should be checked separately
                continue
    return entries


def summarise_sr(entries: List[Dict[str, Any]]) -> None:
    total = len(entries)
    sr_entries = [e for e in entries if e.get("component") == "sr"]

    print(f"Total ITGL entries: {total}")
    print(f"SR entries:         {len(sr_entries)}")
    print()

    if not sr_entries:
        print("No SR events recorded.")
        return

    by_reason = Counter(e.get("input", {}).get("reason", "unknown") for e in sr_entries)
    by_scope = Counter(e.get("input", {}).get("scope", "unknown") for e in sr_entries)

    print("SR by reason:")
    for reason, count in by_reason.most_common():
        print(f"  - {reason}: {count}")

    print("\nSR by scope:")
    for scope, count in by_scope.most_common():
        print(f"  - {scope}: {count}")


def main() -> None:
    if len(sys.argv) > 1:
        ledger_path = Path(sys.argv[1])
    else:
        ledger_path = DEFAULT_LEDGER_PATH

    try:
        entries = load_ledger(ledger_path)
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)

    summarise_sr(entries)


if __name__ == "__main__":
    main()
