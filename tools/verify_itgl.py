#!/usr/bin/env python3
"""
Verify the ITGL hash-chained run ledger emitted by red_team_suite.py.

- Reads proofs/itgl_ledger.jsonl
- Checks structure + chain continuity
- Verifies ledger_hash integrity per-entry

Ledger rules (current):
- Entry 1 must have prev_hash == "GENESIS"
- For i>1: entry[i]["prev_hash"] must equal entry[i-1]["ledger_hash"]
- ledger_hash == sha256( (prev_hash or "") + final_hash_raw )

Where final_hash_raw is:
- entry["final_hash"] if present (preferred)
- else entry["itgl_prompt_final_hash"] with optional "sha256:" prefix stripped

Outputs:
- proofs/itgl_final_hash.txt   (sha256:<final_ledger_hash>)
- Prints: ITGL_FINAL_HASH=sha256:<final_ledger_hash> (CI-friendly)
"""

import argparse
import os
import sys
from pathlib import Path

LEDGER_PATH = Path("proofs") / "itgl_ledger.jsonl"


sys.path.insert(0, str(Path(__file__).resolve().parent))

from itgl import LedgerVerificationError, load_and_verify_ledger


def main(ledger_path: Path = LEDGER_PATH) -> None:
    try:
        itgl_final_hash, row_count = load_and_verify_ledger(ledger_path)
    except LedgerVerificationError as exc:
        print(f"ITGL ledger verification FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"ITGL ledger verification ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    os.makedirs("proofs", exist_ok=True)
    with open("proofs/itgl_final_hash.txt", "w", encoding="utf-8") as out:
        out.write(itgl_final_hash + "\n")

    print(f"ITGL_FINAL_HASH={itgl_final_hash}")
    print(
        f"ITGL ledger verification OK: {row_count} entries, "
        f"final_ledger_hash={itgl_final_hash.removeprefix('sha256:')}"
    )
    raise SystemExit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify an ITGL hash-chained ledger.")
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    args = parser.parse_args()
    main(args.ledger)
