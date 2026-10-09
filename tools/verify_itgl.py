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

from itgl import (
    CHAIN_VERSION_V1,
    LedgerVerificationError,
    ledger_chain_version,
    load_and_verify_ledger,
    load_ledger,
)


def main(ledger_path: Path = LEDGER_PATH, minimum_chain_version: int = CHAIN_VERSION_V1) -> None:
    try:
        chain_version = ledger_chain_version(load_ledger(ledger_path))
        itgl_final_hash, row_count = load_and_verify_ledger(ledger_path, minimum_chain_version)
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
    # Say which rule this was checked under, because "verified" means
    # different things under each. Under chain_version 1 the row hash covers
    # only an opaque per-prompt digest, so the row's own decision, prompt
    # identifier and flags are not bound by it. Under 2 they are.
    print(f"chain_version={chain_version} (minimum required: {minimum_chain_version})")
    if chain_version == CHAIN_VERSION_V1:
        print(
            "NOTE: chain_version 1 binds row order, not row contents. Pair this "
            "with the archive receipt to detect an altered row.",
            file=sys.stderr,
        )
    raise SystemExit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify an ITGL hash-chained ledger.")
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    parser.add_argument(
        "--min-chain-version",
        type=int,
        default=CHAIN_VERSION_V1,
        help=(
            "Refuse any row declaring a chain version below this. Defaults to 1 "
            "so that archives published before 7 October 2026 verify under the "
            "rule they were written with. A certificate-driven check derives "
            "this from the signed sir_firewall_version instead of taking it "
            "from the ledger, because a row that set its own bar could be "
            "downgraded to the weaker rule by whoever holds the archive."
        ),
    )
    args = parser.parse_args()
    main(args.ledger, args.min_chain_version)
