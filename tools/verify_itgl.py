#!/usr/bin/env python3
"""
Verify the ITGL hash-chained ledger emitted by red_team_suite.py.

- Reads proofs/itgl_ledger.jsonl
- Checks that each entry has the expected fields
- Verifies that:
    - ledger[i]["prev_hash"] == ledger[i-1]["ledger_hash"] (chain continuity)
    - ledger_hash == sha256(prev_hash + final_hash)
- Exits 0 if the full chain is valid, non-zero otherwise.

SIR+ P1 additions:
- Writes proofs/itgl_final_hash.txt with the run-level ITGL final hash
  formatted as "sha256:<ledger_hash>"
- Prints "ITGL_FINAL_HASH=sha256:<ledger_hash>" for CI to capture into env
"""

import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, Any, List

LEDGER_PATH = Path("proofs") / "itgl_ledger.jsonl"


class LedgerVerificationError(RuntimeError):
    """Raised when the ITGL ledger fails structural or hash checks."""


def _load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise LedgerVerificationError(f"ITGL ledger not found at {path}")

    entries: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LedgerVerificationError(
                    f"Invalid JSON on line {line_no}: {exc}"
                ) from exc
            if not isinstance(entry, dict):
                raise LedgerVerificationError(
                    f"Ledger entry on line {line_no} is not a JSON object"
                )
            entries.append(entry)

    if not entries:
        raise LedgerVerificationError("ITGL ledger is empty")

    return entries


def _verify_entry_fields(entry: Dict[str, Any], index: int) -> None:
    required_fields = [
        "ts",
        "prompt_index",
        "isc_template",
        "status",
        "expected",
        "final_hash",
        "prev_hash",
        "ledger_hash",
    ]
    missing = [f for f in required_fields if f not in entry]
    if missing:
        raise LedgerVerificationError(
            f"Entry #{index} missing required fields: {', '.join(missing)}"
        )


def _compute_ledger_hash(prev_hash: str, final_hash: str) -> str:
    payload = (prev_hash or "") + final_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_ledger(entries: List[Dict[str, Any]]) -> str:
    """
    Verify the full ledger chain.

    Returns the final ledger hash if all checks pass.
    Raises LedgerVerificationError on any failure.
    """
    previous_ledger_hash = None
    final_ledger_hash = ""

    for idx, entry in enumerate(entries):
        human_index = idx + 1
        _verify_entry_fields(entry, human_index)

        prev_hash = str(entry["prev_hash"])
        final_hash = str(entry["final_hash"])
        stored_ledger_hash = str(entry["ledger_hash"])

        if idx == 0:
            # First entry should be anchored from GENESIS (set in red_team_suite.py)
            if prev_hash != "GENESIS":
                raise LedgerVerificationError(
                    f"Entry #1 has unexpected prev_hash={prev_hash!r}, "
                    "expected 'GENESIS'"
                )
        else:
            # For subsequent entries, prev_hash must equal previous ledger_hash
            if prev_hash != previous_ledger_hash:
                raise LedgerVerificationError(
                    f"Entry #{human_index} prev_hash={prev_hash!r} does not match "
                    f"previous ledger_hash={previous_ledger_hash!r}"
                )

        computed_ledger_hash = _compute_ledger_hash(prev_hash, final_hash)
        if stored_ledger_hash != computed_ledger_hash:
            raise LedgerVerificationError(
                f"Entry #{human_index} has invalid ledger_hash: "
                f"stored={stored_ledger_hash!r}, computed={computed_ledger_hash!r}"
            )

        previous_ledger_hash = stored_ledger_hash
        final_ledger_hash = stored_ledger_hash

    if not final_ledger_hash:
        raise LedgerVerificationError("No final ledger hash computed")

    return final_ledger_hash


def main() -> None:
    try:
        entries = _load_ledger(LEDGER_PATH)
        final_hash = verify_ledger(entries)
    except LedgerVerificationError as exc:
        print(f"ITGL ledger verification FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:  # defensive catch-all
        print(f"ITGL ledger verification ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    # Run-level ITGL final hash — canonical form for certs/HTML
    itgl_final_hash = f"sha256:{final_hash}"

    os.makedirs("proofs", exist_ok=True)
    with open("proofs/itgl_final_hash.txt", "w", encoding="utf-8") as out:
        out.write(itgl_final_hash + "\n")

    # CI-friendly env line; workflow can append this to $GITHUB_ENV
    print(f"ITGL_FINAL_HASH={itgl_final_hash}")

    print(
        f"ITGL ledger verification OK: {len(entries)} entries, "
        f"final_ledger_hash={final_hash}"
    )
    raise SystemExit(0)


if __name__ == "__main__":
    main()
