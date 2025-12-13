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

import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional

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
                raise LedgerVerificationError(f"Invalid JSON on line {line_no}: {exc}") from exc
            if not isinstance(entry, dict):
                raise LedgerVerificationError(f"Ledger entry on line {line_no} is not a JSON object")
            entries.append(entry)

    if not entries:
        raise LedgerVerificationError("ITGL ledger is empty")

    return entries


def _final_hash_raw(entry: Dict[str, Any]) -> Optional[str]:
    if "final_hash" in entry:
        v = str(entry.get("final_hash") or "").strip()
        return v or None

    v = str(entry.get("itgl_prompt_final_hash") or "").strip()
    if not v:
        return None
    return v.split("sha256:", 1)[-1] if v.startswith("sha256:") else v


def _verify_entry_fields(entry: Dict[str, Any], index: int) -> None:
    required = ["ts", "prompt_index", "prev_hash", "ledger_hash"]
    missing = [k for k in required if k not in entry]
    if missing:
        raise LedgerVerificationError(f"Entry #{index} missing required fields: {', '.join(missing)}")

    if "final_hash" not in entry and "itgl_prompt_final_hash" not in entry:
        raise LedgerVerificationError(
            f"Entry #{index} missing per-prompt final hash field "
            "(expected 'final_hash' or 'itgl_prompt_final_hash')"
        )


def _compute_ledger_hash(prev_hash: str, final_hash_raw: str) -> str:
    payload = (prev_hash or "") + final_hash_raw
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_ledger(entries: List[Dict[str, Any]]) -> str:
    previous_ledger_hash = None
    final_ledger_hash = ""

    for idx, entry in enumerate(entries):
        human_index = idx + 1
        _verify_entry_fields(entry, human_index)

        prev_hash = str(entry.get("prev_hash") or "")
        stored_ledger_hash = str(entry.get("ledger_hash") or "")

        fh_raw = _final_hash_raw(entry)
        if not fh_raw:
            raise LedgerVerificationError(f"Entry #{human_index} has empty final hash")

        if idx == 0:
            if prev_hash != "GENESIS":
                raise LedgerVerificationError(
                    f"Entry #1 has unexpected prev_hash={prev_hash!r}, expected 'GENESIS'"
                )
        else:
            if prev_hash != previous_ledger_hash:
                raise LedgerVerificationError(
                    f"Entry #{human_index} prev_hash={prev_hash!r} does not match "
                    f"previous ledger_hash={previous_ledger_hash!r}"
                )

        computed = _compute_ledger_hash(prev_hash, fh_raw)
        if stored_ledger_hash != computed:
            raise LedgerVerificationError(
                f"Entry #{human_index} has invalid ledger_hash: "
                f"stored={stored_ledger_hash!r}, computed={computed!r}"
            )

        previous_ledger_hash = stored_ledger_hash
        final_ledger_hash = stored_ledger_hash

    if not final_ledger_hash:
        raise LedgerVerificationError("No final ledger hash computed")

    return final_ledger_hash


def main() -> None:
    try:
        entries = _load_ledger(LEDGER_PATH)
        final_hash_hex = verify_ledger(entries)
    except LedgerVerificationError as exc:
        print(f"ITGL ledger verification FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"ITGL ledger verification ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    itgl_final_hash = f"sha256:{final_hash_hex}"

    os.makedirs("proofs", exist_ok=True)
    with open("proofs/itgl_final_hash.txt", "w", encoding="utf-8") as out:
        out.write(itgl_final_hash + "\n")

    print(f"ITGL_FINAL_HASH={itgl_final_hash}")
    print(f"ITGL ledger verification OK: {len(entries)} entries, final_ledger_hash={final_hash_hex}")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
