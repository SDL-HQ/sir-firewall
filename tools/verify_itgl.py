#!/usr/bin/env python3
"""
Verify the ITGL hash-chained *run ledger* emitted by red_team_suite.py.

Ledger file: proofs/itgl_ledger.jsonl

Checks:
- Each entry has required fields
- Chain continuity:
    - entry[i].prev_hash == entry[i-1].ledger_hash
    - entry[0].prev_hash == "GENESIS"
- Hash rule (must match red_team_suite.py exactly):
    ledger_hash == sha256( prev_hash + itgl_prompt_final_hash_raw )

Where:
- itgl_prompt_final_hash is stored as "sha256:<hex>" in the ledger
- we strip the "sha256:" prefix before chaining

Outputs:
- Writes proofs/itgl_final_hash.txt as "sha256:<final_ledger_hash>"
- Prints "ITGL_FINAL_HASH=sha256:<final_ledger_hash>" for CI
"""

import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, Any, List

LEDGER_PATH = Path("proofs") / "itgl_ledger.jsonl"


class LedgerVerificationError(RuntimeError):
    """Raised when the run ledger fails structural or hash checks."""


def _load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise LedgerVerificationError(f"Run ledger not found at {path}")

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
        raise LedgerVerificationError("Run ledger is empty")

    return entries


def _verify_entry_fields(entry: Dict[str, Any], index: int) -> None:
    required_fields = [
        "ts",
        "prompt_index",
        "isc_template",
        "suite_path",
        "domain_pack",
        "status",
        "expected",
        "prev_hash",
        "ledger_hash",
        # P2 ledger field name:
        "itgl_prompt_final_hash",
    ]
    missing = [f for f in required_fields if f not in entry]
    if missing:
        raise LedgerVerificationError(
            f"Entry #{index} missing required fields: {', '.join(missing)}"
        )


def _strip_sha256_prefix(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("sha256:"):
        return v.split("sha256:", 1)[1]
    return v


def _compute_ledger_hash(prev_hash: str, itgl_prompt_final_hash: str) -> str:
    # Must mirror red_team_suite.py:
    # ledger_hash = sha256( (prev_hash + final_hash_raw).encode("utf-8") )
    final_raw = _strip_sha256_prefix(itgl_prompt_final_hash)
    payload = (prev_hash or "") + final_raw
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_ledger(entries: List[Dict[str, Any]]) -> str:
    previous_ledger_hash = None
    final_ledger_hash = ""

    for idx, entry in enumerate(entries):
        human_index = idx + 1
        _verify_entry_fields(entry, human_index)

        prev_hash = str(entry["prev_hash"])
        itgl_prompt_final_hash = str(entry["itgl_prompt_final_hash"])
        stored_ledger_hash = str(entry["ledger_hash"])

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

        computed_ledger_hash = _compute_ledger_hash(prev_hash, itgl_prompt_final_hash)
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
        print(f"Run ledger verification FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"Run ledger verification ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    itgl_final_hash = f"sha256:{final_hash}"

    os.makedirs("proofs", exist_ok=True)
    (Path("proofs") / "itgl_final_hash.txt").write_text(itgl_final_hash + "\n", encoding="utf-8")

    print(f"ITGL_FINAL_HASH={itgl_final_hash}")
    print(f"Run ledger verification OK: {len(entries)} entries, final_ledger_hash={final_hash}")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
