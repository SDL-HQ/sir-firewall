"""Shared loading and verification for SIR ITGL JSONL ledgers."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class LedgerVerificationError(RuntimeError):
    """Raised when an ITGL ledger fails structural or hash checks."""


def load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise LedgerVerificationError(f"ITGL ledger not found at {path}")
    entries: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as source:
            for line_no, line in enumerate(source, start=1):
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
    except (OSError, UnicodeError) as exc:
        raise LedgerVerificationError(f"Unable to read ITGL ledger at {path}: {exc}") from exc
    if not entries:
        raise LedgerVerificationError("ITGL ledger is empty")
    return entries


def _final_hash_raw(entry: Dict[str, Any]) -> Optional[str]:
    if "final_hash" in entry:
        value = str(entry.get("final_hash") or "").strip()
        return value or None
    value = str(entry.get("itgl_prompt_final_hash") or "").strip()
    if not value:
        return None
    return value.split("sha256:", 1)[-1] if value.startswith("sha256:") else value


def verify_ledger(entries: List[Dict[str, Any]]) -> str:
    previous = None
    final = ""
    for offset, entry in enumerate(entries):
        index = offset + 1
        missing = [key for key in ("ts", "prompt_index", "prev_hash", "ledger_hash") if key not in entry]
        if missing:
            raise LedgerVerificationError(f"Entry #{index} missing required fields: {', '.join(missing)}")
        if "final_hash" not in entry and "itgl_prompt_final_hash" not in entry:
            raise LedgerVerificationError(
                f"Entry #{index} missing per-prompt final hash field (expected 'final_hash' or 'itgl_prompt_final_hash')"
            )
        prev_hash = str(entry.get("prev_hash") or "")
        stored = str(entry.get("ledger_hash") or "")
        raw = _final_hash_raw(entry)
        if not raw:
            raise LedgerVerificationError(f"Entry #{index} has empty final hash")
        if offset == 0 and prev_hash != "GENESIS":
            raise LedgerVerificationError(f"Entry #1 has unexpected prev_hash={prev_hash!r}, expected 'GENESIS'")
        if offset and prev_hash != previous:
            raise LedgerVerificationError(
                f"Entry #{index} prev_hash={prev_hash!r} does not match previous ledger_hash={previous!r}"
            )
        computed = hashlib.sha256((prev_hash + raw).encode("utf-8")).hexdigest()
        if stored != computed:
            raise LedgerVerificationError(
                f"Entry #{index} has invalid ledger_hash: stored={stored!r}, computed={computed!r}"
            )
        previous = stored
        final = stored
    if not final:
        raise LedgerVerificationError("No final ledger hash computed")
    return final


def load_and_verify_ledger(path: Path) -> Tuple[str, int]:
    """Return a verified prefixed chain head and nonblank ledger row count."""
    entries = load_ledger(path)
    return f"sha256:{verify_ledger(entries)}", len(entries)
