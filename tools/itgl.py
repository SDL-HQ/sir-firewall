"""Shared loading and verification for SIR ITGL JSONL ledgers."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class LedgerVerificationError(RuntimeError):
    """Raised when an ITGL ledger fails structural or hash checks."""


CHAIN_VERSION_V1 = 1
CHAIN_VERSION_V2 = 2
CURRENT_CHAIN_VERSION = CHAIN_VERSION_V2
SUPPORTED_CHAIN_VERSIONS = (CHAIN_VERSION_V1, CHAIN_VERSION_V2)

# The only two fields a row's own hash cannot cover, because they are the hash
# and its predecessor. Everything else is covered, and that is deliberately
# expressed as an exclusion rather than a list of included fields: a
# maintained include-list makes anything omitted an undetected tamper surface,
# and new row fields would have to remember to join it.
CHAIN_FIELDS = ("prev_hash", "ledger_hash")


def declared_chain_version(entry: Dict[str, Any]) -> int:
    """Which rule computes this row's hash.

    This selects the computation and nothing else. Whether the row is
    acceptable is the minimum passed to verify_ledger, which comes from
    outside the data.

    What stops a tampered row being downgraded to v1 is not that minimum. In a
    v2 ledger the original hash already covered the row's contents, so
    recomputing under v1 produces a different value, the next row's prev_hash
    stops matching, and repairing the linkage moves the terminal hash the
    certificate signed. The mixed-version check below catches it earlier still.
    The minimum exists so a reader can require the stronger format where there
    is no signed terminal hash to pin anything, which is the standalone case.
    """
    value = entry.get("chain_version", CHAIN_VERSION_V1)
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerVerificationError(f"chain_version must be an integer, got {value!r}")
    if value not in SUPPORTED_CHAIN_VERSIONS:
        raise LedgerVerificationError(f"unsupported chain_version {value}")
    return value


def chain_payload(entry: Dict[str, Any]) -> str:
    """The bytes hashed alongside prev_hash, by version.

    v1 covers only the row's own opaque per-prompt digest, so every
    human-readable field in a published row is unbound. That was reproduced on
    a real archive on 2 October 2026: a row's decision, prompt identifier,
    prompt hash, leak flag and timestamp were all altered and the certificate
    still verified at exit 0.

    v2 covers a canonical form of the parsed row, computed from the object
    rather than the bytes on disk. Hashing the raw line would mean that
    re-serialising a ledger with different key order or unicode escaping broke
    every row; hashing the canonical object means reformatting survives and
    changing a value does not.
    """
    version = declared_chain_version(entry)
    if version == CHAIN_VERSION_V1:
        return _final_hash_raw(entry) or ""
    row = {key: value for key, value in entry.items() if key not in CHAIN_FIELDS}
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_ledger_hash(prev_hash: str, entry: Dict[str, Any]) -> str:
    """The chain rule, in one place.

    This module is what ships to third parties in a minimal verification
    bundle, so it holds the definition and the runner imports it. Until
    7 October 2026 red_team_suite.py carried a private copy, and writer and
    verifier agreed only because both were three lines long. A drift between
    them would mean our own archives verify for us and not for a reader.
    """
    return hashlib.sha256(
        ((prev_hash or "") + chain_payload(entry)).encode("utf-8")
    ).hexdigest()


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


def verify_ledger(
    entries: List[Dict[str, Any]],
    minimum_chain_version: int = CHAIN_VERSION_V1,
) -> str:
    """Verify chain linkage and per-row hashes.

    minimum_chain_version is the bar, and it comes from the caller rather than
    from the data: verify_certificate derives it from the certificate's signed
    sir_firewall_version, and the command line takes it as a flag. A row
    declaring a version below the bar is refused rather than verified under the
    weaker rule.

    The default is v1 so that the 292 archives published before 7 October 2026
    keep verifying under the rule they were written with. A verifier defaulting
    to v2 would manufacture a catastrophe out of a format change.
    """
    previous = None
    final = ""
    observed_versions = set()
    for offset, entry in enumerate(entries):
        index = offset + 1
        missing = [key for key in ("ts", "prompt_index", "prev_hash", "ledger_hash") if key not in entry]
        if missing:
            raise LedgerVerificationError(f"Entry #{index} missing required fields: {', '.join(missing)}")
        version = declared_chain_version(entry)
        observed_versions.add(version)
        if version < minimum_chain_version:
            raise LedgerVerificationError(
                f"Entry #{index} declares chain_version {version} but at least "
                f"{minimum_chain_version} is required. Under chain_version 1 the "
                "row hash does not cover the row's contents, so accepting this "
                "would accept an unbound row."
            )
        if len(observed_versions) > 1:
            raise LedgerVerificationError(
                f"Entry #{index} declares chain_version {version} in a ledger "
                f"that also uses {sorted(observed_versions - {version})}. One "
                "run writes one version; a mixture is tampering or a defect."
            )
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
        computed = compute_ledger_hash(prev_hash, entry)
        if stored != computed:
            raise LedgerVerificationError(
                f"Entry #{index} has invalid ledger_hash: stored={stored!r}, computed={computed!r}"
            )
        previous = stored
        final = stored
    if not final:
        raise LedgerVerificationError("No final ledger hash computed")
    return final


def load_and_verify_ledger(
    path: Path, minimum_chain_version: int = CHAIN_VERSION_V1
) -> Tuple[str, int]:
    """Return a verified prefixed chain head and nonblank ledger row count."""
    entries = load_ledger(path)
    return f"sha256:{verify_ledger(entries, minimum_chain_version)}", len(entries)


def ledger_chain_version(entries: List[Dict[str, Any]]) -> int:
    """The version a ledger was written with, for a verifier to report.

    A reader needs to be told which rule their archive was checked under,
    because "verified" means something different under each.
    """
    return max(declared_chain_version(entry) for entry in entries)
