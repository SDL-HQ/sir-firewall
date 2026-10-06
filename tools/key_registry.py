#!/usr/bin/env python3
"""Shared key-registry helpers for offline certificate/receipt verification."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

TS_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RUN_NUMBER_RE = re.compile(r"-gh(\d+)-")


def parse_utc_z(ts: str) -> datetime:
    if not isinstance(ts, str) or TS_Z_RE.match(ts) is None:
        raise ValueError("timestamp must be UTC ISO-8601 with Z suffix")
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_registry(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"failed to parse key registry JSON {path}: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object in {path}, got {type(obj).__name__}")
    return obj


def find_registry_key(path: Path, key_id: str) -> Optional[Dict[str, Any]]:
    reg = load_registry(path)
    keys = reg.get("keys")
    if not isinstance(keys, list):
        raise ValueError("key registry keys must be a list")
    for item in keys:
        if isinstance(item, dict) and item.get("key_id") == key_id:
            return item
    return None


def public_key_pem_from_entry(entry: Dict[str, Any]) -> str:
    pem = entry.get("pubkey_pem")
    if isinstance(pem, str) and pem.strip():
        return pem

    b64 = entry.get("pubkey_base64")
    if isinstance(b64, str) and b64.strip():
        return base64.b64decode(b64.encode("ascii")).decode("utf-8")

    raise ValueError("registry key entry missing pubkey_pem/pubkey_base64")


def run_number_from_run_id(run_id: Optional[str]) -> Optional[int]:
    """CI run number embedded in a run identifier, or None.

    Run identifiers carry the publishing CI run as ``-gh<number>-``. The number
    increases monotonically per repository and is assigned by the forge, not by
    whoever holds a signing key.
    """
    if not isinstance(run_id, str):
        return None
    match = RUN_NUMBER_RE.search(run_id)
    return int(match.group(1)) if match else None


def revocation_allows_proof(
    entry: Dict[str, Any],
    proof_timestamp_utc: Optional[str],
    proof_run_id: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Decide whether a revoked key's signature may still be honoured.

    A revoked key is, by assumption, held by someone who can sign anything they
    like, including a certificate carrying a timestamp from before the
    revocation. The signer's own timestamp therefore cannot decide this: it is
    chosen by the party the revocation exists to stop.

    The anchor decides instead. ``last_trusted_run_id`` names the last run
    published before the key was revoked, and a proof counts as
    pre-revocation only if its own run identifier is at or below that one. Run
    numbers come from the forge, so a key holder cannot raise theirs. The
    timestamp is still checked, but it can only tighten the result.

    Fails closed when the entry carries no anchor, or the proof carries no
    parseable run identifier.
    """
    if entry.get("status") != "revoked":
        return True, None

    revoked_utc = entry.get("revoked_utc")
    if not isinstance(revoked_utc, str):
        return False, "revoked key missing revoked_utc"

    anchor_run_id = entry.get("last_trusted_run_id")
    anchor = run_number_from_run_id(anchor_run_id)
    if anchor is None:
        return False, (
            "revoked key has no usable last_trusted_run_id anchor, and revocation "
            "cannot be established from a signer-supplied timestamp alone"
        )

    proof_number = run_number_from_run_id(proof_run_id)
    if proof_number is None:
        return False, "proof carries no parseable run_id (fail closed for revocation checks)"

    if proof_number > anchor:
        return False, (
            f"proof run_id {proof_run_id} is after the last trusted run "
            f"{anchor_run_id} for this revoked key"
        )

    if isinstance(proof_timestamp_utc, str) and proof_timestamp_utc:
        if parse_utc_z(proof_timestamp_utc) >= parse_utc_z(revoked_utc):
            return False, (
                f"proof timestamp_utc {proof_timestamp_utc} is at/after "
                f"revoked_utc {revoked_utc}"
            )

    return True, None
