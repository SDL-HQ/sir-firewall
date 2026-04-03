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


def revocation_allows_proof(entry: Dict[str, Any], proof_timestamp_utc: Optional[str]) -> Tuple[bool, Optional[str]]:
    status = entry.get("status")
    if status != "revoked":
        return True, None

    revoked_utc = entry.get("revoked_utc")
    if not isinstance(revoked_utc, str):
        return False, "revoked key missing revoked_utc"

    revoked_ts = parse_utc_z(revoked_utc)
    if not isinstance(proof_timestamp_utc, str) or not proof_timestamp_utc:
        return False, "timestamp_utc missing in proof (fail closed for revocation checks)"

    proof_ts = parse_utc_z(proof_timestamp_utc)
    if proof_ts >= revoked_ts:
        return False, f"proof timestamp_utc {proof_timestamp_utc} is at/after revoked_utc {revoked_utc}"
    return True, None
