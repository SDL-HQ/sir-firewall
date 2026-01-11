#!/usr/bin/env python3
"""
SIR Firewall — Certificate Verifier

Verifies:
- payload_hash matches reconstructed payload
- RSA signature matches payload using provided public key

Default behavior:
- cert: proofs/latest-audit.json
- pubkey: spec/sdl.pub

Also supports:
- reading JSON cert from stdin (pipe)
- verifying any cert path (positional arg)
- custom pubkey via --pubkey (useful for local test keys)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


DEFAULT_CERT_PATH = Path("proofs/latest-audit.json")
DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")


def _read_json_from_stdin() -> Optional[Dict[str, Any]]:
    if sys.stdin is None or sys.stdin.isatty():
        return None
    raw = sys.stdin.read().strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to parse JSON from stdin: {e}") from e


def _load_cert(cert_path: Optional[str]) -> Dict[str, Any]:
    # 1) If cert_path provided, read it
    if cert_path:
        p = Path(cert_path)
        try:
            with p.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise SystemExit(f"ERROR: failed to read cert file: {p} ({e})") from e

    # 2) If piped, read from stdin
    stdin_obj = _read_json_from_stdin()
    if stdin_obj is not None:
        return stdin_obj

    # 3) Default: proofs/latest-audit.json
    try:
        with DEFAULT_CERT_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise SystemExit(
            f"ERROR: no cert path provided and could not read default {DEFAULT_CERT_PATH} ({e})"
        ) from e


def _load_pubkey(pubkey_path: str) -> Any:
    p = Path(pubkey_path)
    try:
        data = p.read_bytes()
        return serialization.load_pem_public_key(data)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to load public key: {p} ({e})") from e


def _rebuild_payload(cert: Dict[str, Any]) -> bytes:
    # Must match tools/generate_certificate.py:
    # json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a SIR audit certificate JSON.")
    ap.add_argument(
        "cert",
        nargs="?",
        default=None,
        help="Path to certificate JSON (default: proofs/latest-audit.json). If omitted and stdin is piped, reads from stdin.",
    )
    ap.add_argument(
        "--pubkey",
        default=str(DEFAULT_PUBKEY_PATH),
        help="Path to PEM public key to verify signatures (default: spec/sdl.pub).",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Only exit code, no success message.",
    )
    args = ap.parse_args()

    cert = _load_cert(args.cert)
    public_key = _load_pubkey(args.pubkey)

    # Sanity
    if "signature" not in cert or "payload_hash" not in cert:
        print("ERROR: missing required fields: signature and/or payload_hash", file=sys.stderr)
        return 2

    payload = _rebuild_payload(cert)

    expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    if cert.get("payload_hash") != expected_hash:
        print("ERROR: payload_hash mismatch", file=sys.stderr)
        print(f"  cert: {cert.get('payload_hash')}", file=sys.stderr)
        print(f"  calc: {expected_hash}", file=sys.stderr)
        return 3

    try:
        sig = base64.b64decode(str(cert["signature"]))
    except Exception as e:
        print(f"ERROR: signature is not valid base64 ({e})", file=sys.stderr)
        return 4

    try:
        public_key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print("ERROR: signature verification failed (InvalidSignature)", file=sys.stderr)
        return 5
    except Exception as e:
        print(f"ERROR: signature verification failed ({e})", file=sys.stderr)
        return 6

    if not args.quiet:
        print("OK: Certificate signature valid and payload_hash matches.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
