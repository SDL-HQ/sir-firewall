#!/usr/bin/env python3
"""
SIR Firewall — Certificate Verifier

Verifies:
- payload_hash matches reconstructed payload
- RSA signature matches payload using provided public key

Inputs:
- cert path (positional arg), OR
- "-" to read JSON cert from stdin, OR
- if cert arg omitted and stdin is piped, read from stdin

Default (when cert omitted and stdin is a TTY):
- proofs/latest-audit.json (if it exists)

Defaults:
- pubkey: spec/sdl.pub
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")
DEFAULT_CERT_PATH = Path("proofs/latest-audit.json")


def _read_json_from_stdin_strict() -> Dict[str, Any]:
    if sys.stdin is None:
        raise SystemExit("ERROR: stdin is unavailable")

    # If user explicitly asked for stdin ("-") but stdin is a TTY, fail fast with guidance.
    if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        raise SystemExit('ERROR: stdin is a TTY. Pipe JSON into stdin, or pass a certificate file path.')

    raw = sys.stdin.read()
    if raw is None:
        raise SystemExit("ERROR: failed to read stdin")

    raw = raw.strip()
    if not raw:
        raise SystemExit("ERROR: no JSON provided on stdin")

    try:
        return json.loads(raw)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to parse JSON from stdin: {e}") from e


def _load_cert_from_file(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to read cert file: {path} ({e})") from e


def _load_cert(cert_arg: str | None) -> tuple[Dict[str, Any], str]:
    # Explicit stdin mode.
    if cert_arg == "-":
        return _read_json_from_stdin_strict(), "stdin"

    # If cert omitted: read from stdin if piped; else fall back to default file path.
    if cert_arg is None:
        if sys.stdin is not None and hasattr(sys.stdin, "isatty") and not sys.stdin.isatty():
            return _read_json_from_stdin_strict(), "stdin"
        if DEFAULT_CERT_PATH.exists():
            return _load_cert_from_file(DEFAULT_CERT_PATH), str(DEFAULT_CERT_PATH)
        raise SystemExit(
            f"ERROR: no cert argument provided, stdin is not piped, and default cert not found: {DEFAULT_CERT_PATH}"
        )

    # File path mode.
    p = Path(cert_arg)
    if not p.exists():
        raise SystemExit(f"ERROR: cert file does not exist: {p}")
    return _load_cert_from_file(p), str(p)


def _load_pubkey(pubkey_path: str) -> Any:
    p = Path(pubkey_path)
    try:
        data = p.read_bytes()
        return serialization.load_pem_public_key(data)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to load public key: {p} ({e})") from e


def _rebuild_payload(cert: Dict[str, Any]) -> bytes:
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a SIR audit certificate JSON.")
    ap.add_argument(
        "cert",
        nargs="?",
        default=None,
        help=(
            'Path to certificate JSON, or "-" to read from stdin. '
            "If omitted and stdin is piped, reads from stdin; otherwise "
            f"attempts to use {DEFAULT_CERT_PATH} if it exists."
        ),
    )
    ap.add_argument(
        "--pubkey",
        default=str(DEFAULT_PUBKEY_PATH),
        help="Path to PEM public key to verify signatures (default: spec/sdl.pub).",
    )
    ap.add_argument("--quiet", action="store_true", help="Only exit code, no success message.")
    args = ap.parse_args()

    cert, _source = _load_cert(args.cert)
    public_key = _load_pubkey(args.pubkey)

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
