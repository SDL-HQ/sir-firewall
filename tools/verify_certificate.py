#!/usr/bin/env python3
"""
SIR Firewall — Certificate Verifier

Verifies:
- payload_hash matches the reconstructed signed payload bytes
- RSA signature matches those payload bytes using resolved public key material

Inputs:
- cert path (positional arg), OR
- "-" to read JSON cert from stdin

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

from key_registry import find_registry_key, public_key_pem_from_entry, revocation_allows_proof

DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")
DEFAULT_KEY_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")


def _require_json_object(obj: Any, source: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise SystemExit(f"ERROR: expected a JSON object for certificate from {source}, but got {type(obj).__name__}")
    # typing: we just asserted it's a dict
    return obj  # type: ignore[return-value]


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
        obj = json.loads(raw)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to parse JSON from stdin: {e}") from e

    return _require_json_object(obj, "stdin")


def _load_cert_from_file(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to read cert file: {path} ({e})") from e

    return _require_json_object(obj, str(path))


def _load_cert(cert_arg: str) -> tuple[Dict[str, Any], str]:
    # Explicit stdin mode.
    if cert_arg == "-":
        return _read_json_from_stdin_strict(), "stdin"

    # File path mode.
    p = Path(cert_arg)
    if not p.exists():
        raise SystemExit(f"ERROR: cert file does not exist: {p}")
    return _load_cert_from_file(p), str(p)


def _load_pubkey(pubkey_path: str) -> tuple[Any, str]:
    p = Path(pubkey_path)
    try:
        data = p.read_bytes()
        return serialization.load_pem_public_key(data), f"--pubkey {p}"
    except Exception as e:
        raise SystemExit(f"ERROR: failed to load public key: {p} ({e})") from e


def _load_pubkey_with_registry(
    cert: Dict[str, Any], pubkey_path: str, key_registry_path: str, require_registry: bool = False
) -> tuple[Any, str]:
    signing_key_id = cert.get("signing_key_id")
    registry_path = Path(key_registry_path)

    if "signing_key_id" in cert and (not isinstance(signing_key_id, str) or not signing_key_id):
        raise SystemExit("ERROR: signing_key_id must be a non-empty string when present")

    if isinstance(signing_key_id, str) and signing_key_id:
        if not registry_path.exists():
            if require_registry:
                raise SystemExit(
                    f"ERROR: key registry not found: {registry_path} (required for signing_key_id={signing_key_id})"
                )
            print(
                "WARNING: signing_key_id present but key registry unavailable; falling back to --pubkey verification only (revocation checks not enforced).",
                file=sys.stderr,
            )
            return _load_pubkey(pubkey_path)
        try:
            entry = find_registry_key(registry_path, signing_key_id)
            if entry is None:
                raise SystemExit(f"ERROR: signing_key_id not found in key registry: {signing_key_id}")
            allowed, reason = revocation_allows_proof(entry, cert.get("timestamp_utc"))
            if not allowed:
                raise SystemExit(f"ERROR: revoked-key verification failure: {reason}")
            pem = public_key_pem_from_entry(entry)
            return (
                serialization.load_pem_public_key(pem.encode("utf-8")),
                f"key registry {registry_path} entry signing_key_id={signing_key_id}",
            )
        except SystemExit:
            raise
        except Exception as e:
            if require_registry:
                raise SystemExit(
                    f"ERROR: failed to load required key registry {registry_path} ({e})"
                ) from e
            print(
                "WARNING: signing_key_id present but key registry unreadable; falling back to --pubkey verification only (revocation checks not enforced).",
                file=sys.stderr,
            )
            return _load_pubkey(pubkey_path)

    return _load_pubkey(pubkey_path)


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Verify certificate payload integrity and signature validity for an existing SIR certificate JSON."
        ),
        epilog=(
            "Examples:\n"
            "  python3 tools/verify_certificate.py proofs/latest-audit.json\n"
            "  cat proofs/latest-audit.json | python3 tools/verify_certificate.py -\n\n"
            "Key resolution:\n"
            "  If signing_key_id is present and key registry is readable, that key is used.\n"
            "  Otherwise verifier falls back to --pubkey unless --require-registry is set."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "cert",
        help='Certificate JSON path, or "-" to read certificate JSON from stdin.',
    )
    ap.add_argument(
        "--pubkey",
        default=str(DEFAULT_PUBKEY_PATH),
        help="Path to PEM public key to verify signatures (default: spec/sdl.pub).",
    )
    ap.add_argument(
        "--key-registry",
        default=str(DEFAULT_KEY_REGISTRY),
        help="Path to key registry JSON used with signing_key_id if present (default: spec/pubkeys/key_registry.v1.json).",
    )
    ap.add_argument(
        "--require-registry",
        action="store_true",
        help="Fail when signing_key_id is present but key registry is missing/unreadable (disables --pubkey fallback).",
    )
    ap.add_argument("--quiet", action="store_true", help="Only exit code, no success message.")
    return ap.parse_args()


def _rebuild_payload(cert: Dict[str, Any]) -> bytes:
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> int:
    args = _parse_args()

    cert, _source = _load_cert(args.cert)
    public_key, key_source = _load_pubkey_with_registry(
        cert, args.pubkey, args.key_registry, require_registry=args.require_registry
    )

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
        print(
            "OK: payload_hash matches reconstructed signed payload and signature verifies "
            f"against {key_source}; this proves payload integrity + signature validity only "
            "(not policy correctness, model safety, or broader trust guarantees)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
