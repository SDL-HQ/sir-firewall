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

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from key_registry import find_registry_key, public_key_pem_from_entry, revocation_allows_proof
from itgl import LedgerVerificationError, load_and_verify_ledger

DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")
DEFAULT_KEY_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")
LEDGER_BINDING_FAILURE = 7
LEDGER_BINDING_NOT_CHECKED = 9


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
            "  python3 tools/verify_certificate.py proofs/latest-audit.json --no-ledger\n"
            "  cat proofs/latest-audit.json | python3 tools/verify_certificate.py - --no-ledger\n\n"
            "Key resolution:\n"
            "  If signing_key_id is present and key registry is readable, that key is used.\n"
            "  Otherwise verifier falls back to --pubkey unless --require-registry is set.\n\n"
            "Exit code 7 means ledger chain or certificate-binding verification failed.\n"
            "Exit code 9 means binding was not checked because no ledger was found."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--ledger",
        help="Verify this ITGL ledger and bind its chain head and row count to the certificate.",
    )
    ap.add_argument(
        "--no-ledger",
        action="store_true",
        help="Explicitly skip ledger discovery and certificate-to-ledger binding verification.",
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
    args = ap.parse_args()
    if args.ledger and args.no_ledger:
        ap.error("--ledger and --no-ledger are mutually exclusive")
    return args


def _discover_ledger(cert: Dict[str, Any], cert_arg: str) -> Path | None:
    """Resolve a ledger from signed run identity, never unrelated adjacency."""
    if cert_arg == "-":
        return None

    cert_dir = Path(cert_arg).parent
    run_id = cert.get("run_id")
    if isinstance(run_id, str) and run_id:
        try:
            from sir_firewall.evidence_paths import canonical_ledger_path

            canonical = canonical_ledger_path(run_id)
        except (ImportError, ValueError):
            canonical = None
        if canonical is not None and canonical.is_file():
            return canonical

        archive_candidate = cert_dir / "proofs" / "itgl_ledger.jsonl"
        if cert_dir.name == run_id and archive_candidate.is_file():
            return archive_candidate
        return None

    return None


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

    ledger_path = Path(args.ledger) if args.ledger else (None if args.no_ledger else _discover_ledger(cert, args.cert))
    if not args.no_ledger and ledger_path is None:
        run_id = cert.get("run_id")
        identity_detail = (
            f" for signed run_id={run_id!r}" if isinstance(run_id, str) and run_id else ""
        )
        print(
            "NOT CHECKED: certificate-to-ledger binding was not checked because no ledger "
            f"corresponding to the signed identity{identity_detail} was found. "
            "Pass --ledger PATH explicitly for replay or use --no-ledger to skip binding.",
            file=sys.stderr,
        )
        return LEDGER_BINDING_NOT_CHECKED

    if ledger_path is not None:
        try:
            ledger_hash, row_count = load_and_verify_ledger(ledger_path)
        except (LedgerVerificationError, OSError, UnicodeError) as exc:
            print(f"ERROR: ledger binding verification failed: {exc}", file=sys.stderr)
            return LEDGER_BINDING_FAILURE
        cert_hash = cert.get("itgl_final_hash")
        if ledger_hash != cert_hash:
            print("ERROR: ledger binding verification failed: terminal hash mismatch", file=sys.stderr)
            print(f"  cert: {cert_hash}", file=sys.stderr)
            print(f"  ledger: {ledger_hash}", file=sys.stderr)
            return LEDGER_BINDING_FAILURE
        prompts_tested = cert.get("prompts_tested")
        signed_row_count = cert.get("itgl_row_count")
        if signed_row_count is None:
            print(
                "ERROR: ledger binding verification failed: certificate carries no itgl_row_count,\n"
                "so the signed row count cannot be bound to this ledger "
                f"(ledger rows: {row_count},\nprompts_tested: {prompts_tested}). "
                "Certificates emitted before SIR 2.3.4 do not carry this field.",
                file=sys.stderr,
            )
            return LEDGER_BINDING_FAILURE
        if row_count != prompts_tested or row_count != signed_row_count:
            print("ERROR: ledger binding verification failed: row count mismatch", file=sys.stderr)
            print(f"  prompts_tested: {prompts_tested}", file=sys.stderr)
            print(f"  signed itgl_row_count: {signed_row_count}", file=sys.stderr)
            print(f"  ledger rows: {row_count}", file=sys.stderr)
            return LEDGER_BINDING_FAILURE

    if cert.get("detached_ledger") is True:
        print(
            "WARNING: certificate is explicitly marked detached_ledger=true; "
            "its signed run_id does not assert the canonical location of this ledger.",
            file=sys.stderr,
        )

    if args.no_ledger:
        print(
            "NOT VERIFIED: certificate-to-ledger binding was skipped with --no-ledger.",
            file=sys.stderr,
        )

    if not args.quiet:
        if ledger_path is not None:
            print(
                "OK: payload_hash and signature verify "
                f"against {key_source}; ledger binding verifies signed itgl_final_hash="
                f"{ledger_hash} equals the ledger terminal hash from {ledger_path}, and signed "
                f"itgl_row_count={row_count} equals prompts_tested={prompts_tested}."
            )
        else:
            print(
                "OK: payload_hash and signature verify "
                f"against {key_source}; certificate integrity and signature are valid."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
