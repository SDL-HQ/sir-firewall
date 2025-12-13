#!/usr/bin/env python3
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _load_json_from_path_or_stdin(default_path: str) -> Dict[str, Any]:
    """
    Rules:
      - If stdin is piped (not a TTY), read stdin.
      - Else read from default_path (or argv[1] if provided).
      - Also accept explicit "-" to force stdin.
    """
    # Explicit "-" forces stdin
    if len(sys.argv) > 1 and sys.argv[1].strip() == "-":
        raw = sys.stdin.read()
        if not raw.strip():
            raise RuntimeError("No input provided on stdin")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise RuntimeError("Certificate JSON must be an object")
        return obj

    # Piped input
    if not sys.stdin.isatty():
        raw = sys.stdin.read()
        if raw.strip():
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise RuntimeError("Certificate JSON must be an object")
            return obj

    # File path
    path = sys.argv[1] if len(sys.argv) > 1 else default_path
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError("Certificate JSON must be an object")
    return obj


def _find_public_key_bytes() -> bytes:
    candidates = [
        Path("policy") / "sdl_public_key.pem",  # canonical
        Path("spec") / "sdl.pub",               # fallback (legacy/spec)
        Path("keys") / "sdl_public_key.pem",
        Path("tools") / "sdl_public_key.pem",
        Path("sdl_public_key.pem"),
        Path("sdl.pub"),
    ]
    for c in candidates:
        if c.exists():
            return c.read_bytes()

    env = os.getenv("SDL_PUBLIC_KEY_PEM", "").strip()
    if env:
        return env.encode("utf-8")

    raise RuntimeError(
        "SDL public key not found. Expected one of:\n"
        "  policy/sdl_public_key.pem\n"
        "  spec/sdl.pub\n"
        "  keys/sdl_public_key.pem\n"
        "  tools/sdl_public_key.pem\n"
        "  ./sdl_public_key.pem\n"
        "  ./sdl.pub\n"
        "Or provide SDL_PUBLIC_KEY_PEM in env."
    )


def _load_public_key(pub_bytes: bytes):
    s = pub_bytes.lstrip()
    if s.startswith(b"ssh-"):
        return serialization.load_ssh_public_key(pub_bytes)
    return serialization.load_pem_public_key(pub_bytes)


def _canonical_payload_bytes(cert: Dict[str, Any]) -> bytes:
    # MUST match tools/generate_certificate.py:
    # Hash/sign over payload fields ONLY (exclude payload_hash + signature).
    payload = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strip_sha256_prefix(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("sha256:"):
        return v.split("sha256:", 1)[-1].strip()
    return v


def main() -> None:
    cert = _load_json_from_path_or_stdin("proofs/latest-audit.json")

    sig_b64 = str(cert.get("signature") or "").strip()
    if not sig_b64:
        print("ERROR: Missing signature", file=sys.stderr)
        raise SystemExit(1)

    claimed_ph = str(cert.get("payload_hash") or "").strip()
    if not claimed_ph:
        print("ERROR: Missing payload_hash", file=sys.stderr)
        raise SystemExit(1)

    payload_bytes = _canonical_payload_bytes(cert)

    h = hashes.Hash(hashes.SHA256())
    h.update(payload_bytes)
    computed = h.finalize().hex()

    claimed_hex = _strip_sha256_prefix(claimed_ph)

    if claimed_hex != computed:
        print("ERROR: Payload hash mismatch", file=sys.stderr)
        print(f"  claimed={claimed_hex}", file=sys.stderr)
        print(f"  computed={computed}", file=sys.stderr)
        raise SystemExit(1)

    pub_bytes = _find_public_key_bytes()
    public_key = _load_public_key(pub_bytes)

    try:
        signature = base64.b64decode(sig_b64)
    except Exception:
        print("ERROR: Signature is not valid base64", file=sys.stderr)
        raise SystemExit(1)

    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:
        print(f"ERROR: Signature verification failed: {e}", file=sys.stderr)
        raise SystemExit(1)

    print("OK: Certificate signature valid and payload_hash matches.")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
