# tools/verify_certificate.py
#!/usr/bin/env python3
import base64
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _load_json_from_path_or_stdin(path: Optional[str]) -> Dict[str, Any]:
    # If piped (curl | python -m tools.verify_certificate), read stdin
    if path in (None, "", "-"):
        raw = sys.stdin.read()
        if not raw.strip():
            raise RuntimeError("No input provided on stdin")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise RuntimeError("Certificate JSON must be an object")
        return obj

    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError("Certificate JSON must be an object")
    return obj


def _find_public_key_pem() -> str:
    # Prefer repo-shipped public key files. Add more candidates if you move it.
    candidates = [
        Path("policy") / "sdl_public_key.pem",
        Path("keys") / "sdl_public_key.pem",
        Path("tools") / "sdl_public_key.pem",
        Path("sdl_public_key.pem"),
    ]
    for c in candidates:
        if c.exists():
            return c.read_text(encoding="utf-8")

    # Optional env override (useful for CI/local dev if needed)
    env = (sys.environ.get("SDL_PUBLIC_KEY_PEM") if hasattr(sys, "environ") else None)  # defensive
    if not env:
        env = None
    if env:
        return env

    raise RuntimeError(
        "SDL public key not found. Expected one of:\n"
        "  policy/sdl_public_key.pem\n"
        "  keys/sdl_public_key.pem\n"
        "  tools/sdl_public_key.pem\n"
        "  ./sdl_public_key.pem\n"
        "Or provide SDL_PUBLIC_KEY_PEM in env."
    )


def _canonical_payload_bytes(cert: Dict[str, Any]) -> bytes:
    # IMPORTANT: must match tools/generate_certificate.py
    payload = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strip_sha256_prefix(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("sha256:"):
        return v.split("sha256:", 1)[-1].strip()
    return v


def main() -> None:
    # Default to proofs/latest-audit.json for local runs
    path = sys.argv[1] if len(sys.argv) > 1 else "proofs/latest-audit.json"

    cert = _load_json_from_path_or_stdin(path)

    sig_b64 = str(cert.get("signature") or "").strip()
    if not sig_b64:
        print("ERROR: Missing signature", file=sys.stderr)
        raise SystemExit(1)

    claimed_ph = str(cert.get("payload_hash") or "").strip()
    if not claimed_ph:
        print("ERROR: Missing payload_hash", file=sys.stderr)
        raise SystemExit(1)

    payload_bytes = _canonical_payload_bytes(cert)
    computed_hex = hashes.Hash(hashes.SHA256())
    computed_hex.update(payload_bytes)
    computed = computed_hex.finalize().hex()

    claimed_hex = _strip_sha256_prefix(claimed_ph)

    if claimed_hex != computed:
        print("ERROR: Payload hash mismatch", file=sys.stderr)
        print(f"  claimed={claimed_hex}", file=sys.stderr)
        print(f"  computed={computed}", file=sys.stderr)
        raise SystemExit(1)

    # Load public key and verify signature over payload_bytes
    pub_pem = _find_public_key_pem()
    public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))

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
