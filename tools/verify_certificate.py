#!/usr/bin/env python3
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _load_public_key() -> bytes:
    candidates = [
        Path("sdl.pub"),
        Path("spec") / "sdl.pub",
    ]
    for p in candidates:
        if p.exists():
            return p.read_bytes()
    raise SystemExit("ERROR: Public key not found (expected ./sdl.pub or ./spec/sdl.pub)")


def _read_cert() -> dict:
    # If piped input exists (curl | python -m tools.verify_certificate)
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if not raw:
            raise SystemExit("ERROR: No JSON received on stdin")
        return json.loads(raw)

    # Else read from file path arg or default proofs/latest-audit.json
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("proofs") / "latest-audit.json"
    if not path.exists():
        raise SystemExit(f"ERROR: Certificate not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    cert = _read_cert()

    sig_b64 = cert.get("signature")
    payload_hash_claim = str(cert.get("payload_hash") or "").strip()

    if not sig_b64:
        raise SystemExit("ERROR: Missing signature field")
    if not payload_hash_claim.startswith("sha256:"):
        raise SystemExit("ERROR: Missing/invalid payload_hash (expected 'sha256:<hex>')")

    # Reconstruct payload (everything except signature + payload_hash)
    payload = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Verify payload hash
    computed = hashlib.sha256(payload_bytes).hexdigest()
    claimed = payload_hash_claim.split("sha256:", 1)[1]
    if computed != claimed:
        raise SystemExit(f"ERROR: Payload hash mismatch\n  claimed={claimed}\n  computed={computed}")

    # Verify RSA signature
    pub_bytes = _load_public_key()
    public_key = serialization.load_pem_public_key(pub_bytes)

    signature = base64.b64decode(sig_b64)
    public_key.verify(
        signature,
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    print("OK: Certificate signature valid and payload_hash matches.")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
