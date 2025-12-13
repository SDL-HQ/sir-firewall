#!/usr/bin/env python3
"""tools/verify_certificate.py

Verification utility for SIR audit certificates.

Supports:
- stdin (recommended):  curl .../latest-audit.json | python3 -m tools.verify_certificate
- file path argument:  python3 -m tools.verify_certificate proofs/latest-audit.json
- default local path:  proofs/latest-audit.json

Verification checks:
1) payload_hash matches canonicalised payload (everything except signature + payload_hash)
2) RSA signature validates against repo public key (spec/sdl.pub)
"""

import base64
import hashlib
import json
import sys
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


PUBLIC_KEY_CANDIDATES = [
    "spec/sdl.pub",
    "spec/sdl_public_key.pem",
    "policy/sdl_public_key.pem",
]


def _load_public_key():
    last_err = None
    for path in PUBLIC_KEY_CANDIDATES:
        try:
            with open(path, "rb") as f:
                return serialization.load_pem_public_key(f.read())
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(
        f"Could not load public key from any known path: {PUBLIC_KEY_CANDIDATES}. Last error: {last_err}"
    )


def _read_json_from_stdin() -> Optional[Dict[str, Any]]:
    if sys.stdin is None:
        return None
    try:
        if sys.stdin.isatty():
            return None
    except Exception:
        return None

    data = sys.stdin.read()
    if not data.strip():
        return None
    return json.loads(data)


def _read_json_from_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _canonical_payload(cert: Dict[str, Any]) -> bytes:
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> None:
    cert = _read_json_from_stdin()

    if cert is None:
        path = sys.argv[1] if len(sys.argv) > 1 else "proofs/latest-audit.json"
        cert = _read_json_from_file(path)

    if not isinstance(cert, dict):
        print("ERROR: certificate payload is not a JSON object")
        raise SystemExit(1)

    public_key = _load_public_key()
    payload = _canonical_payload(cert)

    expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    if cert.get("payload_hash") != expected_hash:
        print("ERROR: payload_hash mismatch")
        print(f"expected: {expected_hash}")
        print(f"got:      {cert.get('payload_hash')}")
        raise SystemExit(1)

    sig_b64 = cert.get("signature")
    if not sig_b64:
        print("ERROR: missing signature")
        raise SystemExit(1)

    try:
        public_key.verify(
            base64.b64decode(sig_b64),
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:
        print(f"ERROR: signature verification failed: {type(e).__name__}: {e}")
        raise SystemExit(1)

    print("OK: Certificate signature valid and payload_hash matches.")


if __name__ == "__main__":
    main()
