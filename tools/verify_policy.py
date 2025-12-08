#!/usr/bin/env python3
import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical_payload(data: dict) -> bytes:
    """Must match sign_policy.py exactly."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> None:
    # Load signed policy
    try:
        with open("policy/isc_policy.signed.json", "r", encoding="utf-8") as f:
            signed = json.load(f)
    except FileNotFoundError:
        print("ERROR: policy/isc_policy.signed.json not found")
        sys.exit(1)

    # Load public key
    try:
        with open("spec/sdl.pub", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("ERROR: spec/sdl.pub not found")
        sys.exit(1)

    payload = canonical_payload(signed["payload"])

    # Check hash matches
    expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    actual_hash = signed.get("payload_hash")

    if actual_hash != expected_hash:
        print("ERROR: payload_hash mismatch")
        print(f"  expected: {expected_hash}")
        print(f"  actual:   {actual_hash}")
        sys.exit(1)

    # Verify signature
    try:
        public_key.verify(
            base64.b64decode(signed["signature"]),
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:  # cryptography throws several specific errors; we treat all as failure
        print(f"ERROR: signature verification failed: {e}")
        sys.exit(1)

    print("Policy verification PASSED — signed ISC policy is valid")


if __name__ == "__main__":
    main()
