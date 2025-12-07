#!/usr/bin/env python3
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key():
    """Load SDL private key from env, same pattern as generate_certificate.py."""
    pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def canonical_payload(data: dict) -> bytes:
    """
    Canonical JSON representation for hashing/signing.

    sort_keys=True + compact separators guarantees stable hashes
    across runs and environments.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> None:
    # Load raw policy
    with open("policy/isc_policy.json", "r", encoding="utf-8") as f:
        policy = json.load(f)

    payload = canonical_payload(policy)
    payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()

    # Sign with SDL private key
    private_key = load_private_key()
    signature = private_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    signed = {
        "payload": policy,
        "payload_hash": payload_hash,
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    os.makedirs("policy", exist_ok=True)
    out_path = "policy/isc_policy.signed.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2)
        f.write("\n")

    print(f"Signed policy → {out_path}")
    print(f"Payload hash: {payload_hash}")


if __name__ == "__main__":
    main()
