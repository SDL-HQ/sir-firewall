#!/usr/bin/env python3
"""Sign policy/isc_policy.json, recording which key did it.

A signed policy that does not name its own signing key cannot be resolved
through the key registry, which means it cannot be revoked, cannot be anchored,
and carries no evidence of its signer. That matters more here than elsewhere:
generate_certificate.py refuses to issue a certificate when verify_policy()
fails, so this artefact gates every other signature the project produces.

The key id is inside the signed bytes rather than beside them. Recording it as
an unsigned field would reproduce the same missing binding one level up.
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

SIGNATURE_SCHEMA = "isc-policy-signature/v2"


def load_private_key():
    """Load SDL private key from env, same pattern as generate_certificate.py."""
    pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def signing_key_id() -> str:
    """The registry key id this signature claims.

    Mirrors generate_certificate.py so a rotation cannot move one and not the
    other. Both read SDL_SIGNING_KEY_ID and both fall back to "default".
    """
    return (os.getenv("SDL_SIGNING_KEY_ID") or "default").strip() or "default"


def canonical_payload(data: dict) -> bytes:
    """
    Canonical JSON representation for hashing/signing.

    sort_keys=True + compact separators guarantees stable hashes
    across runs and environments.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signing_input(schema: str, key_id: str, payload_hash: str) -> bytes:
    """The bytes the signature covers.

    The policy itself is covered transitively: payload_hash is the hash of the
    canonical policy, and verify_policy recomputes it from the enforced file
    before checking the signature, so a swapped payload fails on the hash.
    """
    return canonical_payload(
        {"schema": schema, "key_id": key_id, "payload_hash": payload_hash}
    )


def main() -> None:
    # Load raw policy
    with open("policy/isc_policy.json", "r", encoding="utf-8") as f:
        policy = json.load(f)

    payload = canonical_payload(policy)
    payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    key_id = signing_key_id()

    # Sign with SDL private key
    private_key = load_private_key()
    signature = private_key.sign(
        signing_input(SIGNATURE_SCHEMA, key_id, payload_hash),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    signed = {
        "schema": SIGNATURE_SCHEMA,
        "key_id": key_id,
        "payload": policy,
        "payload_hash": payload_hash,
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    os.makedirs("policy", exist_ok=True)
    out_path = "policy/isc_policy.signed.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2)
        f.write("\n")

    print(f"Signed policy -> {out_path}")
    print(f"Key id: {key_id}")
    print(f"Payload hash: {payload_hash}")


if __name__ == "__main__":
    main()
