#!/usr/bin/env python3
"""Verify that the signed policy is authentic and matches the enforced policy.

Authenticity is resolved through spec/pubkeys/key_registry.v1.json rather than
against a public key file on disk. A file on disk answers no questions about
status: it cannot say whether the key is active, retired or revoked. The
registry can, and it is the only key surface the project publishes.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parent))

from key_registry import find_registry_key, public_key_pem_from_entry  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

SIGNATURE_SCHEMA = "isc-policy-signature/v2"
DEFAULT_KEY_REGISTRY = ROOT / "spec/pubkeys/key_registry.v1.json"


def canonical_payload(data: dict) -> bytes:
    """Must match sign_policy.py exactly."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signing_input(schema: str, key_id: str, payload_hash: str) -> bytes:
    """Must match sign_policy.py exactly."""
    return canonical_payload(
        {"schema": schema, "key_id": key_id, "payload_hash": payload_hash}
    )


def verify_policy(
    signed_path: Path = ROOT / "policy/isc_policy.signed.json",
    enforced_path: Path = ROOT / "policy/isc_policy.json",
    registry_path: Path = DEFAULT_KEY_REGISTRY,
) -> tuple[bool, str]:
    """Verify authenticity and exact correspondence with the enforced policy."""
    try:
        with Path(signed_path).open("r", encoding="utf-8") as f:
            signed = json.load(f)
    except FileNotFoundError:
        return False, f"{signed_path} not found"

    try:
        with Path(enforced_path).open("r", encoding="utf-8") as f:
            enforced = json.load(f)
    except FileNotFoundError:
        return False, f"{enforced_path} not found"

    if signed.get("payload") != enforced:
        return False, (
            "signed policy payload differs from policy/isc_policy.json "
            "enforced by the runtime"
        )

    schema = signed.get("schema")
    if schema != SIGNATURE_SCHEMA:
        if schema is None:
            return False, (
                "signed policy carries no schema and no key identity, so the "
                "signing key cannot be resolved through the registry. Re-sign "
                f"with tools/sign_policy.py to produce {SIGNATURE_SCHEMA}"
            )
        return False, f"unsupported signed policy schema {schema!r}"

    key_id = signed.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        return False, "signed policy carries no key_id"
    key_id = key_id.strip()

    payload = canonical_payload(signed["payload"])
    expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    actual_hash = signed.get("payload_hash")
    if actual_hash != expected_hash:
        return False, (
            f"payload_hash mismatch (expected {expected_hash}, actual {actual_hash})"
        )

    entry = find_registry_key(Path(registry_path), key_id)
    if entry is None:
        return False, f"signing key {key_id} is not in the key registry"

    status = str(entry.get("status") or "").strip().lower()
    if status != "active":
        return False, (
            f"signing key {key_id} has registry status {status or 'unset'!r}, "
            "not active. A policy signed by a key that is no longer active "
            "cannot gate certificate generation; rotate and re-sign"
        )

    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem_from_entry(entry).encode("utf-8")
        )
    except Exception as exc:  # malformed registry entry is a verification failure
        return False, f"registry entry for {key_id} carries no usable public key: {exc}"

    try:
        public_key.verify(
            base64.b64decode(signed["signature"]),
            signing_input(schema, key_id, actual_hash),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:  # cryptography throws several specific errors; all are failure
        return False, f"signature verification failed: {e}"

    return True, (
        f"signed policy is authentic under registry key {key_id} and exactly "
        "matches the enforced policy"
    )


def main() -> None:
    ok, detail = verify_policy()
    if not ok:
        print(f"ERROR: {detail}")
        sys.exit(1)

    print(f"Policy verification PASSED - {detail}")


if __name__ == "__main__":
    main()
