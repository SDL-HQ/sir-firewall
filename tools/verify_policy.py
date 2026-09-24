#!/usr/bin/env python3
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical_payload(data: dict) -> bytes:
    """Must match sign_policy.py exactly."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


ROOT = Path(__file__).resolve().parents[1]


def verify_policy(
    signed_path: Path = ROOT / "policy/isc_policy.signed.json",
    enforced_path: Path = ROOT / "policy/isc_policy.json",
    pubkey_path: Path = ROOT / "spec/sdl.pub",
) -> tuple[bool, str]:
    """Verify authenticity and exact correspondence with the enforced policy."""
    try:
        with signed_path.open("r", encoding="utf-8") as f:
            signed = json.load(f)
    except FileNotFoundError:
        return False, f"{signed_path} not found"

    try:
        with enforced_path.open("r", encoding="utf-8") as f:
            enforced = json.load(f)
    except FileNotFoundError:
        return False, f"{enforced_path} not found"

    if signed.get("payload") != enforced:
        return False, "signed policy payload differs from policy/isc_policy.json enforced by the runtime"

    # Load public key
    try:
        with pubkey_path.open("rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        return False, f"{pubkey_path} not found"

    payload = canonical_payload(signed["payload"])

    # Check hash matches
    expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    actual_hash = signed.get("payload_hash")

    if actual_hash != expected_hash:
        return False, f"payload_hash mismatch (expected {expected_hash}, actual {actual_hash})"

    # Verify signature
    try:
        public_key.verify(
            base64.b64decode(signed["signature"]),
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:  # cryptography throws several specific errors; we treat all as failure
        return False, f"signature verification failed: {e}"

    return True, "signed policy is authentic and exactly matches the enforced policy"


def main() -> None:
    ok, detail = verify_policy()
    if not ok:
        print(f"ERROR: {detail}")
        sys.exit(1)

    print(f"Policy verification PASSED — {detail}")


if __name__ == "__main__":
    main()
