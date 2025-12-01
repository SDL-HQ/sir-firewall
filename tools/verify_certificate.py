#!/usr/bin/env python3
import json
import base64
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load the certificate we just generated
with open("proofs/audit-certificate.json") as f:
    cert = json.load(f)

# Load the real public key (the one you just cleaned)
with open("spec/sdl.pub", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Reconstruct the exact payload that was signed
payload = json.dumps(
    {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
    separators=(",", ":")
).encode()

expected_hash = "sha256:" + hashes.SHA256().finalize(hashes.Hash(hashes.SHA256()).update(payload).finalize()).hex()
if cert["payload_hash"] != expected_hash:
    print("payload hash mismatch!")
    sys.exit(1)

# Verify signature
try:
    public_key.verify(
        base64.b64decode(cert["signature"]),
        payload,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Signature verification PASSED — 100% real, cryptographically valid")
except Exception as e:
    print(f"Signature verification FAILED: {e}")
    sys.exit(1)
