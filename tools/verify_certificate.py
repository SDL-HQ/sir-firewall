#!/usr/bin/env python3
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load certificate
with open("proofs/audit-certificate.json") as f:
    cert = json.load(f)

# Load public key
with open("spec/sdl.pub", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Rebuild exact signed payload
payload = json.dumps(
    {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
    separators=(",", ":")
).encode()

# Recompute payload hash
expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
if cert.get("payload_hash") != expected_hash:
    print("Payload hash mismatch!")
    raise SystemExit(1)

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
    raise SystemExit(1)
