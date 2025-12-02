#!/usr/bin/env python3
import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Always verify the real latest signed JSON
with open("proofs/latest-audit.json") as f:
    cert = json.load(f)

# Load the real public key
with open("spec/sdl.pub", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Re-create exact signed payload
payload = json.dumps(
    {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
    separators=(",", ":")
).encode()

# Check payload hash first
if cert["payload_hash"] != "sha256:" + hashlib.sha256(payload).hexdigest():
    print("Payload hash mismatch!")
    raise SystemExit(1)

# Verify signature
public_key.verify(
    base64.b64decode(cert["signature"]),
    payload,
    padding.PKCS1v15(),
    hashes.SHA256()
)

print("Signature verification PASSED — 100% real, cryptographically valid proof")
