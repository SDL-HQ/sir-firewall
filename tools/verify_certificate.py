#!/usr/bin/env python3
import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Load the certificate we just generated
with open("proofs/audit-certificate.json") as f:
    cert = json.load(f)

# Load the real public key
with open("spec/sdl.pub", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Reconstruct the exact signed payload (exclude signature + payload_hash)
payload = json.dumps(
    {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
    separators=(",", ":")
).encode()

# Recompute the payload hash exactly like the signer did
expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()

if cert.get("payload_hash") != expected_hash:
    print(f"Payload hash mismatch! Expected: {expected_hash}")
    print(f"Found in cert: {cert.get('payload_hash')}")
    raise SystemExit(1)

# Verify the RSA signature
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
