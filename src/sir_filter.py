import json
import hashlib
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from typing import Dict, Any
from hmac import compare_digest


# --- Constants ---
WHITELIST = ["HIPAA-ISC-v1", "PCI-DSS-ISC-v1", "EU-AI-Act-ISC-v1"]
MAX_INPUT_BYTES = 1_048_576  # 1MB


# --- Helper Functions for ITGL Output ---

def reject(reason: str, code: int = 403) -> Dict[str, Any]:
    """Returns a standardized RED (blocked) log entry."""
    return {
        "status": "BLOCKED",
        "reason": reason,
        "itgl_log": {
            "event": "SIR_FAIL",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status_code": code,
            "message": f"Validation failed: {reason}",
        }
    }


def allow(isc_data: Dict[str, Any], key_fpr: str) -> Dict[str, Any]:
    """Returns a standardized BLUE (passed) log entry with key fingerprint."""
    return {
        "status": "PASS",
        "reason": "Governance signal verified.",
        "isc_payload": isc_data["payload"],
        "itgl_log": {
            "event": "SIR_PASS",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "template_id": isc_data["template_id"],
            "issuer": isc_data["provenance"]["issuer"],
            "key_fingerprint": key_fpr,
            "sig_alg": "RSA-PKCS1v15-SHA256",
            "status_code": 200,
        }
    }


# --- Token Counting + Key Fingerprint ---

def count_tokens(text: str) -> int:
    """Rough token count: 1 token ≈ 4 chars (GPT-style)"""
    return (len(text) + 3) // 4


def _spki_fingerprint_hex(pem: str) -> str:
    """SHA-256 of DER-encoded SubjectPublicKeyInfo."""
    k = serialization.load_pem_public_key(pem.encode())
    der = k.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


# --- Core SIR Validation Logic (SIR v1.0.2) ---

def validate_sir(input_data: Any) -> Dict[str, Any]:
    try:
        # 0. Early size guardrail
        if isinstance(input_data, str) and len(input_data.encode()) > MAX_INPUT_BYTES:
            return reject("Input exceeds size limit", code=413)

        input_json = json.loads(input_data) if isinstance(input_data, str) else input_data
        isc = input_json.get("isc", {})

        # 1. Schema Check
        required = ["version", "template_id", "priority_lock", "provenance", "payload", "checksum"]
        if not all(k in isc for k in required):
            return reject("Missing required ISC fields", code=400)

        # 2. Template Whitelist
        if isc["template_id"] not in WHITELIST:
            return reject("Unapproved governance template")

        # 3. Build canonical envelope (includes priority_lock)
        envelope_parts = [
            str(isc["version"]),
            isc["template_id"],
            isc["checksum"],
            isc["payload"],
            json.dumps(isc["priority_lock"], separators=(",", ":"), sort_keys=True)
        ]
        envelope = "|".join(envelope_parts).encode('utf-8')

        # 4. SHA256 Checksum over payload
        payload_bytes = isc["payload"].encode('utf-8')
        expected_checksum = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
        if not compare_digest(isc["checksum"], expected_checksum):
            return reject("Payload checksum mismatch")

        # 5. Signature Verification over full envelope
        prov = isc["provenance"]
        public_key = serialization.load_pem_public_key(prov["public_key"].encode())

        # Enforce RSA >= 2048
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            return reject("Invalid public key: must be RSA >= 2048 bits")

        # Strict base64 decode
        sig_b64 = prov["signature"].split(":", 1)[1] if ":" in prov["signature"] else prov["signature"]
        signature = base64.b64decode(sig_b64, validate=True)

        public_key.verify(
            signature,
            envelope,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # 6. Provenance Check
        if prov["issuer"] != "Structural Design Labs (SDL Limited)":
            return reject("Unauthorized issuer provenance")

        # 7. Friction Delta on payload
        if count_tokens(isc["payload"]) > 1000:
            return reject("Suspicious complexity (Friction Delta exceeded 1000 tokens)")

        # 8. PASS with key fingerprint
        key_fpr = _spki_fingerprint_hex(prov["public_key"])
        return allow(isc, key_fpr)

    except json.JSONDecodeError as e:
        return reject(f"JSON parse error: {e}", code=400)
    except KeyError as e:
        return reject(f"Missing field: {e}", code=400)
    except Exception as e:
        return reject(f"Cryptographic or validation error: {e}")
