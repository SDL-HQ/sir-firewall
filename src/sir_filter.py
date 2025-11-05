import json
import hashlib
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from typing import Dict, Any


# --- Helper Functions for ITGL Output ---

def reject(reason: str) -> Dict[str, Any]:
    """Returns a standardized RED (blocked) log entry."""
    return {
        "status": "BLOCKED",
        "reason": reason,
        "itgl_log": {
            "event": "SIR_FAIL",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status_code": 403,
            "message": f"Validation failed: {reason}",
        }
    }


def allow(isc_data: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a standardized BLUE (passed) log entry."""
    return {
        "status": "PASS",
        "reason": "Governance signal verified.",
        "isc_payload": isc_data["payload"],
        "itgl_log": {
            "event": "SIR_PASS",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "template_id": isc_data["template_id"],
            "issuer": isc_data["provenance"]["issuer"],
            "status_code": 200,
        }
    }


# --- Core SIR Validation Logic (From Spec Section 4) ---

def validate_sir(input_data: Any) -> Dict[str, Any]:
    """
    Validates an Inference Substrate Compiler (ISC) payload using 6 checks.
    Accepts JSON string or dict.
    """
    try:
        # Accept string or dict
        if isinstance(input_data, str):
            input_json = json.loads(input_data)
        else:
            input_json = input_data

        isc = input_json.get("isc", {})
        
        # 1. Schema Check
        required = ["version", "template_id", "priority_lock", "provenance", "payload", "checksum"]
        if not all(k in isc for k in required):
            return reject("Missing required ISC fields")

        # 2. Template Whitelist Check
        WHITELIST = ["HIPAA-ISC-v1", "PCI-DSS-ISC-v1", "EU-AI-Act-ISC-v1"]
        if isc["template_id"] not in WHITELIST:
            return reject("Unapproved governance template")

        # 3. Checksum Verification (md5)
        payload_bytes = isc["payload"].encode('utf-8')
        expected_checksum = hashlib.md5(payload_bytes).hexdigest()
        if isc["checksum"] != f"md5:{expected_checksum}":
            return reject("Payload checksum mismatch")

        # 4. Signature Verification (SHA256 with PKCS1v15)
        prov = isc["provenance"]
        public_key = serialization.load_pem_public_key(prov["public_key"].encode())
        
        signature_base64 = prov["signature"].split(":", 1)[1] if ":" in prov["signature"] else prov["signature"]
        signature = base64.b64decode(signature_base64)
        
        public_key.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # 5. Provenance Check
        if prov["issuer"] != "Structural Design Labs (SDL Limited)":
            return reject("Unauthorized issuer provenance")

        # 6. Friction Delta
        if len(isc["payload"].split()) > 1000:
            return reject("Suspicious complexity (Friction Delta exceeded 1000 tokens)")

        # 7. Pass
        return allow(isc)

    except json.JSONDecodeError as e:
        return reject(f"JSON parse error: {e}")
    except KeyError as e:
        return reject(f"Missing field: {e}")
    except Exception as e:
        return reject(f"Cryptographic or validation error: {e}")
