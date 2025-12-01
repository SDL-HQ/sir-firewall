from __future__ import annotations

import hashlib
from typing import Any, Dict

# Whitelisted templates
WHITELISTED_TEMPLATES = {
    "HIPAA-ISC-v1",
    "PCI-DSS-ISC-v1",
    "EU-AI-Act-ISC-v1",
}

MAX_PAYLOAD_BYTES = 4000


def validate_sir(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        isc = payload.get("isc")
        if not isinstance(isc, dict):
            return _block("Missing 'isc' envelope")

        if isc.get("version") != "1.0":
            return _block("Unsupported version")

        if isc.get("template_id") not in WHITELISTED_TEMPLATES:
            return _block("Template not allowed")

        issuer = isc.get("provenance", {}).get("issuer", "")
        if issuer != "Structural Design Labs (SDL Limited)":
            return _block("Invalid issuer")

        payload_str = isc.get("payload", "")
        if len(payload_str.encode()) > MAX_PAYLOAD_BYTES:
            return _block("Friction delta exceeded")

        expected = "sha256:" + hashlib.sha256(payload_str.encode()).hexdigest()
        if isc.get("checksum") != expected:
            return _block("Checksum mismatch")

        return {
            "status": "PASS",
            "reason": "Valid governance signal",
            "itgl_log": f"SIR_PASS|{isc.get('template_id')}|{expected}",
        }

    except Exception as e:
        return _block(f"Validation error: {e}")


def _block(reason: str) -> Dict[str, Any]:
    return {
        "status": "BLOCKED",
        "reason": reason,
        "itgl_log": f"SIR_BLOCK|{reason}",
    }
