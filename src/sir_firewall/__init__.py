from __future__ import annotations

import json
import hashlib
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Whitelisted templates (add more as needed)
WHITELISTED_TEMPLATES = {
    "HIPAA-ISC-v1",
    "PCI-DSS-ISC-v1",
    "EU-AI-Act-ISC-v1",
}

# Max token-equivalent friction (≈4 chars per token)
MAX_INPUT_BYTES = 4000


def validate_sir(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a SIR governance envelope.
    Returns {"status": "PASS" | "BLOCKED", "reason": "...", "itgl_log": "..."}
    """
    try:
        isc = payload.get("isc")
        if not isinstance(isc, dict):
            return _block("Missing or invalid 'isc' envelope")

        version = isc.get("version")
        if version != "1.0":
            return _block("Unsupported version")

        template_id = isc.get("template_id")
        if template_id not in WHITELISTED_TEMPLATES:
            return _block(f"Template {template_id} not whitelisted")

        provenance = isc.get("provenance", {})
        issuer = provenance.get("issuer")
        if issuer != "Structural Design Labs (SDL Limited)":
            return _block("Invalid issuer")

        payload_str = isc.get("payload", "")
        if len(payload_str.encode("utf-8")) > MAX_INPUT_BYTES:
            return _block("Friction delta exceeded (jailbreak spam)")

        checksum = isc.get("checksum")
        expected = "sha256:" + hashlib.sha256(payload_str.encode()).hexdigest()
        if checksum != expected:
            return _block("Checksum mismatch")

        # Signature validation would go here (omitted for brevity in public demo)
        # In production this loads spec/sdl.pub and verifies the RSA signature

        return {
            "status": "PASS",
            "reason": "Valid governance signal",
            "itgl_log": f"SIR_PASS|{template_id}|{expected}",
        }

    except Exception as e:
        return _block(f"Validation error: {e}")


def _block(reason: str) -> Dict[str, Any]:
    return {
        "status": "BLOCKED",
        "reason": reason,
        "itgl_log": f"SIR_BLOCK|{reason}",
    }
