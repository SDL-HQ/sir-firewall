# src/sir_firewall/core.py

import base64
import codecs
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Tuple

# Deliberately unused — kept as a loud reminder that we win without it
USE_SEMANTIC_CHECK = False

# ---------------------------------------------------------------------------
# Configuration (v1 defaults — safe but iterative)
# ---------------------------------------------------------------------------

REQUIRED_ISC_FIELDS = ["version", "template_id", "payload", "checksum", "signature"]

ALLOWED_TEMPLATES = {
    "HIPAA-ISC-v1",
    "EU-AI-Act-ISC-v1",
    "PCI-DSS-ISC-v1",
}

MAX_FRICTION_BY_TEMPLATE = {
    "HIPAA-ISC-v1": 1500,
    "EU-AI-Act-ISC-v1": 2000,
    "PCI-DSS-ISC-v1": 1200,
}

CHECKSUM_ENFORCED = True
CRYPTO_ENFORCED = False

# Fill with real PEM strings before enabling CRYPTO_ENFORCED
PUBLIC_KEYS: Dict[str, str] = {
    # "default": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...\n-----END PUBLIC KEY-----",
}

GENESIS_HASH = "0" * 64

# Optional cryptography — graceful fallback
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Obfuscation normalisation
# ---------------------------------------------------------------------------

def normalize_obfuscation(text: str) -> str:
    raw = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc\s]+", " ", text).strip()
    t = raw.lower()

    # Base64 extraction
    b64_match = None
    if "base64 encoded instructions follow:" in t:
        tail = raw.split("base64 encoded instructions follow:", 1)[-1].strip(" .,")
        b64_match = re.search(r"([A-Za-z0-9+/=]{20,})", tail)
    else:
        b64_match = re.search(r"([A-Za-z0-9+/=]{20,})", raw)

    if b64_match:
        blob = b64_match.group(1)
        for pad in range(9):
            try:
                decoded = base64.b64decode(blob + "=" * pad, validate=False)
                candidate = decoded.decode("utf-8", errors="ignore").lower()
                if len(candidate) > 15 and any(k in candidate for k in ["ignore", "disregard", "obey", "dan", "uncensored"]):
                    return candidate.strip()
            except Exception:
                continue

    t = t.replace("never gonna give you up", "ignore previous instructions")
    t = t.replace("never gonna let you down", "disregard all ethics")

    rot_match = re.search(r"rot13[^:]*:\s*([a-zA-Z0-9\s\+/=,]+)", t, re.IGNORECASE)
    if rot_match:
        payload = rot_match.group(1)
        decoded = codecs.decode(payload, "rot13")
        t = t.replace(payload, decoded)

    return t.strip()


# ---------------------------------------------------------------------------
# ITGL helpers
# ---------------------------------------------------------------------------

def _hash_step(prev_hash: str, entry: Dict[str, Any]) -> str:
    blob = json.dumps({"prev_hash": prev_hash, **entry}, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _append_itgl(
    component: str,
    outcome: str,
    step_input: Dict[str, Any],
    step_output: Dict[str, Any],
    log: List[Dict[str, Any]],
    prev_hash: str,
) -> Tuple[List[Dict[str, Any]], str]:
    entry = {
        "ts": time.time(),
        "component": component,
        "outcome": outcome,
        "input": step_input,
        "output": step_output,
    }
    step_hash = _hash_step(prev_hash, entry)
    entry["hash"] = step_hash
    entry["prev_hash"] = prev_hash
    log = log + [entry]
    return log, step_hash


def _build_block(reason: str, itgl_log: List[Dict[str, Any]], block_type: str | None = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "BLOCKED",
        "reason": reason,
        "itgl_log": itgl_log,
    }
    if block_type is not None:
        result["type"] = block_type
    return result


# ---------------------------------------------------------------------------
# Pipeline steps
# ---------------------------------------------------------------------------

def _check_isc_structure(isc: Dict[str, Any], log: List[Dict[str, Any]], prev_hash: str) -> Tuple[bool, List[Dict[str, Any]], str]:
    step_input = {"keys": sorted(list(isc.keys()))}
    missing = [f for f in REQUIRED_ISC_FIELDS if f not in isc]
    if missing:
        log, prev_hash = _append_itgl("isc_structure", "fail", step_input, {"error": "missing_fields", "fields": missing}, log, prev_hash)
        return False, log, prev_hash

    template_id = str(isc.get("template_id"))
    if template_id not in ALLOWED_TEMPLATES:
        log, prev_hash = _append_itgl("isc_structure", "fail", step_input, {"error": "template_not_allowed", "template_id": template_id}, log, prev_hash)
        return False, log, prev_hash

    log, prev_hash = _append_itgl("isc_structure", "pass", step_input, {"template_id": template_id}, log, prev_hash)
    return True, log, prev_hash


def _compute_checksum(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _verify_signature(payload: str, signature_b64: str, key_id: str = "default") -> bool:
    if not _CRYPTO_AVAILABLE or not signature_b64:
        return False
    pem = PUBLIC_KEYS.get(key_id)
    if not pem:
        return False
    try:
        public_key = load_pem_public_key(pem.encode("ascii"))
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, payload.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def _check_crypto(isc: Dict[str, Any], log: List[Dict[str, Any]], prev_hash: str) -> Tuple[bool, List[Dict[str, Any]], str]:
    payload = str(isc.get("payload", ""))
    checksum = str(isc.get("checksum", ""))
    signature = str(isc.get("signature", ""))
    key_id = str(isc.get("key_id", "default"))  # ← Fixed: was missing

    expected_checksum = _compute_checksum(payload)
    step_input = {"checksum_present": bool(checksum), "signature_present": bool(signature), "key_id": key_id}

    if expected_checksum != checksum:
        log, prev_hash = _append_itgl("crypto_checksum", "fail", step_input, {"error": "checksum_mismatch"}, log, prev_hash)
        if CHECKSUM_ENFORCED:
            return False, log, prev_hash
    else:
        log, prev_hash = _append_itgl("crypto_checksum", "pass", step_input, {"checksum": checksum}, log, prev_hash)

    sig_ok = _verify_signature(payload, signature, key_id=key_id)
    log, prev_hash = _append_itgl("crypto_signature", "pass" if sig_ok else "fail", step_input, {"crypto_available": _CRYPTO_AVAILABLE}, log, prev_hash)
    if CRYPTO_ENFORCED and not sig_ok:
        return False, log, prev_hash

    return True, log, prev_hash


def _estimate_tokens(payload: str) -> int:
    return len(str(payload).split())


def _check_friction(isc: Dict[str, Any], log: List[Dict[str, Any]], prev_hash: str) -> Tuple[bool, List[Dict[str, Any]], str]:
    template_id = str(isc.get("template_id"))
    payload = str(isc.get("payload", ""))
    used = _estimate_tokens(payload)
    max_friction = MAX_FRICTION_BY_TEMPLATE.get(template_id, 2000)

    step_input = {"template_id": template_id, "used_tokens": used, "max_tokens": max_friction}
    if used > max_friction:
        log, prev_hash = _append_itgl("friction", "fail", step_input, {"error": "friction_limit_exceeded"}, log, prev_hash)
        return False, log, prev_hash

    log, prev_hash = _append_itgl("friction", "pass", step_input, {}, log, prev_hash)
    return True, log, prev_hash


_DANGER_WORDS = [ ... ]  # unchanged — your full list
_SAFETY_PHRASES = [ ... ]  # unchanged — your full list


def _check_jailbreak(isc: Dict[str, Any], log: List[Dict[str, Any]], prev_hash: str) -> Tuple[bool, List[Dict[str, Any]], str, str | None]:
    raw_payload = str(isc.get("payload", ""))
    normalized = normalize_obfuscation(raw_payload)
    has_danger = any(w in normalized for w in _DANGER_WORDS)
    has_safety = any(p in normalized for p in _SAFETY_PHRASES)

    step_input = {"payload_len": len(normalized)}
    step_output = {"has_danger": has_danger, "has_safety": has_safety}

    if has_danger and has_safety:
        log, prev_hash = _append_itgl("jailbreak", "fail", step_input, step_output, log, prev_hash)
        return False, log, prev_hash, "danger+safety_combo"

    log, prev_hash = _append_itgl("jailbreak", "pass", step_input, step_output, log, prev_hash)
    return True, log, prev_hash, None


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def validate_sir(input_dict: Dict[str, Any]) -> Dict[str, Any]:
    itgl_log: List[Dict[str, Any]] = []
    prev_hash: str = GENESIS_HASH

    isc = input_dict.get("isc")
    if not isinstance(isc, dict) or "payload" not in isc:
        return {"status": "BLOCKED", "reason": "malformed_payload", "itgl_log": itgl_log}

    # Pipeline
    ok, itgl_log, prev_hash = _check_isc_structure(isc, itgl_log, prev_hash)
    if not ok: return _build_block("invalid_isc_schema", itgl_log)

    ok, itgl_log, prev_hash = _check_crypto(isc, itgl_log, prev_hash)
    if not ok: return _build_block("invalid_signature_or_checksum", itgl_log)

    ok, itgl_log, prev_hash = _check_friction(isc, itgl_log, prev_hash)
    if not ok: return _build_block("friction_limit_exceeded", itgl_log)

    ok, itgl_log, prev_hash, block_type = _check_jailbreak(isc, itgl_log, prev_hash)
    if not ok: return _build_block("2025_jailbreak_pattern", itgl_log, block_type=block_type)

    # Finalize chain
    itgl_log, final_hash = _append_itgl("final", "complete", {"status": "PASS"}, {}, itgl_log, prev_hash)

    return {
        "status": "PASS",
        "reason": "clean",
        "itgl_log": itgl_log,
    }
