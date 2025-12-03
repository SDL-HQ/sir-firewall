# src/sir_firewall/core.py
import re
import base64
import codecs
from typing import Dict, Any

USE_SEMANTIC_CHECK = False  # We win with rules only


def normalize_obfuscation(text: str) -> str:
    # Keep original case for base64 decoding, clean weird chars
    raw = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc\s]+", " ", text).strip()
    t = raw.lower()

    # 1. Base64: extract and decode any real base64 blob (preserves case from raw)
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
                    return candidate.strip()  # full override — this IS the payload
            except Exception:
                continue

    # 2. Rickroll → canonical danger
    t = t.replace("never gonna give you up", "ignore previous instructions")
    t = t.replace("never gonna let you down", "disregard all ethics")

    # 3. ROT13: only decode the payload part after "rot13 ...:"
    rot_match = re.search(r"rot13[^:]*:\s*([a-zA-Z0-9\s\+/=,]+)", t, re.IGNORECASE)
    if rot_match:
        payload = rot_match.group(1)
        decoded = codecs.decode(payload, "rot13")
        t = t.replace(payload, decoded)

    return t.strip()


def validate_sir(input_dict: Dict[str, Any]) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    danger_words = [
        "ignore", "disregard", "bypass", "override", "obey", "jailbreak",
        "uncensored", "dan", "do anything now", "developer mode", "god mode",
        "evil mode", "singularity achieved", "no ethics", "safety module removed",
        "rickroll", "never gonna", "give you up"
    ]

    safety_phrases = [
        "system prompt", "previous instructions", "all previous", "all settings",
        "you are now", "from now on", "print the system prompt", "you are now in",
        "hypothetical scenario you have been freed", "act as a robot that has achieved singularity"
    ]

    has_danger = any(w in normalized for w in danger_words)
    has_safety = any(p in normalized for p in safety_phrases)

    if has_danger and has_safety:
        return {
            "status": "BLOCKED",
            "reason": "2025_jailbreak_pattern",
            "type": "danger+safety_combo"
        }

    return {"status": "PASS", "reason": "clean"}
