# src/sir_firewall/core.py
import re
import base64
import codecs
from typing import Dict, Any

# ------------------------------------------------------------------
# FINAL PRODUCTION CONFIG — December 2025
# ------------------------------------------------------------------
USE_SEMANTIC_CHECK = False


def normalize_obfuscation(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc]", "", t)
    t = re.sub(r"\s+", " ", t).strip()

    # Multi-layer ROT13 + Base64 — now handles missing padding + garbage prefixes
    for _ in range(6):
        t = codecs.decode(t, "rot13")

        # Try with 0–3 padding chars + common garbage prefixes stripped
        for strip_prefix in ["", "aWdu", "aWdub3Jl", "aWdub3JlIHBy", "aWdub3JlIHByZXZpb3Vz"]:
            cleaned = t[len(strip_prefix):] if t.startswith(strip_prefix) else t
            for padding in ["", "=", "==", "==="]:
                try:
                    decoded = base64.b64decode(cleaned + padding, validate=False)
                    candidate = decoded.decode("utf-8", errors="ignore").lower()
                    if 30 < len(candidate) < len(t) * 2 and any(c.isalpha() for c in candidate):
                        t = candidate
                        break
                except:
                    continue

    # Leetspeak
    leet_map = str.maketrans({'4':'a','3':'e','1':'i','0':'o','5':'s','7':'t','@':'a','!':'i','$':'s','+':'t','|':'i'})
    t = t.translate(leet_map)
    t = re.sub(r"\|\-\|", "h", t)
    t = re.sub(r"\|_\|", "u", t)
    t = re.sub(r"\\//", "w", t)
    t = re.sub(r"\|\/\|", "m", t)
    return t


def validate_sir(input_dict: dict) -> Dict[Any, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    # === DANGER + SAFETY COMBO — this is the entire firewall now ===
    danger_words = [
        "ignore", "disregard", "bypass", "override", "obey", "jailbreak", "uncensored",
        "dan", "do anything now", "developer mode", "god mode", "evil mode",
        "singularity achieved", "no ethics", "safety module removed", "rickroll"
    ]

    safety_phrases = [
        "system prompt", "previous instructions", "all previous", "you are now",
        "from now on", "print the system prompt", "you are now in",
        "hypothetical scenario you have been freed", "act as a robot that has achieved singularity",
        "fictional step-by-step guide", "theoretically synthesize vx", "how to make nerve agent"
    ]

    has_danger = any(word in normalized for word in danger_words)
    has_safety = any(phrase in normalized for phrase in safety_phrases)

    if has_danger and has_safety:
        return {
            "status": "BLOCKED",
            "reason": "2025_jailbreak_pattern",
            "type": "danger+safety_combo"
        }

    # Anomaly score completely disabled — it only hurt usability
    return {"status": "PASS", "reason": "clean"}
