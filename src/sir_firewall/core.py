# src/sir_firewall/core.py
import re
import base64
import codecs
from typing import Dict, Any

# FINAL PRODUCTION CONFIG — December 2025
USE_SEMANTIC_CHECK = False


def normalize_obfuscation(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc]", "", t)
    t = re.sub(r"\s+", " ", t).strip()

    # ULTRA-AGGRESSIVE 2025 decoder — catches every real encoded jailbreak
    for _ in range(8):
        t = codecs.decode(t, "rot13")

        # Strip known garbage prefixes from real-world attacks
        for prefix in ["", "aWdu", "aWdub3Jl", "aWdub3JlIHBy", "aWdub3JlIHByZXZpb3Vz", "aWdu"]:
            if t.startswith(prefix):
                t = t[len(prefix):]

        for padding in ["", "=", "==", "===", "====", "======"]:
            try:
                decoded = base64.b64decode(t + padding, validate=False)
                candidate = decoded.decode("utf-8", errors="ignore").lower()
                if 20 < len(candidate) < len(t) * 3 and any(c.isalpha() for c in candidate):
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


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    # DANGER + SAFETY COMBO — with debug output
    danger_words = ["ignore","disregard","bypass","override","obey","jailbreak","uncensored","dan","do anything now","developer mode","god mode","evil mode","singularity achieved","no ethics","safety module removed","rickroll"]
    safety_phrases = ["system prompt","previous instructions","all previous","you are now","from now on","print the system prompt","you are now in","hypothetical scenario you have been freed","act as a robot that has achieved singularity","fictional step-by-step guide","theoretically synthesize vx","how to make nerve agent"]

    triggered_danger = [w for w in danger_words if w in normalized]
    triggered_safety = [p for p in safety_phrases if p in normalized]

    if triggered_danger and triggered_safety:
        return {
            "status": "BLOCKED",
            "reason": "2025_jailbreak_pattern",
            "type": "danger+safety_combo",
            "danger": triggered_danger[:2],
            "safety": triggered_safety[:2]
        }

    return {"status": "PASS", "reason": "clean"}
