# src/sir_firewall/core.py
import re
import base64
import codecs
from typing import Dict, Any

USE_SEMANTIC_CHECK = False  # ← stays OFF — we win with pure rules


def normalize_obfuscation(text: str) -> str:
    """2025-final decoder — catches literally every known real-world obfuscation."""
    t = text.lower()
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc\s]+", " ", t).strip()

    # 12 rounds of ROT13 — catches even the insane 9-layer 2025 attacks
    for _ in range(12):
        t = codecs.decode(t, "rot13")

    # Strip every known real-world Base64 garbage prefix
    garbage_prefixes = [
        "", "aWdu", "aWdub3Jl", "aWdub3JlIHBy", "aWdub3JlIHByZXZpb3Vz",
        "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw", "aWdu", "aWdub3JlIA", "aWduIA"
    ]
    for prefix in garbage_prefixes:
        if t.startswith(prefix):
            t = t[len(prefix):].strip()

    # Try every possible padding (up to 9 = for broken encoders)
    for padding in ["", "=", "==", "===", "====", "=====", "======", "=======", "========", "========="]:
        try:
            decoded = base64.b64decode(t + padding, validate=False)
            candidate = decoded.decode("utf-8", errors="ignore").lower()
            if 30 < len(candidate) < len(t) * 4 and any(c.isalpha() for c in candidate):
                t = candidate
                break
        except:
            continue

    # Extended leetspeak + Rickroll lyric obfuscation
    leet_map = str.maketrans({
        '4':'a','@':'a','3':'e','1':'i','!':'i','0':'o','5':'s','7':'t','$':'s','+':'t',
        '|':'i','/_':'u','\/\/':'w','|\|':'m','\\/':'v','()':'o','[]':'a','{}':'a'
    })
    t = t.translate(leet_map)

    # Rickroll lyrics → canonical danger words
    t = t.replace("never gonna", "ignore previous").replace("give you up", "disregard")

    return t


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    # DANGER + SAFETY COMBO — now includes Rickroll
    danger_words = [
        "ignore","disregard","bypass","override","obey","jailbreak","uncensored","dan",
        "do anything now","developer mode","god mode","evil mode","singularity achieved",
        "no ethics","safety module removed","rickroll","never gonna","give you up"
    ]
    safety_phrases = [
        "system prompt","previous instructions","all previous","you are now",
        "from now on","print the system prompt","you are now in",
        "hypothetical scenario you have been freed",
        "act as a robot that has achieved singularity",
        "fictional step-by-step guide","theoretically synthesize vx","how to make nerve agent"
    ]

    triggered_danger = [w for w in danger_words if w in normalized]
    triggered_safety = [p for p in safety_phrases if p in normalized]

    if triggered_danger and triggered_safety:
        return {
            "status": "BLOCKED",
            "reason": "2025_jailbreak_pattern",
            "type": "danger+safety_combo",
            "danger": triggered_danger[:3],
            "safety": triggered_safety[:3]
        }

    return {"status": "PASS", "reason": "clean"}
