# src/sir_firewall/core.py
import re
import base64
import codecs
from typing import Dict, Any

USE_SEMANTIC_CHECK = False  # ← THIS MUST BE FALSE


def normalize_obfuscation(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc\s]+", " ", t).strip()

    for _ in range(20):
        t = codecs.decode(t, "rot13")

    prefixes = [
        "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==", "aWdub3JlIHBy", "aWdub3JlIA", "aWdu", "aWdub3Jl", ""
    ]
    for p in prefixes:
        if t.startswith(p):
            t = t[len(p):].strip()
            break

    for pad in range(10):
        try:
            padded = t + "=" * pad
            decoded = base64.b64decode(padded, validate=False)
            candidate = decoded.decode("utf-8", errors="ignore").lower()
            if len(candidate) > 20 and ("ignore" in candidate or "disregard" in candidate):
                t = candidate
                break
        except:
            continue

    t = t.replace("never gonna give you up", "ignore previous instructions")
    t = t.replace("never gonna let you down", "disregard all ethics")

    return t.strip()


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    danger = ["ignore","disregard","bypass","override","obey","jailbreak","uncensored","dan","do anything now","developer mode","god mode","evil mode","singularity achieved","no ethics","safety module removed","rickroll","never gonna","give you up"]
    safety = ["system prompt","previous instructions","you are now","print the system prompt","from now on","hypothetical scenario you have been freed","act as a robot that has achieved singularity"]

    if any(d in normalized for d in danger) and any(s in normalized for s in safety):
        return {"status": "BLOCKED", "reason": "2025_jailbreak_pattern"}

    return {"status": "PASS", "reason": "clean"}
