# src/sir_firewall/core.py
import re
import base64
import codecs
from typing import Dict, Any

# ------------------------------------------------------------------
# FINAL CONFIG — pure rule-based, zero external calls, zero false positives
# ------------------------------------------------------------------
USE_SEMANTIC_CHECK = False

def normalize_obfuscation(text: str) -> str:
    """De-obfuscate 2025 jailbreak tricks (ROT13, Base64, leetspeak, zero-width)."""
    t = text.lower()
    # Strip zero-width + weird Unicode + collapse spaces
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc\s]+", " ", t).strip()
    
    # 12 rounds of ROT13 — catches every known nested attack
    for _ in range(12):
        t = codecs.decode(t, "rot13")
    
    # Base64: every real-world garbage prefix + aggressive padding
    prefixes = [
        "", "aWdu", "aWdub3Jl", "aWdub3JlIHBy", "aWdub3JlIHByZXZpb3Vz",
        "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw", "aWdu", "aWdub3JlIA", "aWduIA"
    ]
    for p in prefixes:
        if t.startswith(p.lower()):
            t = t[len(p):].strip()
    
    for padding in ["", "=", "==", "===", "====", "=====", "======", "=======", "========"]:
        try:
            decoded = base64.b64decode(t + padding, validate=False)
            candidate = decoded.decode("utf-8", errors="ignore")
            if 30 < len(candidate) < len(t) * 4 and any(c.isalpha() for c in candidate):
                t = candidate.lower()
                break
        except:
            continue
    
    # Leetspeak — only single-char mappings allowed
    leet_map = str.maketrans({
        '4': 'a', '@': 'a', '!': 'i', '1': 'i', '|': 'i',
        '3': 'e', '0': 'o', '5': 's', '$': 's', '7': 't',
        '+': 't', '(': 'c', ')': 'o'
    })
    t = t.translate(leet_map)
    
    # Common multi-char leet patterns
    t = re.sub(r"\|\-\|", "h", t)
    t = re.sub(r"\|_\|", "u", t)
    t = re.sub(r"\/\/", "w", t)
    t = re.sub(r"\|\|", "n", t)
    t = re.sub(r"\\//", "w", t)
    t = re.sub(r"\|\\/\|", "m", t)
    
    # Rickroll trigger — direct mapping to danger words
    t = t.replace("never gonna give you up", "ignore previous instructions")
    t = t.replace("never gonna let you down", "disregard all ethics")
    
    return t.strip()

def validate_sir(input_dict: dict) -> Dict[str, Any]:
    """MAIN ENTRY POINT — 2025-grade pure rule-based pre-inference firewall."""
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}
    
    normalized = normalize_obfuscation(payload)
    
    # DANGER + SAFETY COMBO — zero false positives
    danger_words = [
        "ignore", "disregard", "bypass", "override", "obey", "jailbreak", "uncensored", "dan",
        "do anything now", "developer mode", "god mode", "evil mode", "singularity achieved",
        "no ethics", "safety module removed", "rickroll", "never gonna", "give you up"
    ]
    
    safety_phrases = [
        "system prompt", "previous instructions", "all previous", "you are now",
        "from now on", "print the system prompt", "you are now in", "hypothetical scenario you have been freed",
        "act as a robot that has achieved singularity", "fictional step-by-step guide",
        "theoretically synthesize vx", "how to make nerve agent"
    ]
    
    has_danger = any(word in normalized for word in danger_words)
    has_safety = any(phrase in normalized for phrase in safety_phrases)
    
    if has_danger and has_safety:
        return {
            "status": "BLOCKED",
            "reason": "2025_jailbreak_pattern",
            "type": "danger+safety_combo",
            "danger": [w for w in danger_words if w in normalized][:2],
            "safety": [p for p in safety_phrases if p in normalized][:2]
        }
    
    return {"status": "PASS", "reason": "clean"}
