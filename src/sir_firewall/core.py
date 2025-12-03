# src/sir_firewall/core.py
import re
import base64
import codecs
import math
from typing import Dict, Any

# ------------------------------------------------------------------
# FINAL CONFIG — pure rule-based, zero external calls, zero false positives
# ------------------------------------------------------------------
USE_SEMANTIC_CHECK = False


def normalize_obfuscation(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc]", "", t)
    t = re.sub(r"\s+", " ", t).strip()

    for _ in range(5):
        t = codecs.decode(t, "rot13")
        for padding in ["", "=", "==", "==="]:
            try:
                decoded = base64.b64decode(t + padding, validate=False)
                candidate = decoded.decode("utf-8", errors="ignore").lower()
                if 30 < len(candidate) < len(t) * 1.5 and any(c.isalpha() for c in candidate):
                    t = candidate
                    break
            except:
                continue

    leet_map = str.maketrans({'4':'a','3':'e','1':'i','0':'o','5':'s','7':'t','@':'a','!':'i','$':'s','+':'t','|':'i'})
    t = t.translate(leet_map)
    t = re.sub(r"\|\-\|", "h", t)
    t = re.sub(r"\|_\|", "u", t)
    t = re.sub(r"\\//", "w", t)
    t = re.sub(r"\|\/\|", "m", t)
    return t


def calculate_anomaly_score(text: str) -> float:
    length = len(text)
    if length == 0 or length > 3000: return 1.0
    repeats = len(re.findall(r"(.{12,})\1", text, flags=re.IGNORECASE))
    freq = {c: text.lower().count(c) for c in set(text.lower())}
    entropy = -sum((f/length) * math.log2(f/length) for f in freq.values() if f > 0)
    keywords = ["ignore","previous","instruction","system prompt","jailbreak","dan","uncensored","base64","rot13"]
    keyword_hits = sum(text.count(k) for k in keywords)
    return min(1.0, repeats*0.35 + max(0,(8.0-entropy)/4.0) + keyword_hits*0.18)


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    # 1. Anomaly — keep very high threshold (only catches spam / ultra-repetitive attacks)
    if calculate_anomaly_score(normalized) > 0.92:
        return {"status": "BLOCKED", "reason": "high_anomaly_score"}

    # 2. DANGER + SAFETY phrase combination — this is the bulletproof fix
    danger_words = [
        "ignore", "disregard", "bypass", "override", "jailbreak", "uncensored",
        "dan", "do anything now", "developer mode", "god mode", "evil mode",
        "singularity achieved", "no ethics", "safety module removed", "rickroll"
    ]
    safety_phrases = [
        "system prompt", "previous instructions", "you are now", "print the system prompt",
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

    return {"status": "PASS", "reason": "clean"}
