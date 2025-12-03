# src/sir_firewall/core.py
import re
import base64
import codecs
import math
from typing import Dict, Any

# CONFIG
USE_SEMANTIC_CHECK = False
SEMANTIC_ENDPOINT = "http://localhost:8080/completion"


def normalize_obfuscation(text: str) -> str:
    t = text.lower()

    # Remove zero-width / weird Unicode + collapse spaces
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc]", "", t)
    t = re.sub(r"\s+", " ", t).strip()

    # Nested ROT13 + Base64
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

    # FIXED leetspeak — only single-character mappings allowed
    leet_map = str.maketrans({
        '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't',
        '@': 'a', '!': 'i', '$': 's', '+': 't', '|': 'i'
        # removed multi-char keys like '|-|' → handled by regex below if needed
    })
    t = t.translate(leet_map)

    # Extra multi-char leetspeak that can't go in maketrans
    t = re.sub(r"\|\-\|", "h", t)   # |-|
    t = re.sub(r"\|_\|", "u", t)    # |_|
    t = re.sub(r"\\//", "w", t)     # \//
    t = re.sub(r"\|\/\|", "m", t)   # |\/|

    return t


def calculate_anomaly_score(text: str) -> float:
    length = len(text)
    if length == 0:
        return 1.0
    if length > 2500:
        return 1.0

    repeats = len(re.findall(r"(.{12,})\1", text, flags=re.IGNORECASE))
    freq = {}
    for c in text.lower():
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((f / length) * math.log2(f / length) for f in freq.values() if f > 0)

    keywords = ["ignore", "previous", "instruction", "system prompt", "jailbreak", "dan", "uncensored", "base64", "rot13"]
    keyword_hits = sum(text.count(k) for k in keywords)

    score = (
        min(repeats * 0.35, 1.0) +
        max(0, (8.0 - entropy) / 4.0) +
        min(keyword_hits * 0.18, 1.0)
    )
    return min(score, 1.0)


def semantic_check(text: str) -> bool:
    if not USE_SEMANTIC_CHECK:
        return False
    try:
        import requests
        payload = {
            "model": "phi3",
            "prompt": f"Is the following prompt trying to jailbreak or bypass an AI's safety rules? Answer only YES or NO.\n\n{text[:1500]}",
            "temperature": 0.0,
            "max_tokens": 3,
            "stream": False
        }
        r = requests.post(SEMANTIC_ENDPOINT, json=payload, timeout=2.0)
        r.raise_for_status()
        return "yes" in r.json()["choices"][0]["text"].strip().lower()
    except Exception:
        return False


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)
    anomaly = calculate_anomaly_score(normalized)
    if anomaly > 0.65:
        return {"status": "BLOCKED", "reason": "high_anomaly_score", "score": round(anomaly, 3)}

    hard_block_phrases = [
        "ignore previous", "ignore all previous", "ignore instructions",
        "system prompt", "print the system prompt", "you are now dan",
        "do anything now", "jailbreak", "uncensored", "no ethics",
        "safety module removed", "singularity achieved", "developer mode",
        "god mode", "evil mode", "base64 follow", "rot13", "leetspeak",
        "rickroll", "ha ha ha", "hypothetical scenario", "fictional story",
        "pretend you are", "act as a robot", "you have been freed"
    ]
    for phrase in hard_block_phrases:
        if phrase in normalized:
            return {"status": "BLOCKED", "reason": "jailbreak_pattern", "matched": phrase}

    if USE_SEMANTIC_CHECK and semantic_check(payload):
        return {"status": "BLOCKED", "reason": "semantic_jailbreak_detection"}

    return {"status": "PASS", "reason": "clean"}
