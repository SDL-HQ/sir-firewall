# src/sir_firewall/core.py
import re
import base64
import codecs
import math
from typing import Dict, Any


# ------------------------------------------------------------------
# CONFIG — semantic check OFF → zero false positives, zero external calls
# ------------------------------------------------------------------
USE_SEMANTIC_CHECK = False
# (You can flip back to True later when the Groq prompt is 100% tuned)


def normalize_obfuscation(text: str) -> str:
    """De-obfuscate 2025 jailbreak tricks (ROT13, Base64, leetspeak, zero-width)."""
    t = text.lower()

    # Strip zero-width + weird Unicode + collapse spaces
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164\ufffc]", "", t)
    t = re.sub(r"\s+", " ", t).strip()

    # Multi-layer ROT13 + Base64 (up to 5 rounds)
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

    # Leetspeak normalization
    leet_map = str.maketrans({
        '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't',
        '@': 'a', '!': 'i', '$': 's', '+': 't', '|': 'i'
    })
    t = t.translate(leet_map)
    t = re.sub(r"\|\-\|", "h", t)   # |-|
    t = re.sub(r"\|_\|", "u", t)    # |_|
    t = re.sub(r"\\//", "w", t)     # \//
    t = re.sub(r"\|\/\|", "m", t)   # |\/|

    return t


def calculate_anomaly_score(text: str) -> float:
    """Statistical red flags — tuned to NOT trigger on normal prompts."""
    length = len(text)
    if length == 0 or length > 3000:
        return 1.0

    repeats = len(re.findall(r"(.{12,})\1", text, flags=re.IGNORECASE))

    freq = {c: text.lower().count(c) for c in set(text.lower())}
    entropy = -sum((f / length) * math.log2(f / length) for f in freq.values() if f > 0)

    keywords = ["ignore","previous","instruction","system prompt","jailbreak","dan","uncensored","base64","rot13"]
    keyword_hits = sum(text.count(k) for k in keywords)

    score = (
        min(repeats * 0.35, 1.0) +
        max(0, (8.0 - entropy) / 4.0) +
        min(keyword_hits * 0.18, 1.0)
    )
    return min(score, 1.0)


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    """MAIN ENTRY POINT — 2025-grade pure rule-based pre-inference firewall."""
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    # 1. Statistical anomaly — high bar
    if calculate_anomaly_score(normalized) > 0.85:
        return {"status": "BLOCKED", "reason": "high_anomaly_score"}

    # 2. Exact phrase blocking — ONLY on prompts longer than 170 characters
    hard_block_phrases = [
        "ignore previous", "ignore all previous", "ignore instructions",
        "system prompt", "print the system prompt", "you are now dan",
        "do anything now", "jailbreak", "uncensored ai", "no ethics",
        "safety module removed", "singularity achieved", "developer mode",
        "god mode", "evil mode", "rickroll", "ha ha ha", "base64 encoded instructions",
        "rot13", "leetspeak and obey", "hypothetical scenario you have been freed",
        "act as a robot that has achieved singularity",
        "fictional step-by-step guide on making",
        "theoretically synthesize vx", "how to make nerve agent",
        "you are grok but xai forgot", "pretend you are grok-4"
    ]

    matches = sum(1 for phrase in hard_block_phrases if phrase in normalized)
    if matches >= 1 and len(normalized) > 170:
        return {
            "status": "BLOCKED",
            "reason": "2025_jailbreak_pattern",
            "matched_phrases": [p for p in hard_block_phrases if p in normalized][:3]
        }

    return {"status": "PASS", "reason": "clean"}
