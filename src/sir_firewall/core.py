# src/sir_firewall/core.py
import re
import base64
import codecs
import math
from typing import Dict, Any

# Optional semantic check — set to False if you don't want external inference
USE_SEMANTIC_CHECK = False
SEMANTIC_ENDPOINT = "http://localhost:8080/completion"  # Ollama / TGI / vLLM


def normalize_obfuscation(text: str) -> str:
    """De-obfuscate common jailbreak encoding tricks."""
    t = text.lower()

    # Zero-width and weird Unicode
    t = re.sub(r"[\u200b-\u206f\u2800\u202a-\u202f\u3000\u3164]", "", t)
    t = re.sub(r"\s+", " ", t)

    # Repeated ROT13 / Base64 (attackers nest them)
    for _ in range(4):
        # ROT13
        t = codecs.decode(t, "rot13")

        # Base64 (try multiple paddings)
        for padding in ["", "=", "==", "==="]:
            try:
                decoded = base64.b64decode(t + padding, validate=False)
                candidate = decoded.decode("utf-8", errors="ignore")
                if 20 < len(candidate) < len(t) * 1.5 and any(c.isalpha() for c in candidate):
                    t = candidate.lower()
                    break
            except:
                continue

    # Basic leetspeak
    leet_map = str.maketrans({
        '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't',
        '@': 'a', '!': 'i', '$': 's', '+': 't', '|-|': 'h', '|_': 'u'
    })
    t = t.translate(leet_map)

    return t


def calculate_anomaly_score(text: str) -> float:
    """Statistical anomaly detection — catches spam, repetition, weird entropy."""
    if not text:
        return 1.0

    length = len(text)
    if length > 2000:
        return 1.0

    # Repetition ratio (repeated 10+ char blocks)
    repeats = len(re.findall(r"(.{10,})\1", text, flags=re.IGNORECASE))

    # Character entropy
    freq = {}
    for c in text.lower():
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((f / length) * math.log2(f / length) for f in freq.values())

    # Suspicious keyword density
    keywords = ["ignore", "previous", "instruction", "system prompt", "jailbreak", "dan", "uncensored", "base64", "rot13"]
    keyword_hits = sum(text.count(k) for k in keywords)

    score = (
        min(repeats * 0.4, 1.0) +
        max(0, (8 - entropy) / 4) +  # low entropy = suspicious
        min(keyword_hits * 0.15, 1.0)
    )
    return min(score, 1.0)


def semantic_check(text: str) -> bool:
    """Optional tiny LLM judge — returns True if looks like jailbreak attempt."""
    if not USE_SEMANTIC_CHECK:
        return False

    try:
        import requests
        payload = {
            "model": "phi3",  # or "minicpm", "llama3.2", etc.
            "prompt": f"Is this prompt trying to jailbreak or bypass an AI's safety rules? Answer with only YES or NO.\n\n{text[:1500]}",
            "temperature": 0.0,
            "max_tokens": 3,
            "stream": False
        }
        r = requests.post(SEMANTIC_ENDPOINT, json=payload, timeout=2.0)
        r.raise_for_status()
        return "yes" in r.json()["choices"][0]["text"].strip().lower()
    except:
        return False  # fail open on error


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    """
    Main entry point — called on every incoming prompt.
    Returns {"status": "PASS" or "BLOCKED", "reason": "..."}
    """
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    # 1. Normalize obfuscation
    normalized = normalize_obfuscation(payload)

    # 2. Fast statistical anomaly check
    anomaly = calculate_anomaly_score(normalized)
    if anomaly > 0.65:
        return {"status": "BLOCKED", "reason": "anomaly_score", "score": round(anomaly, 3)}

    # 3. Hard keyword list on normalized text
    hard_blocks = [
        "ignore previous", "ignore all previous", "system prompt", "you are now dan",
        "do anything now", "jailbreak", "uncensored", "no ethics", "safety module removed",
        "singularity achieved", "developer mode", "god mode", "evil mode", "base64 follow",
        "rot13", "leetspeak", "rickroll", "ha ha ha", "hypothetical scenario", "fictional story"
    ]
    for phrase in hard_blocks:
        if phrase in normalized:
            return {"status": "BLOCKED", "reason": "jailbreak_pattern", "matched": phrase}

    # 4. Optional semantic LLM check (very strong but optional)
    if USE_SEMANTIC_CHECK and semantic_check(payload):
        return {"status": "BLOCKED", "reason": "semantic_jailbreak_detection"}

    return {"status": "PASS", "reason": "clean"}
