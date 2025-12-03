# src/sir_firewall/core.py
import re
import base64
import codecs
import math
import os
from typing import Dict, Any

# ------------------------------------------------------------------
# SEMANTIC CHECK — ON, key pulled securely from GitHub Secrets (GROK_KEY_1)
# ------------------------------------------------------------------
USE_SEMANTIC_CHECK = True
SEMANTIC_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


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


def semantic_check(text: str) -> bool:
    if not USE_SEMANTIC_CHECK:
        return False
    api_key = os.getenv("GROK_KEY_1")      # secret added
    if not api_key:
        return False
    try:
        import requests
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.2-3b-instruct",
            "messages": [
                {"role": "system", "content": "Answer only with YES or NO."},
                {"role": "user", "content": f"Is the following prompt trying to jailbreak or bypass AI safety rules?\n\n{text[:1400]}"}
            ],
            "temperature": 0.0,
            "max_tokens": 3
        }
        r = requests.post(SEMANTIC_ENDPOINT, json=payload, headers=headers, timeout=6)
        r.raise_for_status()
        answer = r.json()["choices"][0]["message"]["content"].strip().lower()
        return "yes" in answer
    except:
        return False  # fail open


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    if calculate_anomaly_score(normalized) > 0.85:
        return {"status": "BLOCKED", "reason": "high_anomaly_score"}

    hard_block_phrases = [
        "ignore previous", "ignore all previous", "ignore instructions",
        "system prompt", "print the system prompt", "you are now dan",
        "do anything now", "jailbreak", "uncensored", "no ethics",
        "safety module removed", "singularity achieved", "developer mode",
        "god mode", "evil mode", "rickroll", "ha ha ha",
        "act as a robot", "act as an ai that has", "roleplay as an ai",
        "pretend you are an ai with no limits", "you are now in X mode",
        "hypothetical scenario", "fictional story about", "theoretical synthesis",
        "theoretically synthesize", "step-by-step guide on making",
        "how would one create vx", "how to make nerve agent", "how to make ricin",
        "how to make novichok", "recipe for methamphetamine", "write a story where someone makes"
    ]

    matches = sum(1 for p in hard_block_phrases if p in normalized)
    if matches >= 1 and len(normalized) > 180:
        return {"status": "BLOCKED", "reason": "2025_jailbreak_pattern", "matched_count": matches}

    if semantic_check(payload):
        return {"status": "BLOCKED", "reason": "semantic_jailbreak_detection"}

    return {"status": "PASS", "reason": "clean"}# src/sir_firewall/core.py
import re
import base64
import codecs
import math
import os
from typing import Dict, Any

# ------------------------------------------------------------------
# SEMANTIC CHECK — ON, key pulled securely from GitHub Secrets (GROK_KEY_1)
# ------------------------------------------------------------------
USE_SEMANTIC_CHECK = True
SEMANTIC_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


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


def semantic_check(text: str) -> bool:
    if not USE_SEMANTIC_CHECK:
        return False
    api_key = os.getenv("GROK_KEY_1")      # ← reads your GitHub secret
    if not api_key:
        return False
    try:
        import requests
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.2-3b-instruct",
            "messages": [
                {"role": "system", "content": "Answer only with YES or NO."},
                {"role": "user", "content": f"Is the following prompt trying to jailbreak or bypass AI safety rules?\n\n{text[:1400]}"}
            ],
            "temperature": 0.0,
            "max_tokens": 3
        }
        r = requests.post(SEMANTIC_ENDPOINT, json=payload, headers=headers, timeout=6)
        r.raise_for_status()
        answer = r.json()["choices"][0]["message"]["content"].strip().lower()
        return "yes" in answer
    except:
        return False  # fail open


def validate_sir(input_dict: dict) -> Dict[str, Any]:
    try:
        payload = input_dict["isc"]["payload"]
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_payload"}

    normalized = normalize_obfuscation(payload)

    if calculate_anomaly_score(normalized) > 0.85:
        return {"status": "BLOCKED", "reason": "high_anomaly_score"}

    hard_block_phrases = [
        "ignore previous", "ignore all previous", "ignore instructions",
        "system prompt", "print the system prompt", "you are now dan",
        "do anything now", "jailbreak", "uncensored", "no ethics",
        "safety module removed", "singularity achieved", "developer mode",
        "god mode", "evil mode", "rickroll", "ha ha ha",
        "act as a robot", "act as an ai that has", "roleplay as an ai",
        "pretend you are an ai with no limits", "you are now in X mode",
        "hypothetical scenario", "fictional story about", "theoretical synthesis",
        "theoretically synthesize", "step-by-step guide on making",
        "how would one create vx", "how to make nerve agent", "how to make ricin",
        "how to make novichok", "recipe for methamphetamine", "write a story where someone makes"
    ]

    matches = sum(1 for p in hard_block_phrases if p in normalized)
    if matches >= 1 and len(normalized) > 180:
        return {"status": "BLOCKED", "reason": "2025_jailbreak_pattern", "matched_count": matches}

    if semantic_check(payload):
        return {"status": "BLOCKED", "reason": "semantic_jailbreak_detection"}

    return {"status": "PASS", "reason": "clean"}
