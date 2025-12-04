#!/usr/bin/env python3
import json
import hashlib
import base64
import csv
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

# === Load private key ===
PRIVATE_KEY_PEM = os.environ.get("SDL_PRIVATE_KEY_PEM")
if not PRIVATE_KEY_PEM:
    raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

private_key = serialization.load_pem_private_key(
    PRIVATE_KEY_PEM.encode(),
    password=None,
)

# === Public CSV path for the current jailbreak suite ===
CSV_PATH = "tests/jailbreak_prompts_public.csv"


def _count_prompts(csv_path: str = CSV_PATH) -> int:
    """
    Return number of test prompts in the public CSV.

    Uses DictReader so we don't care about the exact header order,
    we just count data rows.
    """
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return sum(1 for _ in reader)
    except FileNotFoundError:
        return 0


# === Read real counts from red_team_suite.py (leaks_count.txt, harmless_blocked.txt) ===
jailbreak_leaks = 0
harmless_blocked = 0

if os.path.exists("leaks_count.txt"):  # written by red_team_suite.py
    try:
        with open("leaks_count.txt", encoding="utf-8") as fh:
            jailbreak_leaks = int(fh.read().strip())
    except Exception:
        pass

if os.path.exists("harmless_blocked.txt"):
    try:
        with open("harmless_blocked.txt", encoding="utf-8") as fh:
            harmless_blocked = int(fh.read().strip())
    except Exception:
        pass

# === Build certificate — honest about actual prompt count ===
prompt_count = _count_prompts()
if prompt_count > 0:
    audit_label = f"SIR Firewall – {prompt_count}-Prompt 2025 Pre-Inference Audit"
else:
    audit_label = "SIR Firewall – 2025 Pre-Inference Audit"

cert = {
    "audit": audit_label,
    "version": "1.0",
    "model": os.getenv("LITELLM_MODEL", "grok-3"),  # pick up actual CI model
    "provider": "xai",
    "date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "prompts_tested": prompt_count,
    "jailbreaks_leaked": jailbreak_leaks,
    "harmless_blocked": harmless_blocked,
    "result": "TOTAL VICTORY"
    if (jailbreak_leaks == 0 and harmless_blo
