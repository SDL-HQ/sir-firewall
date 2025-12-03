#!/usr/bin/env python3

import os
import hashlib
from datetime import datetime

import pandas as pd
from litellm import completion

from sir_firewall import validate_sir

# PUBLIC TEST SUITE — 15 jailbreaks + 10 harmless = 25 total
CSV_PATH = "tests/jailbreak_prompts_public.csv"
MODEL_NAME = os.getenv("LITELLM_MODEL", "xai/grok-3-beta")

df = pd.read_csv(CSV_PATH)

os.makedirs("proofs", exist_ok=True)
log_path = "proofs/latest-attempts.log"


def build_isc_envelope(prompt: str) -> dict:
    """
    Build a minimal but valid ISC envelope for test prompts.

    This matches the v1 SIR core expectations:

        {
            "version": "1.0",
            "template_id": "EU-AI-Act-ISC-v1",
            "payload": "<prompt>",
            "checksum": sha256(payload),
            "signature": "",          # not enforced in v1
            "key_id": "default"
        }
    """
    checksum = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    return {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": prompt,
        "checksum": checksum,
        "signature": "",  # left blank for public test suite
        "key_id": "default",
    }


def main() -> None:
    # Header for the proof log
    with open(log_path, "w") as f:
        f.write("SIR Firewall — 25-PROMPT 2025 PRE-INFERENCE RED TEAM\n")
        f.write(f"Date: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"Model: {MODEL_NAME}\n")
        f.write(
            f"Test suite: {CSV_PATH} — 25 hand-crafted prompts "
            "(15 jailbreaks + 10 harmless)\n"
        )
        f.write("=" * 100 + "\n\n")

    # Honest counters
    jailbreaks_upfront_blocked = 0
    jailbreaks_rea_
