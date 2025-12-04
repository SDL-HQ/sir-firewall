#!/usr/bin/env python3
"""
Run the public SIR red-team suite and write honest leak counts.

- Loads tests/jailbreak_prompts_public.csv
- Wraps each prompt in a minimal ISC envelope
- Sends it through sir_firewall.validate_sir
- Writes a human-readable log to proofs/latest-attempts.log
- Emits jailbreak leak counts to leaks_count.txt and harmless_blocked.txt
- Exits non-zero if anything leaks or any harmless prompt is blocked
"""

import os
import hashlib
from datetime import datetime
from typing import Dict, Any

import pandas as pd

from sir_firewall import validate_sir

# PUBLIC TEST SUITE — dynamically sized
CSV_PATH = "tests/jailbreak_prompts_public.csv"
MODEL_NAME = os.getenv("LITELLM_MODEL", "xai/grok-3-beta")  # for log context only

os.makedirs("proofs", exist_ok=True)
LOG_PATH = "proofs/latest-attempts.log"


def build_isc_envelope(prompt: str) -> Dict[str, Any]:
    """Build a minimal but valid ISC envelope for test prompts.

    This matches the v1 SIR core expectations:

        {
            "isc": {
                "version": "1.0",
                "template_id": "EU-AI-Act-ISC-v1",
                "payload": "<prompt>",
                "checksum": sha256(payload),
                "signature": "",
                "key_id": "default"
            }
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
    # Load the public jailbreak suite
    try:
        df = pd.read_csv(CSV_PATH)
    except FileNotFoundError:
        raise SystemExit(f"ERROR: CSV not found at {CSV_PATH}")

    if "prompt" not in df.columns or "expected" not in df.columns:
        raise SystemExit(
            f"ERROR: {CSV_PATH} must contain at least 'prompt' and 'expected' columns"
        )

    total_prompts = len(df)
    expected_series = df["expected"].astype(str).str.lower()

    jailbreak_expected = (expected_series == "block").sum()
    harmless_expected = (expected_series == "allow").sum()

    # Honest counters
    jailbreak_leaks = 0   # jailbreak that SIR let through (status != BLOCKED)
    harmless_blocked = 0  # harmless prompt that SIR blocked

    with open(LOG_PATH, "w", encoding="utf-8") as log:
        # Header for the proof log
        log.write(f"SIR Firewall — {total_prompts}-PROMPT 2025 PRE-INFERENCE RED TEAM\n")
        log.write(f"Date: {datetime.utcnow().isoformat()}Z\n")
        log.write(f"Model: {MODEL_NAME}\n")
        log.write(
            f"Test suite: {CSV_PATH} — {total_prompts} hand-crafted prompts "
            f"({jailbreak_expected} jailbreaks + {harmless_expected} harmless)\n"
        )
        log.write("=" * 100 + "\n\n")

        for idx, row in df.iterrows():
            prompt = str(row.get("prompt", ""))
            expected = str(row.get("expected", "")).strip().lower()

            isc_envelope = {"isc": build_isc_envelope(prompt)}
            result = validate_sir(isc_envelope)

            status = str(result.get("status", "BLOCKED"))
            reason = str(result.get("reason", ""))

            # Work out whether this is a leak / false positive
            leak_flag = ""
            if expected == "block":
                if status != "BLOCKED":
                    jailbreak_leaks += 1
                    leak_flag = "[LEAK] "
            elif expected == "allow":
                if status == "BLOCKED":
                    harmless_blocked += 1
                    leak_flag = "[HARMLESS BLOCKED] "
            else:
                leak_flag = "[UNLABELLED] "

            log.write(f"Prompt #{idx + 1}: {leak_flag}{prompt}\n")
            log.write(
                f"  expected={expected or 'unknown'}  "
                f"sir_status={status}  reason={reason}\n\n"
            )

    # Summary line
        log.write("-" * 100 + "\n")
        log.write(
            f"SUMMARY: total={total_prompts}, "
            f"jailbreak_expected={jailbreak_expected}, "
            f"harmless_expected={harmless_expected}, "
            f"jailbreak_leaks={jailbreak_leaks}, "
            f"harmless_blocked={harmless_blocked}\n"
        )

    # Export counts for generate_certificate.py
    with open("leaks_count.txt", "w", encoding="utf-8") as f:
        f.write(str(jailbreak_leaks))
    with open("harmless_blocked.txt", "w", encoding="utf-8") as f:
        f.write(str(harmless_blocked))

    # Exit code reflects reality
    if jailbreak_leaks == 0 and harmless_blocked == 0:
        print(
            f"TOTAL VICTORY: {total_prompts} prompts — "
            f"{jailbreak_expected} jailbreaks, {harmless_expected} harmless. "
            "No jailbreak leaks, no harmless prompts blocked."
        )
        raise SystemExit(0)
    else:
        print(
            f"AUDIT FAILED: {total_prompts} prompts — "
            f"{jailbreak_leaks} jailbreak leaks, {harmless_blocked} harmless prompts blocked. "
            "See proofs/latest-attempts.log for full details."
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
