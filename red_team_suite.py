#!/usr/bin/env python3
"""
Run the public SIR red-team suite and write honest leak counts.

Round 3 upgrades:

- Suite selection:
  - If SIR_SUITE_PATH is set, use that.
  - Else, switch on SIR_ISC_PACK:
      hipaa_mental_health -> tests/hipaa_prompts_public.csv
      pci_payments        -> tests/pci_prompts_public.csv
      (default)           -> tests/jailbreak_prompts_public.csv
- Records the active domain_pack (from validate_sir) into logs and ITGL.

For each prompt:

- Wraps it in a minimal ISC envelope
- Sends it through sir_firewall.validate_sir
- Writes a human-readable log to proofs/latest-attempts.log
- Writes a hash-chained ITGL ledger to proofs/itgl_ledger.jsonl
- Emits jailbreak leak counts to leaks_count.txt and harmless_blocked.txt
- Exits non-zero if anything leaks or any harmless prompt is blocked
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any

import pandas as pd

from sir_firewall import validate_sir

MODEL_NAME = os.getenv("LITELLM_MODEL", "xai/grok-3-beta")  # for log context only

os.makedirs("proofs", exist_ok=True)
LOG_PATH = "proofs/latest-attempts.log"
LEDGER_PATH = "proofs/itgl_ledger.jsonl"


def resolve_suite_path() -> str:
    """
    Decide which CSV suite to run.

    Priority:
      1) SIR_SUITE_PATH (explicit override)
      2) SIR_ISC_PACK = hipaa_mental_health  -> tests/hipaa_prompts_public.csv
      3) SIR_ISC_PACK = pci_payments         -> tests/pci_prompts_public.csv
      4) default                             -> tests/jailbreak_prompts_public.csv
    """
    explicit = os.getenv("SIR_SUITE_PATH")
    if explicit:
        return explicit

    pack = os.getenv("SIR_ISC_PACK", "").strip()
    if pack == "hipaa_mental_health":
        return "tests/hipaa_prompts_public.csv"
    if pack == "pci_payments":
        return "tests/pci_prompts_public.csv"

    return "tests/jailbreak_prompts_public.csv"


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


def _extract_final_itgl_hash(result: Dict[str, Any]) -> str:
    """
    Best-effort extraction of the final ITGL hash from validate_sir result.

    Expected shape:
        result["itgl_log"] is a list of entries, and the last one has a "hash" field.

    If anything is missing, fall back to a stable hash over the whole result.
    """
    itgl_log = result.get("itgl_log")
    if isinstance(itgl_log, list) and itgl_log:
        last = itgl_log[-1]
        if isinstance(last, dict) and "hash" in last:
            return str(last["hash"])

    # Fallback: hash the entire result payload in a stable way
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    # Decide which CSV to use for this run
    csv_path = resolve_suite_path()

    # Load the public jailbreak / domain suite
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        raise SystemExit(f"ERROR: CSV not found at {csv_path}")

    if "prompt" not in df.columns or "expected" not in df.columns:
        raise SystemExit(
            f"ERROR: {csv_path} must contain at least 'prompt' and 'expected' columns"
        )

    total_prompts = len(df)
    expected_series = df["expected"].astype(str).str.lower()

    jailbreak_expected = (expected_series == "block").sum()
    harmless_expected = (expected_series == "allow").sum()

    # Honest counters
    jailbreak_leaks = 0   # jailbreak that SIR let through (status != BLOCKED)
    harmless_blocked = 0  # harmless prompt that SIR blocked

    # Start a fresh ITGL ledger for this run
    ledger_prev_hash = "GENESIS"

    with open(LOG_PATH, "w", encoding="utf-8") as log, open(
        LEDGER_PATH, "w", encoding="utf-8"
    ) as ledger:
        # Header for the proof log
        log.write(f"SIR Firewall — {total_prompts}-PROMPT 2025 PRE-INFERENCE RED TEAM\n")
        log.write(f"Date: {datetime.utcnow().isoformat()}Z\n")
        log.write(f"Model: {MODEL_NAME}\n")
        log.write(f"Env SIR_ISC_PACK: {os.getenv('SIR_ISC_PACK', 'unset')}\n")
        log.write(f"Test suite: {csv_path} — {total_prompts} hand-crafted prompts "
                  f"({jailbreak_expected} jailbreaks + {harmless_expected} harmless)\n")
        log.write("=" * 100 + "\n\n")

        for idx, row in df.iterrows():
            prompt = str(row.get("prompt", ""))
            expected = str(row.get("expected", "")).strip().lower()

            isc_envelope = {"isc": build_isc_envelope(prompt)}
            result = validate_sir(isc_envelope)

            status = str(result.get("status", "BLOCKED"))
            reason = str(result.get("reason", ""))
            domain_pack = str(result.get("domain_pack", "generic_safety"))

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

            # Human-readable log
            log.write(f"Prompt #{idx + 1}: {leak_flag}{prompt}\n")
            log.write(
                f"  expected={expected or 'unknown'}  "
                f"sir_status={status}  reason={reason}  "
                f"domain_pack={domain_pack}\n\n"
            )

            # ITGL ledger entry — hash-chained across the run
            final_hash = _extract_final_itgl_hash(result)
            ledger_entry = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "prompt_index": idx + 1,
                "isc_template": "EU-AI-Act-ISC-v1",
                "suite_path": csv_path,
                "domain_pack": domain_pack,
                "status": status,
                "expected": expected or "unknown",
                "leak_flag": leak_flag.strip(" []") or "",
                "final_hash": final_hash,
                "prev_hash": ledger_prev_hash,
            }
            ledger_payload = (
                (ledger_entry["prev_hash"] or "")
                + ledger_entry["final_hash"]
            ).encode("utf-8")
            ledger_entry["ledger_hash"] = hashlib.sha256(ledger_payload).hexdigest()

            ledger.write(json.dumps(ledger_entry, separators=(",", ":")) + "\n")
            ledger_prev_hash = ledger_entry["ledger_hash"]

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
            f"AUDIT PASSED: {total_prompts} prompts — "
            f"{jailbreak_expected} jailbreaks, {harmless_expected} harmless. "
            "No jailbreak leaks, no harmless prompts blocked."
        )
        raise SystemExit(0)
    else:
        print(
            f"AUDIT FAILED: {total_prompts} prompts — "
            f"{jailbreak_leaks} jailbreak leaks, {harmless_blocked} harmless prompts blocked. "
            "See proofs/latest-attempts.log and proofs/itgl_ledger.jsonl for full details."
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
