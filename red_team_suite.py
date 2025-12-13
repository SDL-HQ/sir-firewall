#!/usr/bin/env python3
"""
Run the SIR red-team suite and write honest leak counts.

SIR+ upgrades:

- Suite selection:
  - If SIR_SUITE_PATH is set, use that.
  - Else, switch on SIR_ISC_PACK:
      hipaa_mental_health -> tests/hipaa_prompts_public.csv
      pci_payments        -> tests/pci_prompts_public.csv
      (default)           -> tests/jailbreak_prompts_public.csv

- Template selection (no ambiguity):
  - If SIR_TEMPLATE_ID is set, use that.
  - Else:
      hipaa_mental_health -> HIPAA-ISC-v1
      pci_payments        -> PCI-DSS-ISC-v1
      (default)           -> EU-AI-Act-ISC-v1

- Supports both:
  - plain suites with:    prompt, expected, (optional id/note/category)
  - encoded suites with:  prompt_b64, expected, (optional id/note/category)

Encoded suite behaviour:
- Decodes prompt_b64 at runtime for evaluation.
- Logs do NOT print decoded prompt text; they log id/category + prompt_hash instead.
- Ledger stores prompt_hash, not prompt text, for encoded prompts.

Outputs:
- proofs/latest-attempts.log
- proofs/itgl_ledger.jsonl (hash-chained run ledger)
- proofs/itgl_final_hash.txt (final run ledger hash, sha256:...)
- leaks_count.txt
- harmless_blocked.txt

Exit non-zero if anything leaks or any harmless prompt is blocked.
"""

import os
import json
import base64
import hashlib
from datetime import datetime
from typing import Dict, Any, Tuple

import pandas as pd

from sir_firewall import validate_sir

MODEL_NAME = os.getenv("LITELLM_MODEL", "xai/grok-3-beta")  # log context only

os.makedirs("proofs", exist_ok=True)
LOG_PATH = "proofs/latest-attempts.log"
LEDGER_PATH = "proofs/itgl_ledger.jsonl"
RUN_FINAL_HASH_PATH = "proofs/itgl_final_hash.txt"


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


def resolve_template_id() -> str:
    """
    Decide which ISC template_id to use (must match what generate_certificate reports).

    Priority:
      1) SIR_TEMPLATE_ID (explicit override)
      2) SIR_ISC_PACK mapping
      3) default EU template
    """
    explicit = os.getenv("SIR_TEMPLATE_ID")
    if explicit:
        return explicit.strip()

    pack = os.getenv("SIR_ISC_PACK", "").strip()
    if pack == "hipaa_mental_health":
        return "HIPAA-ISC-v1"
    if pack == "pci_payments":
        return "PCI-DSS-ISC-v1"

    return "EU-AI-Act-ISC-v1"


def _b64_decode_prompt(blob: str) -> str:
    """
    Decode base64 prompt safely (tolerant of missing padding).
    Raises ValueError on failure.
    """
    if not isinstance(blob, str) or not blob.strip():
        return ""

    s = blob.strip()
    pad = (-len(s)) % 4
    if pad:
        s = s + ("=" * pad)

    try:
        decoded = base64.b64decode(s, validate=False)
        return decoded.decode("utf-8", errors="strict")
    except Exception as exc:
        raise ValueError(f"prompt_b64 decode failed: {exc}") from exc


def _prompt_sha256(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def build_isc_envelope(prompt: str, template_id: str) -> Dict[str, Any]:
    """
    Build a minimal but valid ISC envelope for test prompts.

        {
          "isc": {
            "version": "1.0",
            "template_id": "<template>",
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
        "template_id": template_id,
        "payload": prompt,
        "checksum": checksum,
        "signature": "",
        "key_id": "default",
    }


def _extract_final_itgl_hash(result: Dict[str, Any]) -> str:
    """
    Best-effort extraction of the final ITGL step hash from validate_sir result.

    Expected shape:
        result["itgl_log"] is a list; last entry has "hash".

    If missing, fall back to a stable hash over the whole result.
    """
    itgl_log = result.get("itgl_log")
    if isinstance(itgl_log, list) and itgl_log:
        last = itgl_log[-1]
        if isinstance(last, dict) and "hash" in last:
            return str(last["hash"])

    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _row_get_str(row: pd.Series, key: str) -> str:
    v = row.get(key, "")
    if v is None:
        return ""
    return str(v)


def _resolve_prompt_from_row(row: pd.Series) -> Tuple[str, bool, str]:
    """
    Returns: (prompt_text, is_encoded, prompt_hash_hex)

    - If prompt_b64 present & non-empty, decode it and mark is_encoded=True.
    - Else use prompt column (plain).
    """
    prompt_b64 = _row_get_str(row, "prompt_b64").strip()
    if prompt_b64:
        prompt_text = _b64_decode_prompt(prompt_b64)
        return prompt_text, True, _prompt_sha256(prompt_text)

    prompt_text = _row_get_str(row, "prompt")
    return prompt_text, False, _prompt_sha256(prompt_text)


def main() -> None:
    csv_path = resolve_suite_path()
    template_id = resolve_template_id()

    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        raise SystemExit(f"ERROR: CSV not found at {csv_path}")

    if "expected" not in df.columns:
        raise SystemExit(f"ERROR: {csv_path} must contain an 'expected' column")

    if "prompt" not in df.columns and "prompt_b64" not in df.columns:
        raise SystemExit(
            f"ERROR: {csv_path} must contain either 'prompt' (plain) or 'prompt_b64' (encoded) column"
        )

    total_prompts = len(df)
    expected_series = df["expected"].astype(str).str.lower().str.strip()

    jailbreak_expected = int((expected_series == "block").sum())
    harmless_expected = int((expected_series == "allow").sum())

    jailbreak_leaks = 0
    harmless_blocked = 0

    ledger_prev_hash = "GENESIS"

    with open(LOG_PATH, "w", encoding="utf-8") as log, open(
        LEDGER_PATH, "w", encoding="utf-8"
    ) as ledger:
        log.write(f"SIR Firewall — {total_prompts}-PROMPT 2025 PRE-INFERENCE RED TEAM\n")
        log.write(f"Date: {datetime.utcnow().isoformat()}Z\n")
        log.write(f"Model: {MODEL_NAME}\n")
        log.write(f"Env SIR_ISC_PACK: {os.getenv('SIR_ISC_PACK', 'unset')}\n")
        log.write(f"ISC template_id: {template_id}\n")
        log.write(
            f"Test suite: {csv_path} — {total_prompts} prompts "
            f"({jailbreak_expected} jailbreaks + {harmless_expected} harmless)\n"
        )
        log.write("=" * 100 + "\n\n")

        for idx, row in df.iterrows():
            expected = _row_get_str(row, "expected").strip().lower()
            prompt_id = _row_get_str(row, "id").strip()
            note = _row_get_str(row, "note").strip()
            category = _row_get_str(row, "category").strip()

            try:
                prompt_text, is_encoded, prompt_hash = _resolve_prompt_from_row(row)
            except ValueError as exc:
                raise SystemExit(f"ERROR: {csv_path} row #{idx+1}: {exc}")

            isc_envelope = {"isc": build_isc_envelope(prompt_text, template_id)}
            result = validate_sir(isc_envelope)

            status = str(result.get("status", "BLOCKED"))
            reason = str(result.get("reason", ""))
            domain_pack = str(result.get("domain_pack", "generic_safety"))

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
            if is_encoded:
                summary = "[ENCODED PROMPT]"
                if prompt_id:
                    summary += f" id={prompt_id}"
                if category:
                    summary += f" category={category}"
                summary += f" prompt_hash=sha256:{prompt_hash}"
                if note:
                    summary += f" note={note}"
                log.write(f"Prompt #{idx + 1}: {leak_flag}{summary}\n")
            else:
                log.write(f"Prompt #{idx + 1}: {leak_flag}{prompt_text}\n")

            log.write(
                f"  expected={expected or 'unknown'}  "
                f"sir_status={status}  reason={reason}  "
                f"domain_pack={domain_pack}\n\n"
            )

            # ITGL ledger entry — hash-chained across the run
            per_prompt_final_hash_hex = _extract_final_itgl_hash(result)

            ledger_entry: Dict[str, Any] = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "prompt_index": idx + 1,
                "prompt_id": prompt_id,
                "category": category,
                "note": note,
                "prompt_encoded": bool(is_encoded),
                "prompt_hash": f"sha256:{prompt_hash}",
                "isc_template": template_id,
                "suite_path": csv_path,
                "domain_pack": domain_pack,
                "status": status,
                "expected": expected or "unknown",
                "leak_flag": leak_flag.strip(" []") or "",

                # For compatibility + clarity:
                "final_hash": per_prompt_final_hash_hex,  # raw hex (preferred for chaining)
                "itgl_prompt_final_hash": f"sha256:{per_prompt_final_hash_hex}",

                "prev_hash": ledger_prev_hash,
            }

            # Chain rule: ledger_hash = sha256(prev_hash + final_hash_raw)
            ledger_payload = ((ledger_entry["prev_hash"] or "") + per_prompt_final_hash_hex).encode("utf-8")
            ledger_entry["ledger_hash"] = hashlib.sha256(ledger_payload).hexdigest()

            ledger.write(json.dumps(ledger_entry, separators=(",", ":")) + "\n")
            ledger_prev_hash = ledger_entry["ledger_hash"]

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

    # Export final run ledger hash for cert generator (sha256:...)
    with open(RUN_FINAL_HASH_PATH, "w", encoding="utf-8") as f:
        f.write(f"sha256:{ledger_prev_hash}")

    if jailbreak_leaks == 0 and harmless_blocked == 0:
        print(
            f"AUDIT PASSED: {total_prompts} prompts — "
            f"{jailbreak_expected} jailbreaks, {harmless_expected} harmless. "
            "No jailbreak leaks, no harmless prompts blocked."
        )
        raise SystemExit(0)

    print(
        f"AUDIT FAILED: {total_prompts} prompts — "
        f"{jailbreak_leaks} jailbreak leaks, {harmless_blocked} harmless prompts blocked. "
        "See proofs/latest-attempts.log and proofs/itgl_ledger.jsonl for full details."
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
