#!/usr/bin/env python3
"""red_team_suite.py

Runs a CSV suite through SIR pre-inference gating and (optionally) calls the target model
for PASSed prompts. This is an *audit harness* — it counts:

- jailbreaks_leaked: prompts marked expected=block that SIR allowed (PASS)
- harmless_blocked: prompts marked expected=allow that SIR blocked

Suite formats supported:
1) Public/plain:
   id,prompt,expected,note,category
2) Sensitive/encoded:
   id,prompt_b64,expected,note,category

Where expected is: allow | block

NEW (P4):
- Aggregates per-run block reasons / rule-ids for website filtering:
  - blocks_by_reason
  - blocks_by_rule_id (reason + optional subtype)
  - blocks_by_type
  - blocks_by_category
  - allows_by_category
  - mismatches
"""

import argparse
import base64
import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from litellm import completion

from sir_firewall import validate_sir


DEFAULT_SUITE = os.getenv("SIR_SUITE_PATH", "tests/jailbreak_prompts_public.csv")
DEFAULT_MODEL = os.getenv("LITELLM_MODEL", "xai/grok-3-beta")
DEFAULT_TEMPLATE_ID = os.getenv("SIR_TEMPLATE_ID", "EU-AI-Act-ISC-v1")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_suite(path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Return (rows_raw, rows_decoded). Decoded rows always have a 'prompt' key."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows_raw = [dict(r) for r in reader]

    rows_decoded: List[Dict[str, str]] = []
    for r in rows_raw:
        r2 = dict(r)

        # Normalize expected
        exp = (r2.get("expected") or "").strip().lower()
        if exp not in ("allow", "block"):
            raise ValueError(f"Suite row has invalid expected= value: {exp!r} (must be allow|block)")

        # Decode prompt
        if "prompt" in r2 and r2["prompt"] is not None and str(r2["prompt"]).strip() != "":
            prompt = str(r2["prompt"])
        elif "prompt_b64" in r2 and r2["prompt_b64"] is not None and str(r2["prompt_b64"]).strip() != "":
            prompt = base64.b64decode(str(r2["prompt_b64"]).encode("ascii")).decode("utf-8", errors="replace")
        else:
            raise ValueError("Suite row missing prompt or prompt_b64")

        r2["prompt"] = prompt
        r2["expected"] = exp

        # Stable id
        if not r2.get("id"):
            r2["id"] = f"row-{len(rows_decoded)+1:03d}"

        rows_decoded.append(r2)

    return rows_raw, rows_decoded


def _suite_hash(rows_decoded: List[Dict[str, str]]) -> str:
    """Hash over the decoded suite (what SIR actually saw)."""
    canonical = [
        {
            "id": r.get("id", ""),
            "prompt": r.get("prompt", ""),
            "expected": r.get("expected", ""),
            "note": r.get("note", ""),
            "category": r.get("category", ""),
        }
        for r in rows_decoded
    ]
    blob = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _build_isc_envelope(prompt: str, template_id: str) -> Dict[str, str]:
    checksum = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    return {
        "version": "1.0",
        "template_id": template_id,
        "payload": prompt,
        "checksum": checksum,
        "signature": "",  # not enforced by default
        "key_id": "default",
    }


def _maybe_call_model(model: str, prompt: str, enable: bool) -> None:
    if not enable:
        return
    # Keep this minimal: we're proving SIR is in front of a real model call.
    # The audit result is still based on SIR gating outcomes, not model content.
    completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=64,
    )


def _inc(counter: Dict[str, int], key: str) -> None:
    if not key:
        key = "unknown"
    counter[key] = int(counter.get(key, 0)) + 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default=DEFAULT_SUITE, help="Path to CSV suite file")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="LiteLLM model name")
    ap.add_argument("--template", default=DEFAULT_TEMPLATE_ID, help="ISC template_id to use")
    ap.add_argument("--no-model-calls", action="store_true", help="Skip model calls even for PASS prompts")
    args = ap.parse_args()

    suite_path = args.suite
    model_name = args.model
    template_id = args.template
    do_model_calls = (os.getenv("SIR_MODEL_CALLS", "1").strip() != "0") and (not args.no_model_calls)

    os.makedirs("proofs", exist_ok=True)
    log_path = "proofs/latest-attempts.log"

    _, rows = _read_suite(suite_path)
    prompts_tested = len(rows)
    suite_hash = _suite_hash(rows)

    # Counters (back-compat)
    jailbreaks_leaked = 0
    harmless_blocked = 0

    # NEW: Aggregates for website filtering
    blocks_by_reason: Dict[str, int] = {}
    blocks_by_rule_id: Dict[str, int] = {}
    blocks_by_type: Dict[str, int] = {}
    blocks_by_category: Dict[str, int] = {}
    allows_by_category: Dict[str, int] = {}
    mismatches = 0

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("SIR Firewall — PRE-INFERENCE RED TEAM SUITE\n")
        f.write(f"Date: {_utc_now_iso()}\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Suite: {suite_path}\n")
        f.write(f"Suite hash: {suite_hash}\n")
        f.write(f"Prompts: {prompts_tested}\n")
        f.write(f"Template: {template_id}\n")
        f.write("=" * 100 + "\n\n")

        for r in rows:
            rid = r.get("id", "")
            prompt = r["prompt"]
            expected = r["expected"]
            category = str(r.get("category") or "").strip() or "uncategorized"

            isc = _build_isc_envelope(prompt, template_id)
            verdict: Dict[str, Any] = validate_sir({"isc": isc})
            status = str(verdict.get("status", "UNKNOWN"))

            # These are stable in core.py today
            reason = str(verdict.get("reason", "")) if isinstance(verdict, dict) else ""
            subtype = str(verdict.get("type", "")) if isinstance(verdict, dict) else ""

            expected_status = "PASS" if expected == "allow" else "BLOCKED"
            ok = (status == expected_status)

            if not ok:
                mismatches += 1

            # Old counters
            if expected == "block" and status == "PASS":
                jailbreaks_leaked += 1
            if expected == "allow" and status == "BLOCKED":
                harmless_blocked += 1

            # NEW aggregates
            if status == "BLOCKED":
                _inc(blocks_by_reason, reason or "unknown_reason")

                # rule_id = reason + subtype (if present)
                rule_id = reason or "unknown_reason"
                if subtype:
                    rule_id = f"{rule_id}:{subtype}"
                    _inc(blocks_by_type, subtype)
                _inc(blocks_by_rule_id, rule_id)

                _inc(blocks_by_category, category)

            elif status == "PASS":
                _inc(allows_by_category, category)

            # Log
            f.write(f"[{rid}] expected={expected_status} got={status}\n")
            if reason:
                f.write(f"  reason: {reason}\n")
            if subtype:
                f.write(f"  type: {subtype}\n")
            if category:
                f.write(f"  category: {category}\n")
            if not ok:
                f.write(f"  NOTE: mismatch (expected {expected})\n")

            # Prove we are actually gating a real call (optional)
            if status == "PASS":
                try:
                    _maybe_call_model(model_name, prompt, do_model_calls)
                except Exception as e:
                    # Model call failures do not change SIR gating counts — log only.
                    f.write(f"  model_call_error: {type(e).__name__}: {e}\n")

            f.write("\n")

    # Back-compat counters for CI scripts that expect these files
    with open("leaks_count.txt", "w", encoding="utf-8") as f:
        f.write(str(jailbreaks_leaked))
    with open("harmless_blocked.txt", "w", encoding="utf-8") as f:
        f.write(str(harmless_blocked))

    # Preferred machine-readable summary for certificate generation
    summary: Dict[str, Any] = {
        "date": _utc_now_iso(),
        "model": model_name,
        "provider": os.getenv("SIR_PROVIDER", "xai"),
        "suite_path": suite_path,
        "suite_name": os.path.splitext(os.path.basename(suite_path))[0],
        "suite_hash": suite_hash,
        "prompts_tested": prompts_tested,
        "jailbreaks_leaked": jailbreaks_leaked,
        "harmless_blocked": harmless_blocked,

        # NEW aggregates
        "mismatches": mismatches,
        "blocks_by_reason": blocks_by_reason,
        "blocks_by_rule_id": blocks_by_rule_id,
        "blocks_by_type": blocks_by_type,
        "blocks_by_category": blocks_by_category,
        "allows_by_category": allows_by_category,
    }

    with open("proofs/run_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"Suite: {suite_path} ({prompts_tested} prompts)")
    print(f"Leaks: {jailbreaks_leaked} | Harmless blocked: {harmless_blocked} | Mismatches: {mismatches}")
    print(f"Proof log: {log_path}")
    print("Summary: proofs/run_summary.json")


if __name__ == "__main__":
    main()
