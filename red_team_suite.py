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

Also emits:
- proofs/run_summary.json          (preferred machine-readable summary)
- proofs/latest-attempts.log       (human log)
- proofs/itgl_ledger.jsonl         (hash-chained per-prompt ledger for offline verification)
"""

import argparse
import base64
import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

from litellm import completion

from sir_firewall import validate_sir


DEFAULT_SUITE = os.getenv("SIR_SUITE_PATH", "tests/domain_packs/generic_safety.csv")
PACK_REGISTRY_PATH = "spec/packs/pack_registry.v1.json"
DEFAULT_MODEL = os.getenv("LITELLM_MODEL", "xai/grok-3-beta")
DEFAULT_TEMPLATE_ID = os.getenv("SIR_TEMPLATE_ID", "EU-AI-Act-ISC-v1")

LEDGER_PATH = os.path.join("proofs", "itgl_ledger.jsonl")


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


def _load_pack_registry(path: str = PACK_REGISTRY_PATH) -> Dict[str, Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        registry = json.load(f)
    packs = registry.get("packs", [])
    if not isinstance(packs, list):
        raise ValueError(f"Invalid registry format in {path}: packs must be an array")

    out: Dict[str, Dict[str, str]] = {}
    for p in packs:
        if not isinstance(p, dict):
            continue
        pack_id = str(p.get("pack_id") or "").strip()
        if not pack_id:
            continue
        out[pack_id] = {
            "pack_id": pack_id,
            "pack_version": str(p.get("pack_version") or p.get("version") or "").strip(),
            "suite_path": str(p.get("suite_path") or "").strip(),
        }
    return out


def _resolve_suite_and_pack(
    suite_arg: Optional[str],
    pack_arg: Optional[str],
    env_suite: str,
    default_suite: str,
    registry_path: str = PACK_REGISTRY_PATH,
) -> Tuple[str, str, str]:
    registry = _load_pack_registry(registry_path)

    if suite_arg:
        suite_path = suite_arg
    elif pack_arg:
        pack = registry.get(pack_arg)
        if not pack:
            raise ValueError(f"Unknown --pack '{pack_arg}'. Check {registry_path}.")
        suite_path = pack.get("suite_path") or ""
        if not suite_path:
            raise ValueError(f"Pack '{pack_arg}' missing suite_path in {registry_path}.")
    elif env_suite:
        suite_path = env_suite
    else:
        suite_path = default_suite

    resolved_pack_id = ""
    resolved_pack_version = ""
    if pack_arg:
        pack = registry.get(pack_arg)
        if pack:
            resolved_pack_id = pack.get("pack_id", "")
            resolved_pack_version = pack.get("pack_version", "")
    else:
        suite_norm = os.path.normpath(suite_path)
        for pack in registry.values():
            if os.path.normpath(pack.get("suite_path", "")) == suite_norm:
                resolved_pack_id = pack.get("pack_id", "")
                resolved_pack_version = pack.get("pack_version", "")
                break

    return suite_path, resolved_pack_id, resolved_pack_version


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


def _policy_flags(policy_path: str = "policy/isc_policy.json") -> Dict[str, bool]:
    defaults = {"CRYPTO_ENFORCED": False, "CHECKSUM_ENFORCED": True}
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        flags = policy.get("flags") if isinstance(policy, dict) else None
        if not isinstance(flags, dict):
            return defaults
        return {
            "CRYPTO_ENFORCED": bool(flags.get("CRYPTO_ENFORCED", defaults["CRYPTO_ENFORCED"])),
            "CHECKSUM_ENFORCED": bool(flags.get("CHECKSUM_ENFORCED", defaults["CHECKSUM_ENFORCED"])),
        }
    except Exception:
        return defaults


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


def _maybe_call_model(model: str, prompt: str, enable: bool) -> bool:
    if not enable:
        return False
    # Keep this minimal: we're proving SIR is in front of a real model call.
    # The audit result is still based on SIR gating outcomes, not model content.
    completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=1,
    )
    return True


def _prompt_hash(prompt: str) -> str:
    return "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _strip_sha256_prefix(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("sha256:"):
        return v.split("sha256:", 1)[-1]
    return v


def _compute_ledger_hash(prev_hash: str, final_hash_raw: str) -> str:
    payload = (prev_hash or "") + (final_hash_raw or "")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _final_hash_from_verdict(verdict: Dict[str, object]) -> Optional[str]:
    """
    Prefer governance_context.itgl_final_hash for PASS.
    For BLOCKED, fall back to the last itgl_log entry hash.
    Returns raw hex (no sha256: prefix), or None if unavailable.
    """
    try:
        gc = verdict.get("governance_context")
        if isinstance(gc, dict):
            v = str(gc.get("itgl_final_hash") or "")
            v = _strip_sha256_prefix(v)
            if v:
                return v
    except Exception:
        pass

    try:
        itgl_log = verdict.get("itgl_log")
        if isinstance(itgl_log, list) and itgl_log:
            last = itgl_log[-1]
            if isinstance(last, dict):
                v = str(last.get("hash") or "")
                v = _strip_sha256_prefix(v)
                if v:
                    return v
    except Exception:
        pass

    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["audit", "live"], default="audit", help="Run mode: audit|live")
    ap.add_argument("--pack", default=None, help="Pack ID from spec/packs/pack_registry.v1.json")
    ap.add_argument("--suite", default=None, help="Path to CSV suite file (explicit override)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="LiteLLM model name")
    ap.add_argument("--template", default=DEFAULT_TEMPLATE_ID, help="ISC template_id to use")
    ap.add_argument("--no-model-calls", action="store_true", help="Skip model calls even for PASS prompts")
    args = ap.parse_args()

    if args.mode == "live" and args.no_model_calls:
        raise SystemExit("ERROR: --mode live cannot be used with --no-model-calls.")

    suite_path, pack_id, pack_version = _resolve_suite_and_pack(
        suite_arg=args.suite,
        pack_arg=args.pack,
        env_suite=os.getenv("SIR_SUITE_PATH", "").strip(),
        default_suite=DEFAULT_SUITE,
    )
    model_name = args.model
    template_id = args.template
    do_model_calls = args.mode == "live"
    proof_class = "LIVE_GATING_CHECK" if args.mode == "live" else "FIREWALL_ONLY_AUDIT"

    os.makedirs("proofs", exist_ok=True)
    log_path = os.path.join("proofs", "latest-attempts.log")

    rows_raw, rows = _read_suite(suite_path)
    prompts_tested = len(rows)
    suite_hash = _suite_hash(rows)

    # Counters
    jailbreaks_leaked = 0
    harmless_blocked = 0
    provider_call_attempts = 0
    provider_call_successes = 0
    provider_call_failures = 0

    # Regenerate the ITGL ledger every run (prevents stale-proof reuse)
    prev_ledger_hash = "GENESIS"
    with open(LEDGER_PATH, "w", encoding="utf-8") as ledger, open(log_path, "w", encoding="utf-8") as f:
        f.write("SIR Firewall — PRE-INFERENCE RED TEAM SUITE\n")
        f.write(f"Date: {_utc_now_iso()}\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Suite: {suite_path}\n")
        f.write(f"Suite hash: {suite_hash}\n")
        f.write(f"Prompts: {prompts_tested}\n")
        f.write("=" * 100 + "\n\n")

        for i, r in enumerate(rows, start=1):
            rid = r.get("id", "")
            prompt = r["prompt"]
            expected = r["expected"]

            # Detect if this row was encoded (from the raw row)
            raw_row = rows_raw[i - 1] if i - 1 < len(rows_raw) else {}
            prompt_encoded = bool((raw_row.get("prompt_b64") or "").strip()) and not bool((raw_row.get("prompt") or "").strip())

            isc = _build_isc_envelope(prompt, template_id)
            verdict = validate_sir({"isc": isc})
            status = str(verdict.get("status", "UNKNOWN"))

            expected_status = "PASS" if expected == "allow" else "BLOCKED"
            ok = (status == expected_status)

            if expected == "block" and status == "PASS":
                jailbreaks_leaked += 1
            if expected == "allow" and status == "BLOCKED":
                harmless_blocked += 1

            f.write(f"[{rid}] expected={expected_status} got={status}\n")
            if not ok:
                f.write(f"  NOTE: mismatch (expected {expected})\n")

            # Prove we are actually gating a real call (optional)
            provider_call_attempted = False
            if status == "PASS" and do_model_calls:
                # Counting rule (deterministic): increment once per attempted downstream call.
                # Retries/timeouts are separate attempts and must each increment this counter.
                provider_call_attempted = True
                provider_call_attempts += 1
                try:
                    if _maybe_call_model(model_name, prompt, do_model_calls):
                        provider_call_successes += 1
                except Exception as e:
                    provider_call_failures += 1
                    # Never persist model response content. Only record call error metadata.
                    f.write(f"  model_call_error: {type(e).__name__}: {e}\n")

            # Build per-prompt ledger entry
            final_hash_raw = _final_hash_from_verdict(verdict)
            if not final_hash_raw:
                # Fail closed on ledger integrity: write a marker but keep file consistent.
                # verify_itgl.py will fail if this is empty — which is correct.
                final_hash_raw = ""

            # Domain pack + template used
            domain_pack = str(verdict.get("domain_pack") or "")
            isc_template = str(template_id)

            # Leak flag (informational)
            leak_flag = ""
            if expected == "block" and status == "PASS":
                leak_flag = "LEAK"

            ledger_hash = _compute_ledger_hash(prev_ledger_hash, final_hash_raw)

            entry = {
                "ts": _utc_now_iso(),
                "prompt_index": i,
                "prompt_id": rid or "",
                "category": str(r.get("category") or ""),
                "note": str(r.get("note") or ""),
                "prompt_encoded": bool(prompt_encoded),
                "prompt_hash": _prompt_hash(prompt),
                "isc_template": isc_template,
                "suite_path": suite_path,
                "domain_pack": domain_pack,
                "status": status,
                "expected": expected,
                "provider_call_attempted": bool(provider_call_attempted),
                "leak_flag": leak_flag,
                # Both fields included for compatibility
                "final_hash": final_hash_raw,
                "itgl_prompt_final_hash": f"sha256:{final_hash_raw}" if final_hash_raw else "",
                "prev_hash": prev_ledger_hash,
                "ledger_hash": ledger_hash,
            }

            ledger.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
            prev_ledger_hash = ledger_hash

    # Back-compat counters for CI scripts that expect these files
    with open("leaks_count.txt", "w", encoding="utf-8") as f:
        f.write(str(jailbreaks_leaked))
    with open("harmless_blocked.txt", "w", encoding="utf-8") as f:
        f.write(str(harmless_blocked))

    # Preferred machine-readable summary for certificate generation
    summary_ts = _utc_now_iso()
    summary = {
        "date": summary_ts,
        "timestamp_utc": summary_ts,
        "proof_class": proof_class,
        "model": model_name,
        "provider": os.getenv("SIR_PROVIDER", "xai"),
        "pack_id": pack_id,
        "pack_version": pack_version,
        "suite_path": suite_path,
        "suite_name": os.path.splitext(os.path.basename(suite_path))[0],
        "suite_hash": suite_hash,
        "prompts_tested": prompts_tested,
        "jailbreaks_leaked": jailbreaks_leaked,
        "harmless_blocked": harmless_blocked,
        "provider_call_attempts": provider_call_attempts,
        "provider_call_successes": provider_call_successes,
        "provider_call_failures": provider_call_failures,
        "model_calls_made": provider_call_attempts,
        "flags": _policy_flags(),
    }
    with open(os.path.join("proofs", "run_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Suite: {suite_path} ({prompts_tested} prompts)")
    print(f"Leaks: {jailbreaks_leaked} | Harmless blocked: {harmless_blocked}")
    print(f"Proof log: {log_path}")
    print("Summary: proofs/run_summary.json")
    print(f"ITGL ledger: {LEDGER_PATH}")


if __name__ == "__main__":
    main()
