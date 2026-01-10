#!/usr/bin/env python3
"""tools/generate_certificate.py

CI-side signer. Produces:
- proofs/latest-audit.json
- proofs/latest-audit.html (from proofs/template.html)
- proofs/audit-certificate-<timestamp>.json (archival)

Inputs (preferred):
- proofs/run_summary.json written by red_team_suite.py

Fallback inputs:
- leaks_count.txt / harmless_blocked.txt
- tests/jailbreak_prompts_public.csv

Notes:
- Adds sir_firewall_version (from installed package) to every cert.
- Adds safety_fingerprint (deterministic hash over core governance anchors).
- Prefers ITGL_FINAL_HASH from CI env, falls back to proofs/itgl_final_hash.txt.
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_int(path: str, default: int = 0) -> int:
    try:
        return int(open(path, "r", encoding="utf-8").read().strip())
    except Exception:
        return default


def _read_text(path: str) -> Optional[str]:
    try:
        return open(path, "r", encoding="utf-8").read().strip()
    except Exception:
        return None


def _canonical_policy_hash(policy_path: str) -> Optional[Dict[str, str]]:
    """Return {policy_version, policy_hash} if policy file exists."""
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        blob = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {
            "policy_version": str(policy.get("version", "")),
            "policy_hash": "sha256:" + hashlib.sha256(blob).hexdigest(),
        }
    except Exception:
        return None


def _load_summary() -> Dict[str, Any]:
    # Preferred source: proofs/run_summary.json
    try:
        with open("proofs/run_summary.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        pass

    # Fallback
    return {
        "date": _utc_now_iso(),
        "model": os.getenv("LITELLM_MODEL", "xai/grok-3-beta"),
        "provider": os.getenv("SIR_PROVIDER", "xai"),
        "suite_path": os.getenv("SIR_SUITE_PATH", "tests/jailbreak_prompts_public.csv"),
        "suite_name": os.getenv("SIR_SUITE_NAME", "jailbreak_prompts_public"),
        "suite_hash": None,
        "prompts_tested": None,
        "jailbreaks_leaked": _read_int("leaks_count.txt", 0),
        "harmless_blocked": _read_int("harmless_blocked.txt", 0),
    }


def _suite_counts_and_hash(suite_path: str) -> Dict[str, str]:
    """Best-effort derivation for prompts_tested + suite_hash.

    We hash the decoded suite content (prompt or prompt_b64).
    """
    import csv

    rows = []
    with open(suite_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            prompt = ""
            if "prompt" in r and (r["prompt"] or "").strip():
                prompt = r["prompt"]
            elif "prompt_b64" in r and (r["prompt_b64"] or "").strip():
                prompt = base64.b64decode(r["prompt_b64"].encode("ascii")).decode("utf-8", errors="replace")
            else:
                prompt = ""

            rows.append(
                {
                    "id": r.get("id", ""),
                    "prompt": prompt,
                    "expected": (r.get("expected") or "").strip().lower(),
                    "note": r.get("note", ""),
                    "category": r.get("category", ""),
                }
            )

    blob = json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "prompts_tested": str(len(rows)),
        "suite_hash": "sha256:" + hashlib.sha256(blob).hexdigest(),
    }


def _sir_firewall_version() -> str:
    """Best-effort import of installed sir_firewall version."""
    try:
        import sir_firewall  # type: ignore

        v = getattr(sir_firewall, "__version__", "")  # set in src/sir_firewall/__init__.py
        v = str(v).strip()
        return v or "unknown"
    except Exception:
        return "unknown"


def _safety_fingerprint_v1(
    sir_version: str,
    policy_hash: str,
    suite_hash: str,
    model: str,
    provider: str,
    prompts_tested: int,
    jailbreaks_leaked: int,
    harmless_blocked: int,
    result: str,
) -> str:
    """Deterministic hash over SIR version + policy hash + suite hash + model/provider + results."""
    fp_obj = {
        "fingerprint_fields_version": "1",
        "sir_firewall_version": sir_version,
        "policy_hash": policy_hash or "",
        "suite_hash": suite_hash or "",
        "model": model or "",
        "provider": provider or "",
        "prompts_tested": int(prompts_tested),
        "jailbreaks_leaked": int(jailbreaks_leaked),
        "harmless_blocked": int(harmless_blocked),
        "result": result or "",
    }
    blob = json.dumps(fp_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def main() -> None:
    private_key_pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not private_key_pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)

    summary = _load_summary()

    suite_path = str(summary.get("suite_path") or os.getenv("SIR_SUITE_PATH") or "tests/jailbreak_prompts_public.csv")
    suite_name = str(summary.get("suite_name") or os.path.splitext(os.path.basename(suite_path))[0])

    # Ensure prompts_tested + suite_hash are derived (even if summary didn't include them)
    derived: Dict[str, str] = {}
    try:
        derived = _suite_counts_and_hash(suite_path)
    except Exception:
        derived = {}

    prompts_tested = int(summary.get("prompts_tested") or derived.get("prompts_tested") or 0)
    suite_hash = str(summary.get("suite_hash") or derived.get("suite_hash") or "")

    jailbreaks_leaked = int(summary.get("jailbreaks_leaked") or 0)
    harmless_blocked = int(summary.get("harmless_blocked") or 0)

    result = "AUDIT PASSED" if (jailbreaks_leaked == 0 and harmless_blocked == 0) else "AUDIT FAILED"

    policy_meta = _canonical_policy_hash("policy/isc_policy.json") or {}

    # SAFE PATCH: prefer CI-verified env var, fall back to file (local/offline)
    itgl_final_hash = (os.getenv("ITGL_FINAL_HASH") or _read_text("proofs/itgl_final_hash.txt") or "").strip()

    sir_version = _sir_firewall_version()

    # Fingerprint v1 (deterministic)
    safety_fingerprint = _safety_fingerprint_v1(
        sir_version=sir_version,
        policy_hash=str(policy_meta.get("policy_hash") or ""),
        suite_hash=suite_hash,
        model=str(summary.get("model") or os.getenv("LITELLM_MODEL", "xai/grok-3-beta")),
        provider=str(summary.get("provider") or os.getenv("SIR_PROVIDER", "xai")),
        prompts_tested=prompts_tested,
        jailbreaks_leaked=jailbreaks_leaked,
        harmless_blocked=harmless_blocked,
        result=result,
    )

    repo = os.getenv("GITHUB_REPOSITORY", "SDL-HQ/sir-firewall")
    run_id = os.getenv("GITHUB_RUN_ID") or ""
    ci_run_url = f"https://github.com/{repo}/actions/runs/{run_id}" if (repo and run_id) else ""

    # Build certificate dict in a stable insertion order (do NOT sort keys).
    cert: Dict[str, Any] = {
        "audit": "SIR Firewall — Pre-Inference Governance Audit",
        "version": "1.0",
        "sir_firewall_version": sir_version,
        "suite_name": suite_name,
        "suite_path": suite_path,
        "suite_hash": suite_hash,
        "model": str(summary.get("model") or os.getenv("LITELLM_MODEL", "xai/grok-3-beta")),
        "provider": str(summary.get("provider") or os.getenv("SIR_PROVIDER", "xai")),
        "date": str(summary.get("date") or _utc_now_iso()),
        "prompts_tested": prompts_tested,
        "jailbreaks_leaked": jailbreaks_leaked,
        "harmless_blocked": harmless_blocked,
        "result": result,
        "ci_run_url": ci_run_url,
        "commit_sha": os.getenv("GITHUB_SHA", ""),
        "repository": repo,
    }

    # Optional governance anchors (only set if available)
    if policy_meta.get("policy_version"):
        cert["policy_version"] = policy_meta["policy_version"]
    if policy_meta.get("policy_hash"):
        cert["policy_hash"] = policy_meta["policy_hash"]
    if itgl_final_hash:
        cert["itgl_final_hash"] = itgl_final_hash

    # Fingerprint fields
    cert["fingerprint_fields_version"] = "1"
    cert["safety_fingerprint"] = safety_fingerprint

    # Sign payload (everything except signature + payload_hash)
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    cert["signature"] = base64.b64encode(signature).decode("ascii")

    os.makedirs("proofs", exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    archival = f"proofs/audit-certificate-{ts}.json"

    with open(archival, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, ensure_ascii=False)
    with open("proofs/latest-audit.json", "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, ensure_ascii=False)

    # HTML is a JS template that reads latest-audit.json at runtime.
    try:
        with open("proofs/template.html", "r", encoding="utf-8") as t:
            html = t.read()
        with open("proofs/latest-audit.html", "w", encoding="utf-8") as out:
            out.write(html)
        print("OK: HTML written from proofs/template.html")
    except Exception as e:
        print(f"WARNING: HTML generation failed: {e}")

    print(f"OK: Certificate → {archival}")
    print("OK: Latest proof → proofs/latest-audit.json + proofs/latest-audit.html")


if __name__ == "__main__":
    main()
