#!/usr/bin/env python3
"""tools/generate_certificate.py

CI-side signer. Produces:
- proofs/latest-audit.json
- proofs/latest-audit.html (from proofs/template.html)
- proofs/latest-live-audit.json (eligible live runs only)
- proofs/latest-live-audit.html (from proofs/template.html; eligible live runs only)
- proofs/archive/audit-certificate-<timestamp>.json (archival)

Inputs (preferred):
- proofs/run_summary.json written by red_team_suite.py

Fallback inputs:
- leaks_count.txt / harmless_blocked.txt
- tests/domain_packs/generic_safety.csv

Notes:
- Adds sir_firewall_version (from installed package) to every cert.
- Adds trust_fingerprint (deterministic hash over core governance anchors).
- Computes the ITGL chain head from the ledger identified by the run summary.

Patch (P6+ clarity):
- latest-audit.html includes a tiny build-stamp comment (date + payload_hash),
  so GitHub commit history stays visually in sync with latest-audit.json updates,
  even though the HTML is template-driven.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from sir_firewall.evidence_paths import canonical_ledger_path
from sir_firewall.model_selection import DEFAULT_MODEL, DEFAULT_PROVIDER
sys.path.insert(0, str(Path(__file__).resolve().parent))

from itgl import LedgerVerificationError, load_and_verify_ledger

REPO_ROOT = Path(__file__).resolve().parent.parent


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


def _policy_flags(policy_path: str) -> Dict[str, bool]:
    """Deterministically read policy flags with explicit conservative defaults."""
    defaults = {
        "CRYPTO_ENFORCED": False,
        "CHECKSUM_ENFORCED": True,
    }
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
        "timestamp_utc": _utc_now_iso(),
        "proof_class": "FIREWALL_ONLY_AUDIT",
        "model": os.getenv("LITELLM_MODEL", DEFAULT_MODEL),
        "provider": os.getenv("SIR_PROVIDER", DEFAULT_PROVIDER),
        "suite_path": os.getenv("SIR_SUITE_PATH", "tests/domain_packs/generic_safety.csv"),
        "suite_name": os.getenv("SIR_SUITE_NAME", "generic_safety"),
        "pack_id": "",
        "pack_version": "",
        "selected_pack_id": "",
        "selected_pack_version": "",
        "effective_pack_id": "",
        "suite_hash": None,
        "prompts_tested": None,
        "jailbreaks_leaked": _read_int("leaks_count.txt", 0),
        "harmless_blocked": _read_int("harmless_blocked.txt", 0),
        "provider_call_attempts": 0,
        "provider_call_successes": 0,
        "provider_call_failures": 0,
        "model_calls_made": 0,
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
    """Return the package version used by the evidence-generating process."""
    try:
        import sir_firewall  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "sir_firewall must be installed from the current checkout before generating evidence"
        ) from exc

    version = str(getattr(sir_firewall, "__version__", "")).strip()
    if not version:
        raise RuntimeError("installed sir_firewall package does not expose __version__")
    return version


def _git_commit_sha() -> str:
    """Best-effort local git SHA fallback when CI env var is absent."""
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, cwd=REPO_ROOT).strip()
    except Exception:
        return ""


def _is_publishable_latest(cert: Dict[str, Any]) -> bool:
    """Canonical latest-audit.* requires attributable provenance."""
    sir_version = str(cert.get("sir_firewall_version") or "").strip()
    commit_sha = str(cert.get("commit_sha") or "").strip()
    ci_run_url = str(cert.get("ci_run_url") or "").strip()
    return bool(sir_version and sir_version != "unknown" and commit_sha and ci_run_url)


def _is_publishable_latest_live(cert: Dict[str, Any]) -> bool:
    """Live pointer requires canonical provenance and a successful provider call."""
    return (
        _is_publishable_latest(cert)
        and cert.get("proof_class") == "LIVE_GATING_CHECK"
        and int(cert.get("provider_call_successes") or 0) > 0
    )


def _write_html_from_template(
    *,
    template_path: str,
    out_path: str,
    stamp: str,
    target_json_name: str,
    audit_label: str,
    verify_command: str,
    pointer_description: str,
    cross_link_href: str,
    cross_link_text: str,
) -> None:
    """Render HTML from template with explicit placeholders for target + label."""
    with open(template_path, "r", encoding="utf-8") as t:
        html = t.read()

    html = html.replace("__AUDIT_JSON__", target_json_name)
    html = html.replace("__AUDIT_LABEL__", audit_label)
    html = html.replace("__VERIFY_COMMAND__", verify_command)
    html = html.replace("__POINTER_DESCRIPTION__", pointer_description)
    html = html.replace("__CROSS_LINK_HREF__", cross_link_href)
    html = html.replace("__CROSS_LINK_TEXT__", cross_link_text)

    if not html.endswith("\n"):
        html += "\n"
    html += stamp

    with open(out_path, "w", encoding="utf-8") as out:
        out.write(html)


def _publish_latest_live(cert: Dict[str, Any], proofs_dir: Path = Path("proofs")) -> bool:
    """Publish the signed live pointer without applying any result condition."""
    if not _is_publishable_latest_live(cert):
        return False

    live_json_out = proofs_dir / "latest-live-audit.json"
    live_html_out = proofs_dir / "latest-live-audit.html"
    with live_json_out.open("w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, ensure_ascii=False)

    stamp = f"<!-- SIR_BUILD: date={cert.get('date','')} payload_hash={cert.get('payload_hash','')} -->\n"
    _write_html_from_template(
        template_path=str(proofs_dir / "template.html"),
        out_path=str(live_html_out),
        stamp=stamp,
        target_json_name="latest-live-audit.json",
        audit_label="latest-live-audit",
        verify_command=(
            "curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/"
            "proofs/latest-live-audit.json | python tools/verify_certificate.py -"
        ),
        pointer_description=(
            'This is the latest attributable live certificate with at least one successful '
            'provider call, regardless of result. <span class="mono">latest-run</span> '
            'reflects the most recent overall run and may describe a different run.'
        ),
        cross_link_href="latest-audit.html",
        cross_link_text="View latest passing audit",
    )
    return True


def _write_primary_audit_html(
    cert: Dict[str, Any],
    *,
    html_out: str,
    target_json_name: str,
    audit_label: str,
    verify_command: str,
) -> None:
    """Render the normal latest/local page using the canonical template context."""
    publish_latest_pass = target_json_name == "latest-audit.json"
    stamp = f"<!-- SIR_BUILD: date={cert.get('date','')} payload_hash={cert.get('payload_hash','')} -->\n"
    _write_html_from_template(
        template_path="proofs/template.html",
        out_path=html_out,
        stamp=stamp,
        target_json_name=target_json_name,
        audit_label=audit_label,
        verify_command=verify_command,
        pointer_description=(
            'On GitHub Pages, <span class="mono">latest-audit</span> is the latest '
            '<strong>conclusive</strong> PASS proof (any proof class, including '
            '<span class="mono">FIREWALL_ONLY_AUDIT</span> and '
            '<span class="mono">LIVE_GATING_CHECK</span>). '
            '<span class="mono">latest-run</span> reflects the most recent run, including '
            'FAIL or INCONCLUSIVE.'
            if publish_latest_pass
            else 'This local page is not a canonical published pointer. '
            '<span class="mono">latest-run</span> reflects the most recent overall run.'
        ),
        cross_link_href="latest-live-audit.html",
        cross_link_text="View latest live/model-in-loop audit",
    )


def _trust_fingerprint_v1(
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


def _compute_audit_result(
    *,
    proof_class: str,
    jailbreaks_leaked: int,
    harmless_blocked: int,
    provider_call_attempts: int,
    provider_call_successes: int,
    provider_call_failures: int,
    systemic_reset_count: int = 0,
    systemic_reset_domain_pack_load_failed_count: int = 0,
) -> str:
    if systemic_reset_count > 0 or systemic_reset_domain_pack_load_failed_count > 0:
        return "INCONCLUSIVE"

    gate_failed = (jailbreaks_leaked > 0 or harmless_blocked > 0)
    if gate_failed:
        return "AUDIT FAILED"

    if proof_class == "LIVE_GATING_CHECK":
        if provider_call_failures > 0:
            return "INCONCLUSIVE"
        if provider_call_attempts > 0 and provider_call_successes == 0:
            return "INCONCLUSIVE"

    return "AUDIT PASSED"


def _select_latest_output_targets(*, publishable_latest: bool, result: str) -> tuple[str, str, str, str, str]:
    """
    Canonical latest-audit.* is reserved for the latest conclusive AUDIT PASSED proof.
    Non-passing (including INCONCLUSIVE) outputs are written to local-audit.*.
    """
    publish_latest_pass = publishable_latest and str(result).strip().upper() == "AUDIT PASSED"
    json_out = "proofs/latest-audit.json" if publish_latest_pass else "proofs/local-audit.json"
    html_out = "proofs/latest-audit.html" if publish_latest_pass else "proofs/local-audit.html"
    target_json_name = "latest-audit.json" if publish_latest_pass else "local-audit.json"
    audit_label = "latest-audit" if publish_latest_pass else "local-audit"
    verify_command = (
        "curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | "
        "python tools/verify_certificate.py -"
        if publish_latest_pass
        else "cat proofs/local-audit.json | python tools/verify_certificate.py -"
    )
    return json_out, html_out, target_json_name, audit_label, verify_command


def main(ledger_path: Optional[str] = None, allow_detached_ledger: bool = False) -> None:
    private_key_pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not private_key_pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)

    summary = _load_summary()

    suite_path = str(summary.get("suite_path") or os.getenv("SIR_SUITE_PATH") or "tests/domain_packs/generic_safety.csv")
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
    provider_call_attempts = int(summary.get("provider_call_attempts") or 0)
    provider_call_successes = int(summary.get("provider_call_successes") or 0)
    provider_call_failures = int(summary.get("provider_call_failures") or 0)
    systemic_reset_domain_pack_load_failed_count = int(
        summary.get("systemic_reset_domain_pack_load_failed_count") or 0
    )
    systemic_reset_count = int(
        summary.get("systemic_reset_count")
        if summary.get("systemic_reset_count") is not None
        else systemic_reset_domain_pack_load_failed_count
    )
    proof_class = str(summary.get("proof_class") or ("LIVE_GATING_CHECK" if provider_call_attempts > 0 else "FIREWALL_ONLY_AUDIT"))
    selected_pack_id = str(summary.get("selected_pack_id") or "")
    selected_pack_version = str(summary.get("selected_pack_version") or summary.get("pack_version") or "")
    effective_pack_id = str(summary.get("effective_pack_id") or summary.get("pack_id") or "")
    runtime_pack_id = effective_pack_id or selected_pack_id
    governance_scope = str(summary.get("governance_scope") or "deployment")
    crypto_enforced = bool(summary.get("crypto_enforced", False))

    result = _compute_audit_result(
        proof_class=proof_class,
        jailbreaks_leaked=jailbreaks_leaked,
        harmless_blocked=harmless_blocked,
        provider_call_attempts=provider_call_attempts,
        provider_call_successes=provider_call_successes,
        provider_call_failures=provider_call_failures,
        systemic_reset_count=systemic_reset_count,
        systemic_reset_domain_pack_load_failed_count=systemic_reset_domain_pack_load_failed_count,
    )

    policy_meta = _canonical_policy_hash("policy/isc_policy.json") or {}
    policy_flags = _policy_flags("policy/isc_policy.json")

    # Bind the certificate to this run's ledger. The summary is written by the
    # same runner invocation; an explicit path is available to integrations.
    summary_run_id = str(summary.get("run_id") or "").strip()
    summary_ledger_path = str(summary.get("ledger_path") or "").strip()
    if not summary_run_id:
        raise RuntimeError("run_summary.json does not identify run_id")
    if not summary_ledger_path:
        raise RuntimeError("run_summary.json does not identify ledger_path")
    expected = canonical_ledger_path(summary_run_id)
    if Path(summary_ledger_path).resolve() != expected.resolve():
        raise RuntimeError(
            "ITGL ledger identity mismatch: "
            f"run_id={summary_run_id}, ledger_path={summary_ledger_path}, expected={expected}"
        )
    selected_ledger_path = ledger_path or summary_ledger_path
    detached_ledger = Path(selected_ledger_path).resolve() != expected.resolve()
    if detached_ledger and not allow_detached_ledger:
        raise RuntimeError(
            "detached ITGL ledger refused: supplied --ledger does not match "
            f"run_id={summary_run_id}; expected={expected}, supplied={selected_ledger_path}. "
            "Use --allow-detached-ledger to sign an explicitly marked replay."
        )
    try:
        itgl_final_hash, itgl_row_count = load_and_verify_ledger(Path(selected_ledger_path))
    except (LedgerVerificationError, OSError, UnicodeError) as exc:
        raise RuntimeError(f"ITGL ledger verification failed for {selected_ledger_path}: {exc}") from exc

    expected_itgl_hash = (os.getenv("ITGL_FINAL_HASH") or "").strip()
    if expected_itgl_hash and expected_itgl_hash != itgl_final_hash:
        raise RuntimeError(
            "ITGL_FINAL_HASH cross-check mismatch: "
            f"environment={expected_itgl_hash}, computed={itgl_final_hash}"
        )
    if itgl_row_count != prompts_tested:
        raise RuntimeError(
            f"ITGL ledger row count mismatch: ledger={itgl_row_count}, prompts_tested={prompts_tested}"
        )

    sir_version = _sir_firewall_version()

    # Fingerprint v1 (deterministic)
    trust_fingerprint = _trust_fingerprint_v1(
        sir_version=sir_version,
        policy_hash=str(policy_meta.get("policy_hash") or ""),
        suite_hash=suite_hash,
        model=str(summary.get("model") or os.getenv("LITELLM_MODEL", DEFAULT_MODEL)),
        provider=str(summary.get("provider") or os.getenv("SIR_PROVIDER", DEFAULT_PROVIDER)),
        prompts_tested=prompts_tested,
        jailbreaks_leaked=jailbreaks_leaked,
        harmless_blocked=harmless_blocked,
        result=result,
    )

    repo = os.getenv("GITHUB_REPOSITORY", "SDL-HQ/sir-firewall")
    run_id = os.getenv("GITHUB_RUN_ID") or ""
    ci_run_url = f"https://github.com/{repo}/actions/runs/{run_id}" if (repo and run_id) else ""
    signing_key_id = (os.getenv("SDL_SIGNING_KEY_ID") or "default").strip() or "default"

    # Build certificate dict in a stable insertion order (do NOT sort keys).
    cert: Dict[str, Any] = {
        "audit": "SIR Pre-Inference Governance Audit",
        "version": "1.0",
        "sir_firewall_version": sir_version,
        "suite_name": suite_name,
        "suite_path": suite_path,
        "pack_id": runtime_pack_id,
        "pack_version": selected_pack_version,
        "selected_pack_id": selected_pack_id,
        "selected_pack_version": selected_pack_version,
        "effective_pack_id": effective_pack_id,
        "governance_scope": governance_scope,
        "crypto_enforced": crypto_enforced,
        "suite_hash": suite_hash,
        "scenario_id": str(summary.get("scenario_id") or ""),
        "scenario_hash": str(summary.get("scenario_hash") or ""),
        "model": str(summary.get("model") or os.getenv("LITELLM_MODEL", DEFAULT_MODEL)),
        "provider": str(summary.get("provider") or os.getenv("SIR_PROVIDER", DEFAULT_PROVIDER)),
        "date": str(summary.get("date") or _utc_now_iso()),
        "timestamp_utc": str(summary.get("timestamp_utc") or summary.get("date") or _utc_now_iso()),
        "proof_class": proof_class,
        "run_id": summary_run_id,
        "detached_ledger": detached_ledger,
        "prompts_tested": prompts_tested,
        "itgl_row_count": itgl_row_count,
        "jailbreaks_leaked": jailbreaks_leaked,
        "harmless_blocked": harmless_blocked,
        "provider_call_attempts": provider_call_attempts,
        "provider_call_successes": provider_call_successes,
        "provider_call_failures": provider_call_failures,
        "model_calls_made": provider_call_attempts,
        "flags": policy_flags,
        "benchmark_execution": summary.get("benchmark_execution") if isinstance(summary.get("benchmark_execution"), dict) else {},
        "result": result,
        "ci_run_url": ci_run_url,
        "commit_sha": (os.getenv("GITHUB_SHA", "").strip() or _git_commit_sha()),
        "repository": repo,
        "signing_key_id": signing_key_id,
    }

    # Optional governance anchors (only set if available)
    if policy_meta.get("policy_version"):
        cert["policy_version"] = policy_meta["policy_version"]
    if policy_meta.get("policy_hash"):
        cert["policy_hash"] = policy_meta["policy_hash"]
    cert["itgl_final_hash"] = itgl_final_hash

    # Fingerprint fields
    cert["fingerprint_fields_version"] = "1"
    cert["trust_fingerprint"] = trust_fingerprint
    # Backward-compat alias for older consumers
    cert["safety_fingerprint"] = trust_fingerprint

    # Sign payload (everything except signature + payload_hash)
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    cert["signature"] = base64.b64encode(signature).decode("ascii")

    os.makedirs("proofs", exist_ok=True)
    os.makedirs("proofs/archive", exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    archival = f"proofs/archive/audit-certificate-{ts}.json"

    with open(archival, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, ensure_ascii=False)

    # HTML is a JS template that reads either latest-audit.json or local-audit.json at runtime.
    # Append a small build stamp so GitHub history stays visually aligned with JSON updates.
    publishable_latest = _is_publishable_latest(cert)
    json_out, html_out, target_json_name, audit_label, verify_command = _select_latest_output_targets(
        publishable_latest=publishable_latest,
        result=result,
    )
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, ensure_ascii=False)

    try:
        _write_primary_audit_html(
            cert,
            html_out=html_out,
            target_json_name=target_json_name,
            audit_label=audit_label,
            verify_command=verify_command,
        )
        print(f"OK: HTML written from proofs/template.html (with build stamp) → {html_out}")
    except Exception as e:
        print(f"WARNING: HTML generation failed: {e}")

    if _is_publishable_latest_live(cert):
        try:
            _publish_latest_live(cert)
            print("OK: Latest live HTML written from proofs/template.html → proofs/latest-live-audit.html")
        except Exception as e:
            print(f"WARNING: latest live HTML generation failed: {e}")
        print("OK: Latest live proof → proofs/latest-live-audit.json + proofs/latest-live-audit.html")
        print("OUTPUT_LIVE_AUDIT_UPDATED=true")
    else:
        print("OUTPUT_LIVE_AUDIT_UPDATED=false")

    print(f"OK: Certificate → {archival}")
    if json_out.endswith("latest-audit.json"):
        print("OK: Latest proof → proofs/latest-audit.json + proofs/latest-audit.html")
        print("OUTPUT_AUDIT_JSON=proofs/latest-audit.json")
    else:
        print("OK: Local proof only → proofs/local-audit.json + proofs/local-audit.html")
        print("INFO: Canonical latest-audit.* not updated (missing attributable provenance fields).")
        print("OUTPUT_AUDIT_JSON=proofs/local-audit.json")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate and sign a certificate for the current run.")
    parser.add_argument("--ledger", help="ITGL ledger for this run (normally must equal run_summary.ledger_path).")
    parser.add_argument(
        "--allow-detached-ledger",
        action="store_true",
        help="Allow --ledger outside the run's canonical path and mark the signed payload as detached.",
    )
    args = parser.parse_args()
    main(args.ledger, args.allow_detached_ledger)
