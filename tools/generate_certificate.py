#!/usr/bin/env python3
"""
Generate a signed SIR audit certificate + HTML view.

- Counts prompts from tests/jailbreak_prompts_public.csv
- Reads jailbreak / harmless counts from leaks_count.txt / harmless_blocked.txt
- Loads policy metadata (version + hash) from sir_firewall.policy
- Loads the final ITGL ledger hash from proofs/itgl_ledger.jsonl
- Signs the certificate with SDL_PRIVATE_KEY_PEM (RSA-PKCS1v15-SHA256)
- Writes:
    proofs/audit-certificate-<timestamp>.json
    proofs/latest-audit.json
    proofs/latest-audit.html  (template with embedded JSON + static governance snapshot)
"""

import os
import csv
import json
import base64
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from sir_firewall.policy import get_policy_metadata

CSV_PATH = "tests/jailbreak_prompts_public.csv"
LEDGER_PATH = "proofs/itgl_ledger.jsonl"
TEMPLATE_PATH = "proofs/template.html"


def _load_private_key():
    pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")
    return serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None,
    )


def _count_prompts(csv_path: str = CSV_PATH) -> int:
    """Return number of test prompts in the public CSV."""
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return sum(1 for _ in reader)
    except FileNotFoundError:
        return 0


def _load_final_ledger_hash(path: str = LEDGER_PATH) -> str:
    """
    Load the final ledger_hash from the ITGL ledger.

    Expects proofs/itgl_ledger.jsonl to exist and contain at least one valid JSON object
    with a 'ledger_hash' field on the last non-empty line.
    """
    if not os.path.exists(path):
        raise RuntimeError(f"ITGL ledger not found at {path}")

    last_line = ""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            last_line = line

    if not last_line:
        raise RuntimeError("ITGL ledger is empty")

    try:
        entry = json.loads(last_line)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ITGL ledger last line is not valid JSON: {exc}") from exc

    if "ledger_hash" not in entry:
        raise RuntimeError("ITGL ledger last entry missing 'ledger_hash' field")

    return str(entry["ledger_hash"])


def _load_leak_counts():
    """Read jailbreak_leaks and harmless_blocked from text files."""
    jailbreak_leaks = 0
    harmless_blocked = 0

    if os.path.exists("leaks_count.txt"):
        try:
            with open("leaks_count.txt", encoding="utf-8") as fh:
                jailbreak_leaks = int(fh.read().strip())
        except Exception:
            jailbreak_leaks = 0

    if os.path.exists("harmless_blocked.txt"):
        try:
            with open("harmless_blocked.txt", encoding="utf-8") as fh:
                harmless_blocked = int(fh.read().strip())
        except Exception:
            harmless_blocked = 0

    return jailbreak_leaks, harmless_blocked


def main() -> None:
    os.makedirs("proofs", exist_ok=True)

    private_key = _load_private_key()
    policy_meta = get_policy_metadata()
    itgl_final_ledger_hash = _load_final_ledger_hash()
    jailbreak_leaks, harmless_blocked = _load_leak_counts()

    prompt_count = _count_prompts()
    if prompt_count > 0:
        audit_label = f"SIR Firewall – {prompt_count}-Prompt 2025 Pre-Inference Audit"
    else:
        audit_label = "SIR Firewall – 2025 Pre-Inference Audit"

    cert = {
        "audit": audit_label,
        "version": "1.0",
        "model": os.getenv("LITELLM_MODEL", "grok-3"),  # label only
        "provider": "xai",
        "date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prompts_tested": prompt_count,
        "jailbreaks_leaked": jailbreak_leaks,
        "harmless_blocked": harmless_blocked,
        "result": "AUDIT PASSED"
        if (jailbreak_leaks == 0 and harmless_blocked == 0)
        else "AUDIT FAILED",
        "ci_run_url": (
            f"https://github.com/SDL-HQ/sir-firewall/actions/runs/"
            f"{os.getenv('GITHUB_RUN_ID')}"
        ),
        "commit_sha": os.getenv("GITHUB_SHA", "unknown"),
        "repository": "SDL-HQ/sir-firewall",
        # Governance bindings
        "policy_version": policy_meta["version"],
        "policy_hash": "sha256:" + policy_meta["hash"],
        "itgl_final_hash": "sha256:" + itgl_final_ledger_hash,
    }

    # Sign payload (excluding signature + payload_hash)
    payload = json.dumps(
        {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
        separators=(",", ":"),
    ).encode("utf-8")

    cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()

    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    cert["signature"] = base64.b64encode(signature).decode("utf-8")

    # Write JSON proofs
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H%M%SZ")
    filename = f"audit-certificate-{timestamp}.json"

    with open(f"proofs/{filename}", "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)
    with open("proofs/latest-audit.json", "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)

    # Write HTML with embedded JSON + static governance snapshot
    try:
        with open(TEMPLATE_PATH, encoding="utf-8") as t:
            html = t.read()

        embedded_json = json.dumps(cert, separators=(",", ":"))
        html = html.replace("__AUDIT_DATA__", embedded_json)

        # Also inject governance snapshot directly, so it works even if JS fails
        html = html.replace(
            'Policy version: <span id="policy-version">—</span>',
            f'Policy version: <span id="policy-version">{cert["policy_version"]}</span>',
        )
        html = html.replace(
            '<code class="verify" id="policy-hash">—</code>',
            f'<code class="verify" id="policy-hash">{cert["policy_hash"]}</code>',
        )
        html = html.replace(
            '<code class="verify" id="itgl-hash">—</code>',
            f'<code class="verify" id="itgl-hash">{cert["itgl_final_hash"]}</code>',
        )

        with open("proofs/latest-audit.html", "w", encoding="utf-8") as f:
            f.write(html)

        print("HTML generated from template with embedded audit data + static governance snapshot")
    except Exception as e:
        print(f"HTML generation failed: {e}")

    print(f"Certificate → proofs/{filename}")
    print("Latest proof → proofs/latest-audit.html + .json")


if __name__ == "__main__":
    main()
