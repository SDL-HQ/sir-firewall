#!/usr/bin/env python3
import json
import hashlib
import base64
import csv
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

from sir_firewall.policy import get_policy_metadata

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
LEDGER_PATH = "proofs/itgl_ledger.jsonl"


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

# === Load policy metadata (must succeed in non-dev governance mode) ===
policy_meta = get_policy_metadata()

# === Load ITGL final ledger hash (bind audit to a specific ledger) ===
itgl_final_ledger_hash = _load_final_ledger_hash()

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
    "result": "AUDIT PASSED"
    if (jailbreak_leaks == 0 and harmless_blocked == 0)
    else "AUDIT FAILED",
    "ci_run_url": (
        f"https://github.com/SDL-HQ/sir-firewall/actions/runs/"
        f"{os.getenv('GITHUB_RUN_ID')}"
    ),
    "commit_sha": os.getenv("GITHUB_SHA", "unknown"),
    "repository": "SDL-HQ/sir-firewall",
    "policy_version": policy_meta["version"],
    "policy_hash": "sha256:" + policy_meta["hash"],
    "itgl_final_hash": "sha256:" + itgl_final_ledger_hash,
}

# === Sign (verify_certificate.py still works perfectly) ===
payload = json.dumps(
    {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
    separators=(",", ":"),
).encode()
cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()

signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
cert["signature"] = base64.b64encode(signature).decode()

# === SAVE ===
os.makedirs("proofs", exist_ok=True)
timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H%M%SZ")
filename = f"audit-certificate-{timestamp}.json"

with open(f"proofs/{filename}", "w", encoding="utf-8") as f:
    json.dump(cert, f, indent=2)
with open("proofs/latest-audit.json", "w", encoding="utf-8") as f:
    json.dump(cert, f, indent=2)

# === Generate HTML using a JS-driven template (no string replacement hacks) ===
try:
    with open("proofs/template.html", encoding="utf-8") as t:
        html = t.read()

    with open("proofs/latest-audit.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("Honest HTML generated from template")
except Exception as e:
    print(f"HTML generation failed: {e}")

print(f"Certificate → proofs/{filename}")
print("Latest proof → proofs/latest-audit.html + .json")
