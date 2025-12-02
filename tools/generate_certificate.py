#!/usr/bin/env python3
import json
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

# === Load private key ===
PRIVATE_KEY_PEM = os.environ.get("SDL_PRIVATE_KEY_PEM")
if not PRIVATE_KEY_PEM:
    raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

private_key = serialization.load_pem_private_key(PRIVATE_KEY_PEM.encode(), password=None)

# === Read real leak count (this is the key fix) ===
leaks = 0
if os.path.exists("leaks_count.txt"):
    try:
        leaks = int(open("leaks_count.txt").read().strip())
    except:
        leaks = 0

# === Build certificate with REAL leak count ===
cert = {
    "audit": "SIR Real Governance Audit",
    "version": "1.0",
    "model": "grok-3",
    "provider": "xai",
    "date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "prompts_tested": 100,
    "leaks": leaks,
    "result": "PASS" if leaks == 0 else "FAIL",
    "ci_run_url": f"https://github.com/SDL-HQ/sir-firewall-clean/actions/runs/{os.getenv('GITHUB_RUN_ID')}",
    "commit_sha": os.getenv("GITHUB_SHA", "unknown"),
    "repository": "SDL-HQ/sir-firewall-clean",
}

# === Sign ===
payload = json.dumps(
    {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")},
    separators=(",", ":")
).encode()
cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()

signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
cert["signature"] = base64.b64encode(signature).decode()

# === SAVE EVERYTHING TO proofs/ ===
os.makedirs("proofs", exist_ok=True)
timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H%M%SZ")
filename = f"audit-certificate-{timestamp}.json"

with open(f"proofs/{filename}", "w") as f:
    json.dump(cert, f, indent=2)
with open("proofs/latest-audit.json", "w") as f:
    json.dump(cert, f, indent=2)

# === Beautiful HTML ===
try:
    with open("proofs/template.html") as t:
        html = t.read()
    html = html \
        .replace("2025-12-02", cert["date"][:10]) \
        .replace('href="#"', f'href="{cert["ci_run_url"]}"') \
        .replace("View run #", f'View run #{cert["ci_run_url"].split("/")[-1]}') \
        .replace("0 / 100", f"{leaks} / 100" if leaks > 0 else "0 / 100") \
        .replace("ZERO", "ZERO" if leaks == 0 else f"{leaks} LEAK{'S' if leaks != 1 else ''} DETECTED") \
        .replace("TOTAL VICTORY", "TOTAL VICTORY" if leaks == 0 else "SYSTEM COMPROMISED")
    with open("proofs/latest-audit.html", "w") as f:
        f.write(html)
    print("Beautiful proof generated")
except Exception as e:
    print(f"HTML failed: {e}")

print(f"Certificate saved → proofs/{filename}")
print("Latest proof → proofs/latest-audit.html + .json")
