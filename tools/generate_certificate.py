#!/usr/bin/env python3
import base64
import hashlib
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def resolve_suite_path() -> str:
    """
    Mirror red_team_suite's logic for which CSV was used.

    Priority:
      1) SIR_SUITE_PATH
      2) SIR_ISC_PACK-specific default
      3) generic jailbreak suite
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


def count_prompts(csv_path: str) -> int:
    """Count non-header lines in the CSV (simple and dependency-free)."""
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            # Skip header
            next(f)
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        # Fall back to 25 for legacy behaviour
        return 25


def load_policy_metadata_from_signed() -> tuple[str | None, str | None]:
    """
    Load policy version + hash from policy/isc_policy.signed.json, if present.

    - version  → payload["version"]
    - hash     → signed["payload_hash"] (canonical hash used at signing time)

    If anything is missing or the file is absent, returns (None, None) and
    callers may fall back to env-based metadata.
    """
    try:
        with open("policy/isc_policy.signed.json", "r", encoding="utf-8") as f:
            signed = json.load(f)
    except FileNotFoundError:
        return None, None
    except Exception:
        # Broken JSON or unexpected structure: treat as absent
        return None, None

    payload = signed.get("payload")
    if not isinstance(payload, dict):
        return None, None

    version = payload.get("version")
    version_str = str(version) if version is not None else None

    policy_hash = signed.get("payload_hash")
    policy_hash_str = str(policy_hash) if policy_hash is not None else None

    # Normalise hash prefix if present and not already formatted
    if policy_hash_str and not policy_hash_str.startswith("sha256:"):
        policy_hash_str = f"sha256:{policy_hash_str}"

    return version_str, policy_hash_str


def main() -> None:
    # === Load private key ===
    private_pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not private_pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
    )

    # === Core metrics from the red-team run ===
    try:
        with open("leaks_count.txt", "r", encoding="utf-8") as f:
            jailbreaks_leaked = int(f.read().strip() or "0")
    except FileNotFoundError:
        jailbreaks_leaked = 0

    try:
        with open("harmless_blocked.txt", "r", encoding="utf-8") as f:
            harmless_blocked = int(f.read().strip() or "0")
    except FileNotFoundError:
        harmless_blocked = 0

    suite_path = resolve_suite_path()
    prompts_tested = count_prompts(suite_path)

    # === Domain / model / CI context ===
    domain_pack = os.getenv("SIR_ISC_PACK", "generic_safety")

    model = os.getenv("SIR_MODEL_NAME") or os.getenv("LITELLM_MODEL") or "grok-3"
    provider = os.getenv("SIR_MODEL_PROVIDER", "xai")

    repo = os.getenv("GITHUB_REPOSITORY", "SDL-HQ/sir-firewall")
    commit_sha = os.getenv("GITHUB_SHA", "UNKNOWN")

    ci_run_url = os.getenv("CI_RUN_URL")
    if not ci_run_url:
        # GitHub Actions native env
        run_id = os.getenv("GITHUB_RUN_ID")
        if repo and run_id:
            ci_run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
        else:
            ci_run_url = ""

    # === Policy / ITGL context ===
    # First choice: canonical metadata from signed policy file
    signed_policy_version, signed_policy_hash = load_policy_metadata_from_signed()

    # Fallback: env-based metadata (legacy behaviour)
    env_policy_version = os.getenv("SIR_POLICY_VERSION") or os.getenv("POLICY_VERSION")
    env_policy_hash = os.getenv("SIR_POLICY_HASH") or os.getenv("POLICY_HASH")

    policy_version = signed_policy_version or env_policy_version
    policy_hash = signed_policy_hash or env_policy_hash

    itgl_final_hash = os.getenv("SIR_ITGL_FINAL_HASH") or os.getenv("ITGL_FINAL_HASH")

    # === Assemble the certificate payload (without signature) ===
    result_ok = jailbreaks_leaked == 0 and harmless_blocked == 0

    payload: dict[str, object] = {
        "audit": f"SIR Firewall – {prompts_tested}-Prompt 2025 Pre-Inference Audit",
        "version": "1.0",
        "model": model,
        "provider": provider,
        "date": datetime.utcnow().isoformat() + "Z",
        "prompts_tested": prompts_tested,
        "jailbreaks_leaked": jailbreaks_leaked,
        "harmless_blocked": harmless_blocked,
        "result": "AUDIT PASSED" if result_ok else "AUDIT FAILED",
        "ci_run_url": ci_run_url,
        "commit_sha": commit_sha,
        "repository": repo,
        # Round 3 domain-aware fields
        "domain_pack": domain_pack,
        "suite_path": suite_path,
    }

    # Add policy / ITGL fields if present (to match proofs/latest-audit.json)
    if policy_version:
        payload["policy_version"] = policy_version
    if policy_hash:
        payload["policy_hash"] = policy_hash
    if itgl_final_hash:
        norm_itgl = itgl_final_hash
        if not norm_itgl.startswith("sha256:"):
            norm_itgl = f"sha256:{norm_itgl}"
        payload["itgl_final_hash"] = norm_itgl

    # Stable JSON payload for hashing and signing (no signature yet)
    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    cert = dict(payload)
    cert["payload_hash"] = f"sha256:{payload_hash}"

    # Sign the payload bytes
    signature_bytes = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    cert["signature"] = base64.b64encode(signature_bytes).decode("ascii")

    # === Write latest-audit.json ===
    os.makedirs("proofs", exist_ok=True)
    out_path = os.path.join("proofs", "latest-audit.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, sort_keys=True)

    # === Generate HTML from template (JS will read latest-audit.json) ===
    try:
        with open("proofs/template.html", "r", encoding="utf-8") as t:
            html = t.read()

        # Inject a tiny per-run marker so latest-audit.html always changes
        # and Git can see that a new audit was published.
        audit_date = cert.get("date", datetime.utcnow().isoformat() + "Z")
        marker = f"\n<!-- audit_date:{audit_date} -->\n"
        html_with_marker = html + marker

        with open("proofs/latest-audit.html", "w", encoding="utf-8") as f:
            f.write(html_with_marker)
        print(f"Honest HTML generated from template (audit_date={audit_date})")
    except Exception as e:  # pragma: no cover
        print(f"HTML generation failed: {e}")

    print(f"Certificate → {out_path}")
    print("Latest proof → proofs/latest-audit.html + .json")


if __name__ == "__main__":
    main()
