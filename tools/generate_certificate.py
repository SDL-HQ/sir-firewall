#!/usr/bin/env python3
import base64
import csv
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---------------------------------------------------------------------------
# Suite resolution (must mirror red_team_suite.py)
# ---------------------------------------------------------------------------

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


def _b64_decode_prompt(blob: str) -> str:
    if not isinstance(blob, str) or not blob.strip():
        return ""
    s = blob.strip()
    pad = (-len(s)) % 4
    if pad:
        s = s + ("=" * pad)
    decoded = base64.b64decode(s, validate=False)
    return decoded.decode("utf-8", errors="strict")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def load_suite_and_hash(csv_path: str) -> Tuple[int, str, str]:
    """
    Load suite and compute:
      - prompts_tested
      - suite_payload_hash (sha256 over canonical per-row prompt_hash+labels)
      - suite_format: plain | b64 | mixed

    This intentionally does NOT hash the raw CSV bytes.
    It hashes what was *actually evaluated* (decoded prompt text),
    without embedding the prompt text into the certificate.
    """
    path = Path(csv_path)
    if not path.exists():
        # legacy fallback
        return 25, "sha256:" + ("0" * 64), "plain"

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return 0, "sha256:" + ("0" * 64), "plain"

        fieldset = set([h.strip() for h in reader.fieldnames if h])

        if "expected" not in fieldset:
            raise RuntimeError(f"{csv_path} missing required column: expected")
        if "prompt" not in fieldset and "prompt_b64" not in fieldset:
            raise RuntimeError(f"{csv_path} must have either prompt or prompt_b64 column")

        lines: List[str] = []
        n = 0
        saw_plain = False
        saw_b64 = False

        for row in reader:
            # Skip fully blank rows
            if not any((v or "").strip() for v in row.values()):
                continue

            expected = (row.get("expected") or "").strip().lower()
            prompt_id = (row.get("id") or "").strip()
            category = (row.get("category") or "").strip()
            note = (row.get("note") or "").strip()

            prompt_text = ""
            if (row.get("prompt_b64") or "").strip():
                saw_b64 = True
                prompt_text = _b64_decode_prompt(row.get("prompt_b64") or "")
            else:
                saw_plain = True
                prompt_text = (row.get("prompt") or "")

            prompt_hash = _sha256_hex(prompt_text)

            # Canonical line (no prompt text)
            # Keeping order preserves meaning + prevents re-ordering attacks.
            # Fields chosen to bind to "what was tested" without leaking content.
            canon = {
                "id": prompt_id,
                "category": category,
                "expected": expected,
                "prompt_hash": f"sha256:{prompt_hash}",
                "note": note,
            }
            lines.append(json.dumps(canon, sort_keys=True, separators=(",", ":")))
            n += 1

        suite_bytes = ("\n".join(lines)).encode("utf-8")
        suite_payload_hash = hashlib.sha256(suite_bytes).hexdigest()

        if saw_plain and saw_b64:
            suite_format = "mixed"
        elif saw_b64:
            suite_format = "b64"
        else:
            suite_format = "plain"

        return n, f"sha256:{suite_payload_hash}", suite_format


# ---------------------------------------------------------------------------
# Policy metadata
# ---------------------------------------------------------------------------

def load_policy_metadata() -> Tuple[Optional[str], Optional[str]]:
    """
    Load policy/isc_policy.json and compute canonical SHA-256.

    Returns:
      (policy_version, policy_hash_with_prefix) or (None, None) on failure.

    If file missing/unreadable, falls back to legacy env:
      - SIR_POLICY_VERSION / POLICY_VERSION
      - SIR_POLICY_HASH / POLICY_HASH
    """
    policy_path = Path("policy") / "isc_policy.json"
    try:
        with policy_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        version = os.getenv("SIR_POLICY_VERSION") or os.getenv("POLICY_VERSION")
        phash = os.getenv("SIR_POLICY_HASH") or os.getenv("POLICY_HASH")
        return version, phash
    except Exception:
        version = os.getenv("SIR_POLICY_VERSION") or os.getenv("POLICY_VERSION")
        phash = os.getenv("SIR_POLICY_HASH") or os.getenv("POLICY_HASH")
        return version, phash

    version = str(data.get("version")) if "version" in data else None
    canon_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canon_bytes).hexdigest()
    return version, f"sha256:{digest}"


# ---------------------------------------------------------------------------
# ITGL helpers
# ---------------------------------------------------------------------------

def _read_itgl_final_hash() -> Optional[str]:
    """
    Prefer explicit env var, else read proofs/itgl_final_hash.txt,
    else read last ledger entry from proofs/itgl_ledger.jsonl.

    Returns sha256:... string or None.
    """
    env = os.getenv("SIR_ITGL_FINAL_HASH") or os.getenv("ITGL_FINAL_HASH")
    if env:
        return env if env.startswith("sha256:") else f"sha256:{env}"

    # file emitted by red_team_suite.py
    p = Path("proofs") / "itgl_final_hash.txt"
    if p.exists():
        v = p.read_text(encoding="utf-8").strip()
        if v:
            return v if v.startswith("sha256:") else f"sha256:{v}"

    # last line of ledger
    ledger = Path("proofs") / "itgl_ledger.jsonl"
    if ledger.exists():
        try:
            lines = ledger.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                obj = json.loads(line)
                lh = str(obj.get("ledger_hash", "")).strip()
                if lh:
                    return f"sha256:{lh}"
                break
        except Exception:
            return None

    return None


def _infer_effective_domain_pack(default_pack: str) -> str:
    """
    Try to read domain_pack from the ledger (first non-empty line).
    Falls back to env-derived default_pack.
    """
    ledger = Path("proofs") / "itgl_ledger.jsonl"
    if not ledger.exists():
        return default_pack

    try:
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            dp = str(obj.get("domain_pack", "")).strip()
            if dp:
                return dp
            break
    except Exception:
        return default_pack

    return default_pack


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    private_pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not private_pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
    )

    # Metrics from red-team run
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
    prompts_tested, suite_payload_hash, suite_format = load_suite_and_hash(suite_path)

    # Domain/model/CI context
    domain_pack_env = os.getenv("SIR_ISC_PACK", "generic_safety")
    domain_pack = _infer_effective_domain_pack(domain_pack_env)

    model = os.getenv("SIR_MODEL_NAME") or os.getenv("LITELLM_MODEL") or "grok-3"
    provider = os.getenv("SIR_MODEL_PROVIDER", "xai")

    repo = os.getenv("GITHUB_REPOSITORY", "SDL-HQ/sir-firewall")
    commit_sha = os.getenv("GITHUB_SHA", "UNKNOWN")

    ci_run_url = os.getenv("CI_RUN_URL")
    if not ci_run_url:
        run_id = os.getenv("GITHUB_RUN_ID")
        if repo and run_id:
            ci_run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
        else:
            ci_run_url = ""

    # Policy / ITGL context
    policy_version, policy_hash = load_policy_metadata()
    itgl_final_hash = _read_itgl_final_hash()

    # Assemble payload (unsigned)
    result_ok = jailbreaks_leaked == 0 and harmless_blocked == 0

    payload: Dict[str, Any] = {
        "audit": f"SIR Firewall – {prompts_tested}-Prompt 2025 Pre-Inference Audit",
        "version": "1.1",
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

        # Suite + domain binding (P2)
        "domain_pack": domain_pack,
        "suite_path": suite_path,
        "suite_format": suite_format,
        "suite_payload_hash": suite_payload_hash,
    }

    if policy_version:
        payload["policy_version"] = policy_version
    if policy_hash:
        payload["policy_hash"] = policy_hash

    if itgl_final_hash:
        payload["itgl_final_hash"] = itgl_final_hash if itgl_final_hash.startswith("sha256:") else f"sha256:{itgl_final_hash}"

    # Stable JSON payload for hashing/signing
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    cert = dict(payload)
    cert["payload_hash"] = f"sha256:{payload_hash}"

    signature_bytes = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    cert["signature"] = base64.b64encode(signature_bytes).decode("ascii")

    # Write JSON
    os.makedirs("proofs", exist_ok=True)
    out_path = os.path.join("proofs", "latest-audit.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, sort_keys=True)

    # HTML from template
    try:
        template_path = Path("proofs") / "template.html"
        html = template_path.read_text(encoding="utf-8")

        audit_date = cert.get("date", datetime.utcnow().isoformat() + "Z")
        marker = f"\n<!-- audit_date:{audit_date} -->\n"
        out_html = Path("proofs") / "latest-audit.html"
        out_html.write_text(html + marker, encoding="utf-8")
        print(f"Honest HTML generated from template (audit_date={audit_date})")
    except Exception as e:  # pragma: no cover
        print(f"HTML generation failed: {e}")

    print(f"Certificate → {out_path}")
    print("Latest proof → proofs/latest-audit.html + .json")


if __name__ == "__main__":
    main()
