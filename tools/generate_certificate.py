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
# Suite/template resolution (must mirror red_team_suite.py)
# ---------------------------------------------------------------------------

def resolve_suite_path() -> str:
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

    Hashes *what was evaluated* (decoded prompt text),
    without embedding prompt text into the certificate.
    """
    path = Path(csv_path)
    if not path.exists():
        return 0, "sha256:" + ("0" * 64), "plain"

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
            if not any((v or "").strip() for v in row.values()):
                continue

            expected = (row.get("expected") or "").strip().lower()
            prompt_id = (row.get("id") or "").strip()
            category = (row.get("category") or "").strip()
            note = (row.get("note") or "").strip()

            if (row.get("prompt_b64") or "").strip():
                saw_b64 = True
                prompt_text = _b64_decode_prompt(row.get("prompt_b64") or "")
            else:
                saw_plain = True
                prompt_text = (row.get("prompt") or "")

            prompt_hash = _sha256_hex(prompt_text)

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
# Policy metadata (prefer signed policy wrapper if present)
# ---------------------------------------------------------------------------

def load_policy_metadata() -> Tuple[Optional[str], Optional[str]]:
    """
    Prefer policy/isc_policy.signed.json if present:
      - policy_version = signed["version"]
      - policy_hash    = signed["payload_hash"]  (hash of canonical unsigned policy payload)

    Else fallback to policy/isc_policy.json:
      - policy_hash = sha256(canonical unsigned policy json)
    """
    signed_path = Path("policy") / "isc_policy.signed.json"
    raw_path = Path("policy") / "isc_policy.json"

    if signed_path.exists():
        try:
            signed = json.loads(signed_path.read_text(encoding="utf-8"))
            version = str(signed.get("version")) if "version" in signed else None
            payload_hash = str(signed.get("payload_hash") or "").strip() or None
            if payload_hash and not payload_hash.startswith("sha256:"):
                payload_hash = f"sha256:{payload_hash}"
            return version, payload_hash
        except Exception:
            pass

    try:
        data = json.loads(raw_path.read_text(encoding="utf-8"))
        version = str(data.get("version")) if "version" in data else None
        canon_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(canon_bytes).hexdigest()
        return version, f"sha256:{digest}"
    except Exception:
        version = os.getenv("SIR_POLICY_VERSION") or os.getenv("POLICY_VERSION")
        phash = os.getenv("SIR_POLICY_HASH") or os.getenv("POLICY_HASH")
        return version, phash


# ---------------------------------------------------------------------------
# Domain pack hash
# ---------------------------------------------------------------------------

def _domain_pack_path_candidates(domain_pack: str) -> List[Path]:
    return [
        Path("src") / "sir_firewall" / "policy" / "isc_packs" / f"{domain_pack}.json",
        Path("sir_firewall") / "policy" / "isc_packs" / f"{domain_pack}.json",
    ]


def load_domain_pack_hash(domain_pack: str) -> Optional[str]:
    for p in _domain_pack_path_candidates(domain_pack):
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            canon = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            return f"sha256:{hashlib.sha256(canon).hexdigest()}"
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# ITGL helpers
# ---------------------------------------------------------------------------

def _read_itgl_final_hash() -> Optional[str]:
    env = os.getenv("SIR_ITGL_FINAL_HASH") or os.getenv("ITGL_FINAL_HASH")
    if env:
        return env if env.startswith("sha256:") else f"sha256:{env}"

    p = Path("proofs") / "itgl_final_hash.txt"
    if p.exists():
        v = p.read_text(encoding="utf-8").strip()
        if v:
            return v if v.startswith("sha256:") else f"sha256:{v}"

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


def _infer_from_ledger() -> Tuple[Optional[str], Optional[str]]:
    """
    Pull domain_pack + isc_template from the first ledger entry (source of truth).
    """
    ledger = Path("proofs") / "itgl_ledger.jsonl"
    if not ledger.exists():
        return None, None

    try:
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            dp = str(obj.get("domain_pack", "")).strip() or None
            tpl = str(obj.get("isc_template", "")).strip() or None
            return dp, tpl
    except Exception:
        return None, None

    return None, None


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

    try:
        jailbreaks_leaked = int(Path("leaks_count.txt").read_text(encoding="utf-8").strip() or "0")
    except Exception:
        jailbreaks_leaked = 0

    try:
        harmless_blocked = int(Path("harmless_blocked.txt").read_text(encoding="utf-8").strip() or "0")
    except Exception:
        harmless_blocked = 0

    suite_path = resolve_suite_path()
    prompts_tested, suite_payload_hash, suite_format = load_suite_and_hash(suite_path)

    ledger_domain_pack, ledger_template = _infer_from_ledger()
    domain_pack = ledger_domain_pack or os.getenv("SIR_ISC_PACK", "generic_safety")
    isc_template = ledger_template or resolve_template_id()

    domain_pack_hash = load_domain_pack_hash(domain_pack)

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

    policy_version, policy_hash = load_policy_metadata()
    itgl_final_hash = _read_itgl_final_hash()

    result_ok = jailbreaks_leaked == 0 and harmless_blocked == 0

    payload: Dict[str, Any] = {
        "audit": f"SIR Firewall – {prompts_tested}-Prompt 2025 Pre-Inference Audit",
        "version": "1.2",
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

        "domain_pack": domain_pack,
        "isc_template": isc_template,
        "suite_path": suite_path,
        "suite_format": suite_format,
        "suite_payload_hash": suite_payload_hash,
    }

    if domain_pack_hash:
        payload["domain_pack_hash"] = domain_pack_hash
    if policy_version:
        payload["policy_version"] = policy_version
    if policy_hash:
        payload["policy_hash"] = policy_hash
    if itgl_final_hash:
        payload["itgl_final_hash"] = itgl_final_hash if itgl_final_hash.startswith("sha256:") else f"sha256:{itgl_final_hash}"

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
    except Exception as e:
        print(f"HTML generation failed: {e}")

    print(f"Certificate → {out_path}")
    print("Latest proof → proofs/latest-audit.html + .json")


if __name__ == "__main__":
    main()
