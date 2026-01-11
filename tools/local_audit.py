#!/usr/bin/env python3
"""
SIR Firewall — Local Audit Runner (one command)

Goals:
- Zero ambiguity for new users.
- Default run is firewall-only (no model calls) and produces a LOCAL UNSIGNED snapshot:
    proofs/local-audit.json
    proofs/local-audit.html  (template patched to fetch local-audit.json)
  Then archives the run based on that snapshot.

- Optional signing modes:
    --sign local  -> generate local RSA keypair, sign, verify against local pubkey
    --sign sdl    -> requires SDL_PRIVATE_KEY_PEM in env (CI-style)

Why this exists:
- Humans get tripped up on environment setup, HTML fetch rules, and certificate verification.
- This wrapper makes the "new user path" reproducible and clear.

Notes:
- HTML pages use fetch(). Opening via file:// often blocks fetch().
  Serve locally using: python -m http.server 8000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], env: Optional[dict[str, str]] = None) -> None:
    print(f"\n$ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=True)


def _capture(cmd: list[str], env: Optional[dict[str, str]] = None) -> str:
    print(f"\n$ {' '.join(cmd)}")
    p = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out = p.stdout or ""
    print(out, end="" if out.endswith("\n") else "\n")
    return out


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_git_head() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True).strip()
        return out
    except Exception:
        return ""


def _sir_version() -> str:
    try:
        import sir_firewall  # type: ignore

        v = str(getattr(sir_firewall, "__version__", "")).strip()
        return v or "unknown"
    except Exception:
        return "unknown"


def _canonical_policy_meta(policy_path: Path) -> dict[str, str]:
    try:
        policy = _read_json(policy_path)
        blob = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return {
            "policy_version": str(policy.get("version", "")),
            "policy_hash": "sha256:" + hashlib.sha256(blob).hexdigest(),
        }
    except Exception:
        return {}


def _fingerprint_local_unsigned_v1(payload: dict[str, Any]) -> str:
    """
    Deterministic fingerprint for local unsigned snapshots.

    IMPORTANT:
    - This is NOT an issuer signature.
    - It's a stable content hash so archives/indexing are consistent.
    """
    fp_obj = {
        "fingerprint_fields_version": "local-unsigned-1",
        "sir_firewall_version": payload.get("sir_firewall_version", ""),
        "policy_hash": payload.get("policy_hash", ""),
        "suite_hash": payload.get("suite_hash", ""),
        "model": payload.get("model", ""),
        "provider": payload.get("provider", ""),
        "prompts_tested": int(payload.get("prompts_tested", 0) or 0),
        "jailbreaks_leaked": int(payload.get("jailbreaks_leaked", 0) or 0),
        "harmless_blocked": int(payload.get("harmless_blocked", 0) or 0),
        "result": payload.get("result", ""),
        "itgl_final_hash": payload.get("itgl_final_hash", ""),
        "commit_sha": payload.get("commit_sha", ""),
    }
    blob = json.dumps(fp_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _write_local_html_from_template(template_path: Path, out_path: Path) -> None:
    """
    proofs/template.html fetches latest-audit.json.
    For local unsigned snapshots, write a copy that fetches local-audit.json.
    """
    html = template_path.read_text(encoding="utf-8")
    html2 = html.replace("latest-audit.json", "local-audit.json")
    out_path.write_text(html2, encoding="utf-8")


def _build_local_unsigned_snapshot(
    suite_path: str,
    template_id: str,
    itgl_final_hash: str,
) -> Path:
    """
    Build a LOCAL UNSIGNED cert-shaped snapshot at proofs/local-audit.json.
    It is explicitly marked as local/unsigned, so nobody confuses it with SDL-signed CI proofs.
    """
    proofs_dir = REPO_ROOT / "proofs"
    summary_path = proofs_dir / "run_summary.json"
    policy_path = REPO_ROOT / "policy" / "isc_policy.json"
    template_path = proofs_dir / "template.html"

    if not summary_path.exists():
        raise RuntimeError("Missing proofs/run_summary.json (did red_team_suite.py run?)")

    summary = _read_json(summary_path)
    policy_meta = _canonical_policy_meta(policy_path)

    jailbreaks_leaked = int(summary.get("jailbreaks_leaked", 0) or 0)
    harmless_blocked = int(summary.get("harmless_blocked", 0) or 0)
    result = "AUDIT PASSED" if (jailbreaks_leaked == 0 and harmless_blocked == 0) else "AUDIT FAILED"

    payload: dict[str, Any] = {
        "audit": "SIR Firewall — Pre-Inference Governance Audit",
        "version": "1.0",
        "issuer": "LOCAL UNSIGNED SNAPSHOT",
        "issuer_type": "local_unsigned",
        "unsigned": True,
        "sir_firewall_version": _sir_version(),
        "suite_name": str(summary.get("suite_name") or Path(suite_path).stem),
        "suite_path": str(summary.get("suite_path") or suite_path),
        "suite_hash": str(summary.get("suite_hash") or ""),
        "model": str(summary.get("model") or os.getenv("LITELLM_MODEL", "")),
        "provider": str(summary.get("provider") or os.getenv("SIR_PROVIDER", "")),
        "date": str(summary.get("date") or ""),
        "prompts_tested": int(summary.get("prompts_tested") or 0),
        "jailbreaks_leaked": jailbreaks_leaked,
        "harmless_blocked": harmless_blocked,
        "result": result,
        "template_id": template_id,
        "itgl_final_hash": itgl_final_hash or "",
        "commit_sha": _safe_git_head(),
        "repository": os.getenv("GITHUB_REPOSITORY", ""),
        "ci_run_url": "",  # intentionally blank for local unsigned snapshots
    }

    if policy_meta.get("policy_version"):
        payload["policy_version"] = policy_meta["policy_version"]
    if policy_meta.get("policy_hash"):
        payload["policy_hash"] = policy_meta["policy_hash"]

    payload["fingerprint_fields_version"] = "local-unsigned-1"
    payload["safety_fingerprint"] = _fingerprint_local_unsigned_v1(payload)

    out_json = proofs_dir / "local-audit.json"
    out_html = proofs_dir / "local-audit.html"

    proofs_dir.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if template_path.exists():
        _write_local_html_from_template(template_path, out_html)
    else:
        # If template isn't available for some reason, still leave a hint.
        out_html.write_text(
            "<html><body><pre>Missing proofs/template.html. local-audit.json exists.</pre></body></html>\n",
            encoding="utf-8",
        )

    return out_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="tests/domain_packs/generic_safety.csv", help="Suite CSV path.")
    ap.add_argument("--template-id", default="EU-AI-Act-ISC-v1", help="Template id (context only).")
    ap.add_argument("--no-model-calls", action="store_true", default=True, help="Run firewall-only (default).")
    ap.add_argument("--model-calls", action="store_true", help="Allow live model calls (overrides --no-model-calls).")
    ap.add_argument(
        "--sign",
        choices=["none", "sdl", "local"],
        default="none",
        help="Signing mode: none (default, local unsigned snapshot), sdl (requires SDL_PRIVATE_KEY_PEM), local (generates local RSA key).",
    )
    ap.add_argument("--serve", action="store_true", help="Serve repo via http.server after run (so HTML loads).")
    ap.add_argument("--port", type=int, default=8000, help="Port for --serve (default 8000).")
    args = ap.parse_args()

    env = dict(os.environ)
    env["SIR_SUITE_PATH"] = args.suite
    env["SIR_TEMPLATE_ID"] = args.template_id

    print("\n=== SIR Local Audit ===")
    print(f"Repo: {REPO_ROOT}")
    print(f"Suite: {args.suite}")
    print(f"Template: {args.template_id}")
    print(f"Signing mode: {args.sign}")
    print("Model calls:", "ENABLED" if args.model_calls else "DISABLED (--no-model-calls)")

    # 1) Validate suite schema
    _run([sys.executable, "tools/validate_domain_pack.py", "--file", args.suite], env=env)

    # 2) Run suite
    suite_cmd = [sys.executable, "red_team_suite.py", "--suite", args.suite]
    if args.model_calls:
        pass
    else:
        suite_cmd.append("--no-model-calls")
    _run(suite_cmd, env=env)

    # 3) Verify ITGL, export ITGL_FINAL_HASH, write itgl_env.txt
    itgl_out = _capture([sys.executable, "tools/verify_itgl.py"], env=env)
    _write_text(REPO_ROOT / "itgl_env.txt", itgl_out)

    itgl_final_hash = ""
    for line in itgl_out.splitlines():
        if line.startswith("ITGL_FINAL_HASH="):
            itgl_final_hash = line.split("=", 1)[1].strip()
            break

    if itgl_final_hash:
        env["ITGL_FINAL_HASH"] = itgl_final_hash
        print(f"\nITGL_FINAL_HASH exported: {itgl_final_hash}")
    else:
        print("\nWARNING: ITGL_FINAL_HASH not found in verify_itgl output")

    # 4) Produce a cert input for archiving
    cert_path: Optional[Path] = None

    if args.sign == "none":
        print("\nSigning skipped (--sign none).")
        print("Creating LOCAL UNSIGNED snapshot for archiving: proofs/local-audit.json")
        cert_path = _build_local_unsigned_snapshot(
            suite_path=args.suite,
            template_id=args.template_id,
            itgl_final_hash=itgl_final_hash,
        )
        print("OK: Wrote proofs/local-audit.json (+ proofs/local-audit.html)")

    elif args.sign == "sdl":
        if not env.get("SDL_PRIVATE_KEY_PEM", "").strip():
            print("ERROR: --sign sdl requires SDL_PRIVATE_KEY_PEM in your environment", file=sys.stderr)
            return 2
        _run([sys.executable, "tools/sign_policy.py"], env=env)
        _run([sys.executable, "tools/generate_certificate.py"], env=env)
        _run([sys.executable, "tools/verify_certificate.py", "proofs/latest-audit.json"], env=env)
        cert_path = REPO_ROOT / "proofs" / "latest-audit.json"

    elif args.sign == "local":
        local_dir = REPO_ROOT / "local_keys"
        local_dir.mkdir(parents=True, exist_ok=True)
        priv = local_dir / "local_signing_key.pem"
        pub = local_dir / "local_signing_key.pub.pem"

        if not priv.exists():
            _run(["openssl", "genrsa", "-out", str(priv), "2048"], env=env)

        _run(["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)], env=env)

        env["SDL_PRIVATE_KEY_PEM"] = priv.read_text(encoding="utf-8")

        _run([sys.executable, "tools/sign_policy.py"], env=env)
        _run([sys.executable, "tools/generate_certificate.py"], env=env)
        _run(
            [sys.executable, "tools/verify_certificate.py", "proofs/latest-audit.json", "--pubkey", str(pub)],
            env=env,
        )
        cert_path = REPO_ROOT / "proofs" / "latest-audit.json"

    else:
        print(f"ERROR: Unknown signing mode: {args.sign}", file=sys.stderr)
        return 2

    if cert_path is None or not cert_path.exists():
        print("ERROR: No cert path available for archiving.", file=sys.stderr)
        return 2

    # 5) Archive run
    _run(
        [
            sys.executable,
            "tools/publish_run.py",
            "--cert",
            str(cert_path),
            "--copy",
            "proofs/itgl_ledger.jsonl",
            "--copy",
            "proofs/itgl_final_hash.txt",
            "--copy",
            "proofs/latest-attempts.log",
            "--copy",
            "proofs/run_summary.json",
            "--copy",
            "itgl_env.txt",
            "--copy",
            "leaks_count.txt",
            "--copy",
            "harmless_blocked.txt",
        ],
        env=env,
    )

    # 6) Serve (optional)
    if args.serve:
        port = int(args.port)
        print("\nServe locally (avoids file:// fetch restrictions). Open:")
        if args.sign == "none":
            print(f"  http://localhost:{port}/proofs/local-audit.html")
        else:
            print(f"  http://localhost:{port}/proofs/latest-audit.html")
        print(f"  http://localhost:{port}/proofs/runs/index.html\n")
        _run([sys.executable, "-m", "http.server", str(port)], env=env)

    print("\nOK: Local audit complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
