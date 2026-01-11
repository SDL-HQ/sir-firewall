#!/usr/bin/env python3
"""
SIR Firewall — Local Audit Runner (one command)

Runs the same local flow that humans trip over if undocumented:
- Validate suite CSV schema
- Run red_team_suite.py (default: --no-model-calls)
- Verify ITGL and export ITGL_FINAL_HASH (writes itgl_env.txt)
- (Optional) sign policy + generate cert
- (Optional) verify cert (supports local pubkey)
- Archive run (publish_run.py)
- (Optional) serve proofs over HTTP so HTML loads (avoids file:// fetch issues)

This does NOT replace CI. It's a local UX wrapper.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], env: Optional[dict[str, str]] = None) -> None:
    print(f"\n$ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=True)


def _capture(cmd: list[str], env: Optional[dict[str, str]] = None) -> str:
    print(f"\n$ {' '.join(cmd)}")
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = p.stdout or ""
    print(out, end="" if out.endswith("\n") else "\n")
    return out


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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
        help="Signing mode: none (default), sdl (requires SDL_PRIVATE_KEY_PEM), local (generates local RSA key).",
    )
    ap.add_argument("--serve", action="store_true", help="Serve proofs via http.server after run (so HTML loads).")
    ap.add_argument("--port", type=int, default=8000, help="Port for --serve (default 8000).")
    args = ap.parse_args()

    env = dict(os.environ)
    env["SIR_SUITE_PATH"] = args.suite
    env["SIR_TEMPLATE_ID"] = args.template_id

    # 1) Validate suite schema
    _run([sys.executable, "tools/validate_domain_pack.py", "--file", args.suite], env=env)

    # 2) Run suite
    suite_cmd = [sys.executable, "red_team_suite.py", "--suite", args.suite]
    if args.model_calls:
        # no flag added (red_team_suite.py defaults depend on your implementation)
        pass
    else:
        suite_cmd.append("--no-model-calls")
    _run(suite_cmd, env=env)

    # 3) Verify ITGL, export ITGL_FINAL_HASH, write itgl_env.txt
    itgl_out = _capture([sys.executable, "tools/verify_itgl.py"], env=env)
    itgl_env_path = REPO_ROOT / "itgl_env.txt"
    _write_text(itgl_env_path, itgl_out)

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

    # 4) Optional signing + cert generation
    local_pubkey: Optional[str] = None

    if args.sign == "sdl":
        if not env.get("SDL_PRIVATE_KEY_PEM", "").strip():
            print("ERROR: --sign sdl requires SDL_PRIVATE_KEY_PEM in your environment", file=sys.stderr)
            return 2
        _run([sys.executable, "tools/sign_policy.py"], env=env)
        _run([sys.executable, "tools/generate_certificate.py"], env=env)

        # verify against default SDL pubkey
        _run([sys.executable, "tools/verify_certificate.py", "proofs/latest-audit.json"], env=env)

    elif args.sign == "local":
        # Generate local keypair via openssl (present on macOS), store under local_keys/
        local_dir = REPO_ROOT / "local_keys"
        local_dir.mkdir(parents=True, exist_ok=True)
        priv = local_dir / "local_signing_key.pem"
        pub = local_dir / "local_signing_key.pub.pem"

        # Generate private key if missing
        if not priv.exists():
            _run(["openssl", "genrsa", "-out", str(priv), "2048"], env=env)

        # Derive public key
        _run(["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)], env=env)

        env["SDL_PRIVATE_KEY_PEM"] = priv.read_text(encoding="utf-8")
        local_pubkey = str(pub)

        _run([sys.executable, "tools/sign_policy.py"], env=env)
        _run([sys.executable, "tools/generate_certificate.py"], env=env)

        # Verify using local pubkey (avoids the "InvalidSignature" confusion)
        _run([sys.executable, "tools/verify_certificate.py", "proofs/latest-audit.json", "--pubkey", local_pubkey], env=env)

    else:
        print("\nSigning skipped (--sign none).")

    # 5) Archive run
    _run(
        [
            sys.executable,
            "tools/publish_run.py",
            "--cert",
            "proofs/latest-audit.json",
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

    # 6) Serve (optional) so HTML can fetch JSON locally
    if args.serve:
        port = int(args.port)
        print("\nServing repo for local HTML viewing (avoid file:// fetch restrictions):")
        print(f"  http://localhost:{port}/proofs/latest-audit.html")
        print(f"  http://localhost:{port}/proofs/runs/index.html\n")
        _run([sys.executable, "-m", "http.server", str(port)], env=env)

    print("\nOK: Local audit complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
