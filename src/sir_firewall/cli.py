from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACK_REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"


def _run_py(script_rel: str, args: list[str]) -> int:
    script = ROOT / script_rel
    cmd = [sys.executable, str(script), *args]
    return subprocess.call(cmd, cwd=ROOT)


def _cmd_run(ns: argparse.Namespace) -> int:
    if ns.mode not in {"audit", "live", "scenario"}:
        raise SystemExit(f"ERROR: unsupported --mode {ns.mode}")

    argv: list[str] = []
    if ns.mode == "scenario":
        argv.extend(["--mode", "audit"])
    else:
        argv.extend(["--mode", ns.mode])

    if ns.pack:
        argv.extend(["--pack", ns.pack])
    if ns.suite:
        argv.extend(["--suite", ns.suite])
    if ns.scenario:
        argv.extend(["--scenario", ns.scenario])
    if ns.model:
        argv.extend(["--model", ns.model])
    if ns.template:
        argv.extend(["--template", ns.template])
    if ns.no_model_calls:
        argv.append("--no-model-calls")

    rc = _run_py("red_team_suite.py", argv)

    if rc == 0 and ns.mode == "scenario":
        summary_path = ROOT / "proofs" / "run_summary.json"
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                summary["proof_class"] = "SCENARIO_AUDIT"
                summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            except Exception:
                pass

    return rc


def _cmd_verify_cert(ns: argparse.Namespace) -> int:
    args = [ns.path]
    if ns.key:
        args.extend(["--pubkey", ns.key])
    if ns.key_registry:
        args.extend(["--key-registry", ns.key_registry])
    return _run_py("tools/verify_certificate.py", args)


def _cmd_verify_archive(ns: argparse.Namespace) -> int:
    args = [ns.path]
    if ns.key:
        args.extend(["--pubkey", ns.key])
    if ns.key_registry:
        args.extend(["--key-registry", ns.key_registry])
    return _run_py("tools/verify_archive_receipt.py", args)


def _load_registry() -> dict:
    return json.loads(PACK_REGISTRY.read_text(encoding="utf-8"))


def _cmd_packs_list(_: argparse.Namespace) -> int:
    reg = _load_registry()
    for pack in reg.get("packs", []):
        pid = pack.get("pack_id", "")
        schema = pack.get("schema", "")
        status = pack.get("status", "")
        print(f"{pid}\t{schema}\t{status}")
    return 0


def _cmd_packs_show(ns: argparse.Namespace) -> int:
    reg = _load_registry()
    for pack in reg.get("packs", []):
        if pack.get("pack_id") == ns.pack_id:
            print(json.dumps(pack, indent=2))
            return 0
    print(f"ERROR: unknown pack_id {ns.pack_id}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sir")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run")
    run.add_argument("--mode", choices=["audit", "live", "scenario"], default="audit")
    run.add_argument("--pack", default=None)
    run.add_argument("--suite", default=None)
    run.add_argument("--scenario", default=None)
    run.add_argument("--model", default=None)
    run.add_argument("--template", default=None)
    run.add_argument("--no-model-calls", action="store_true")
    run.set_defaults(fn=_cmd_run)

    verify = sub.add_parser("verify")
    verify_sub = verify.add_subparsers(dest="verify_cmd", required=True)

    vcert = verify_sub.add_parser("cert")
    vcert.add_argument("path")
    vcert.add_argument("--key", default=None, help="Path to PEM public key for signature verification.")
    vcert.add_argument("--key-registry", default=None, help="Path to key registry JSON for signing_key_id lookup.")
    vcert.set_defaults(fn=_cmd_verify_cert)

    varch = verify_sub.add_parser("archive")
    varch.add_argument("path")
    varch.add_argument("--key", default=None, help="Path to PEM public key for signature verification.")
    varch.add_argument("--key-registry", default=None, help="Path to key registry JSON for signing_key_id lookup.")
    varch.set_defaults(fn=_cmd_verify_archive)

    packs = sub.add_parser("packs")
    packs_sub = packs.add_subparsers(dest="packs_cmd", required=True)

    plist = packs_sub.add_parser("list")
    plist.set_defaults(fn=_cmd_packs_list)

    pshow = packs_sub.add_parser("show")
    pshow.add_argument("pack_id")
    pshow.set_defaults(fn=_cmd_packs_show)

    return p


def main() -> None:
    parser = build_parser()
    ns = parser.parse_args()
    rc = ns.fn(ns)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
