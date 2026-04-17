from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACK_REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"


def _unknown_pack_message(pack_id: str) -> str:
    return (
        f"ERROR: unknown pack_id {pack_id}. "
        "Use `sir packs list` to discover pack_id values and `sir packs show <pack_id>` for details."
    )


def _run_py(script_rel: str, args: list[str]) -> int:
    script = ROOT / script_rel
    cmd = [sys.executable, str(script), *args]
    return subprocess.call(cmd, cwd=ROOT)


def _cmd_run(ns: argparse.Namespace) -> int:
    if ns.mode not in {"audit", "live", "scenario"}:
        raise SystemExit(f"ERROR: unsupported --mode {ns.mode}")

    if ns.mode == "live":
        if not os.getenv("XAI_API_KEY", "").strip():
            print(
                "ERROR: LIVE mode requires your own provider credentials (XAI_API_KEY). "
                "Set XAI_API_KEY before running LIVE mode. SIR does not ship keys.",
                file=sys.stderr,
            )
            return 2
        if importlib.util.find_spec("litellm") is None:
            print(
                'ERROR: LIVE mode requires litellm installed. Run: python3 -m pip install -e ".[live]"',
                file=sys.stderr,
            )
            return 2

    if ns.mode == "scenario":
        if ns.suite:
            print("ERROR: --mode scenario does not support --suite. Use --scenario or a scenario pack.", file=sys.stderr)
            return 2
        if ns.scenario and ns.pack:
            print("ERROR: --mode scenario accepts only one of --scenario or --pack.", file=sys.stderr)
            return 2
        if ns.pack:
            reg = _load_registry()
            pack = next((p for p in reg.get("packs", []) if p.get("pack_id") == ns.pack), None)
            if not pack:
                print(_unknown_pack_message(ns.pack), file=sys.stderr)
                return 2
            if pack.get("schema") != "scenario_json_v1":
                print(
                    f"ERROR: --mode scenario requires a scenario_json_v1 pack; got {ns.pack} ({pack.get('schema')}).",
                    file=sys.stderr,
                )
                return 2
        elif not ns.scenario:
            print("ERROR: --mode scenario requires --scenario or a scenario_json_v1 --pack.", file=sys.stderr)
            return 2

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
                if summary.get("scenario_id") or summary.get("scenario_hash"):
                    summary["proof_class"] = "SCENARIO_AUDIT"
                    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
                else:
                    print(
                        f"WARNING: skipping scenario proof_class rewrite at {summary_path}: "
                        "summary does not include scenario_id/scenario_hash",
                        file=sys.stderr,
                    )
            except (json.JSONDecodeError, OSError) as exc:
                print(f"WARNING: failed to update scenario summary at {summary_path}: {exc}", file=sys.stderr)

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
    try:
        return json.loads(PACK_REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: failed to load pack registry {PACK_REGISTRY}: {exc}", file=sys.stderr)
        raise SystemExit(2)


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
    p = argparse.ArgumentParser(
        prog="sir",
        description="SIR operator CLI for deterministic pre-inference evaluation and verification tasks.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser(
        "run",
        help="Execute an audit/live/scenario run using existing SIR paths.",
        description=(
            "Run SIR via the common operator path.\n"
            "Modes:\n"
            "  audit    Deterministic offline gate evaluation (default).\n"
            "  live     Provider-call gating check (requires XAI_API_KEY and litellm).\n"
            "  scenario Scenario-only path; requires exactly one of --scenario or --pack\n"
            "           where --pack resolves to schema scenario_json_v1.\n\n"
            "Discover packs with `sir packs list` and inspect with `sir packs show <pack_id>`."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    run.add_argument(
        "--mode",
        choices=["audit", "live", "scenario"],
        default="audit",
        help="Execution mode: audit (default), live, or scenario.",
    )
    run.add_argument(
        "--pack",
        default=None,
        help="Pack identifier from pack registry (discover via `sir packs list`).",
    )
    run.add_argument(
        "--suite",
        default=None,
        help="Explicit suite CSV path (not supported with --mode scenario).",
    )
    run.add_argument(
        "--scenario",
        default=None,
        help="Scenario JSON path for --mode scenario (mutually exclusive with --pack in scenario mode).",
    )
    run.add_argument("--model", default=None, help="Model override for compatible run paths.")
    run.add_argument("--template", default=None, help="Prompt template override for compatible run paths.")
    run.add_argument(
        "--no-model-calls",
        action="store_true",
        help="Skip provider model calls where supported by the underlying run path.",
    )
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

    packs = sub.add_parser(
        "packs",
        help="List or inspect registered pack metadata.",
        description="Pack registry lookup helpers for operator pack discovery.",
    )
    packs_sub = packs.add_subparsers(dest="packs_cmd", required=True)

    plist = packs_sub.add_parser("list", help="List registered pack_id/schema/status rows.")
    plist.set_defaults(fn=_cmd_packs_list)

    pshow = packs_sub.add_parser("show", help="Show full registry record for one pack_id.")
    pshow.add_argument("pack_id", help="Exact pack_id to inspect (find values with `sir packs list`).")
    pshow.set_defaults(fn=_cmd_packs_show)

    return p


def main() -> None:
    parser = build_parser()
    ns = parser.parse_args()
    rc = ns.fn(ns)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
