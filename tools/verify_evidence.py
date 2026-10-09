#!/usr/bin/env python3
"""
SIR Firewall - Consolidated evidence verification

One command over one run directory. It resolves the certificate, ledger,
manifest and receipt itself, runs every check that applies, and reports each
property separately.

    python3 tools/verify_evidence.py docs/runs/<run_id>

Why this exists. The documented evaluator procedure was two commands, with a
third, the contract validator, existing and not named in it. The evaluator had
to assemble four paths, know which flag closed which gap, and read prose to tell
one result from another. Most sharply: passing --require-registry and omitting
it produced byte-identical output and the same exit code, while the procedure
asked the evaluator to record a different conclusion in each case. A weaker
result that is reported identically to a stronger one is the defect this project
keeps finding in other people's evidence.

Three rules this tool follows.

**The registry is required, not requested.** Resolution through
spec/pubkeys/key_registry.v1.json is the default and there is no flag to ask for
it. --allow-unregistered-key opts out, and saying so changes the verdict rather
than only the prose, so the weaker check cannot be reached by forgetting
something.

**Not established is not a failure, and it is not a pass.** A certificate no
evidence contract governs has not failed a contract. A ledger that predates the
fields needed to recompute the signed counters has not disagreed with them. Both
are unknown, and unknown has its own verdict and its own exit code. This is the
same rule as content_false_positive_rate being null rather than zero.

**Absence of evidence is reported, not skipped.** A missing receipt or manifest
leaves the custody property unestablished. It does not reduce the number of
checks that had to pass.

Exit codes:
  0  ESTABLISHED      every applicable property established, none unknown
  1  NOT ESTABLISHED  nothing failed, but at least one property is unknown
  2  FAILED           at least one property actively failed
  3  the run directory could not be read
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(TOOLS))

from key_registry import IMPLICIT_KEY_ID

ESTABLISHED = 0
NOT_ESTABLISHED = 1
FAILED = 2
UNREADABLE = 3

# verify_certificate.py's own codes, named here so the report can say what
# happened rather than printing a number.
CERTIFICATE_CODES = {
    0: ("established", "signature, payload hash and ledger binding all verify"),
    2: ("failed", "the certificate is missing fields its era requires"),
    3: ("failed", "payload hash does not match the signed payload"),
    4: ("failed", "the signature is not valid base64"),
    5: ("failed", "signature verification failed"),
    6: ("failed", "signature verification raised"),
    7: ("failed", "certificate-to-ledger binding failed"),
    9: ("unknown", "the certificate-to-ledger binding was not fully checked, so it is "
                   "not established; the signature and payload hash were still checked"),
    10: ("failed", "the signing key is revoked for this archive"),
    11: ("failed", "the signed counters are not supported by the bound ledger"),
}

# verify_certificate.py codes reached only after the signature verified. Signing
# trust is read from this rather than from the overall result, because a missing
# ledger says nothing about the key and must not be reported as though it did.
SIGNATURE_VERIFIED_CODES = frozenset({0, 2, 7, 9, 11})

CONTRACT_CODES = {
    0: ("established", "the certificate satisfies its applicable evidence contract"),
    2: ("failed", "the certificate violates its applicable evidence contract"),
    3: ("unknown", "the contract or the certificate could not be read"),
    8: ("unknown", "no evidence contract governs this certificate's version"),
}

RECEIPT_CODES = {
    0: ("established", "every file named by the signed manifest is present and unchanged"),
    2: ("failed", "a file named by the signed manifest is missing, changed, or the receipt "
                  "signature does not verify"),
    # 3 covers an unreadable manifest or receipt, and a legacy archive published
    # without one at all. Nothing was checked, so nothing failed.
    3: ("unknown", "the manifest or receipt could not be read, or this archive was "
                   "published without one"),
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify every property of one SIR run archive with one command.",
        epilog=(
            "Exit 0 established, 1 not established (nothing failed, something is "
            "unknown), 2 failed, 3 unreadable."
        ),
    )
    parser.add_argument("run_directory", help="A run folder, such as docs/runs/<run_id>")
    parser.add_argument(
        "--allow-unregistered-key",
        action="store_true",
        help=(
            "Verify the signature against --pubkey without resolving the signing key "
            "through the registry. The signing-trust property is then reported as "
            "unknown, because an arbitrary public key file establishes that someone "
            "signed this, not that SDL did."
        ),
    )
    parser.add_argument("--pubkey", default=None, help="Only with --allow-unregistered-key.")
    parser.add_argument(
        "--key-registry",
        default=str(REPO_ROOT / "spec/pubkeys/key_registry.v1.json"),
        help="Approved key registry (default: spec/pubkeys/key_registry.v1.json).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    return parser.parse_args()


def _run(argv: List[str]) -> Tuple[int, str]:
    result = subprocess.run(
        [sys.executable, *argv], cwd=REPO_ROOT, capture_output=True, text=True
    )
    return result.returncode, (result.stderr or result.stdout).strip()


def _classify(code: int, table: Dict[int, Tuple[str, str]], tool: str) -> Tuple[str, str]:
    if code in table:
        return table[code]
    return ("failed", f"{tool} exited {code}")


class Report:
    def __init__(self) -> None:
        self.properties: List[Dict[str, Any]] = []

    def add(self, name: str, state: str, detail: str, evidence: Optional[str] = None) -> None:
        assert state in ("established", "unknown", "failed"), state
        self.properties.append(
            {"property": name, "state": state, "detail": detail, "evidence": evidence}
        )

    @property
    def verdict(self) -> int:
        states = {entry["state"] for entry in self.properties}
        if "failed" in states:
            return FAILED
        if "unknown" in states:
            return NOT_ESTABLISHED
        return ESTABLISHED

    def to_json(self, run_directory: Path) -> str:
        return json.dumps(
            {
                "run_directory": str(run_directory),
                "verdict": {0: "ESTABLISHED", 1: "NOT ESTABLISHED", 2: "FAILED"}[self.verdict],
                "exit_code": self.verdict,
                "properties": self.properties,
            },
            indent=2,
            sort_keys=True,
        )

    def to_text(self, run_directory: Path) -> str:
        label = {0: "ESTABLISHED", 1: "NOT ESTABLISHED", 2: "FAILED"}[self.verdict]
        width = max(len(entry["property"]) for entry in self.properties)
        lines = [f"{run_directory}", ""]
        for entry in self.properties:
            mark = {"established": "OK     ", "unknown": "UNKNOWN", "failed": "FAILED "}[
                entry["state"]
            ]
            lines.append(f"  {mark} {entry['property']:<{width}}  {entry['detail']}")
        lines.append("")
        lines.append(f"VERDICT: {label}")
        if self.verdict == NOT_ESTABLISHED:
            lines.append(
                "Nothing failed. One or more properties could not be established, and "
                "an unestablished property is not a passing one."
            )
        return "\n".join(lines)


def main() -> int:
    args = _parse_args()
    run_directory = Path(args.run_directory)

    if not run_directory.is_dir():
        print(f"ERROR: not a directory: {run_directory}", file=sys.stderr)
        return UNREADABLE

    certificate = run_directory / "audit.json"
    ledger = run_directory / "proofs/itgl_ledger.jsonl"
    manifest = run_directory / "manifest.json"
    receipt = run_directory / "archive_receipt.json"

    if not certificate.is_file():
        print(f"ERROR: no certificate at {certificate}", file=sys.stderr)
        return UNREADABLE
    try:
        cert = json.loads(certificate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ERROR: certificate could not be read: {exc}", file=sys.stderr)
        return UNREADABLE

    report = Report()

    # --- certificate, binding and counters -----------------------------------
    # Run first. Signing trust is read off this result rather than asserted
    # ahead of it: the certificate carrying a signing_key_id says what resolution
    # was attempted, not that it succeeded.
    # Always explicit. verify_certificate.py can discover a ledger from the
    # signed run identity, and that discovery can resolve to a copy elsewhere on
    # disk. An evaluator who points at a directory is asking about that
    # directory, so this tool never lets discovery run: the ledger beside the
    # certificate, or none at all.
    argv = [str(TOOLS / "verify_certificate.py"), str(certificate)]
    argv += ["--ledger", str(ledger)] if ledger.is_file() else ["--no-ledger"]
    if args.allow_unregistered_key:
        if args.pubkey:
            argv += ["--pubkey", args.pubkey]
    else:
        argv += ["--key-registry", args.key_registry, "--require-registry"]
    code, output = _run(argv)
    state, detail = _classify(code, CERTIFICATE_CODES, "verify_certificate.py")
    if not ledger.is_file() and state == "established":
        # Only a pass is downgraded. A signature that failed without a ledger
        # present still failed, and must not be softened into unknown.
        state, detail = (
            "unknown",
            "no ledger in this run directory, so the certificate-to-ledger binding "
            "establishes nothing; the signature and payload hash were still checked",
        )
    last_line = output.splitlines()[-1] if output else None

    # --- signing trust -------------------------------------------------------
    if args.allow_unregistered_key:
        report.add(
            "signing trust",
            "unknown",
            "--allow-unregistered-key was given, so the signing key was not resolved "
            "through the approved registry; this establishes that someone signed the "
            "certificate, not that SDL did",
        )
    elif code not in SIGNATURE_VERIFIED_CODES:
        report.add(
            "signing trust",
            "unknown",
            "the signature did not verify, so registry resolution establishes "
            "nothing about this archive",
        )
    elif cert.get("signing_key_id") is None:
        report.add(
            "signing trust",
            "established",
            "the certificate carries no signing_key_id, because the field postdates it; "
            f"resolved as key_id={IMPLICIT_KEY_ID!r} through {Path(args.key_registry).name}, "
            "with that entry's status and revocation rules applied",
        )
    else:
        report.add(
            "signing trust",
            "established",
            f"signing_key_id={cert['signing_key_id']!r} resolved through "
            f"{Path(args.key_registry).name}, with its status and revocation rules applied",
        )

    report.add("certificate", state, detail, evidence=last_line)

    # The counters are a separate property from the binding, because the ledger
    # can bind correctly and still predate the fields that let the signed
    # numbers be recomputed from it. Saying "verified" for both would report an
    # unperformed check as a performed one.
    certificate_code = code
    if cert.get("counters_checked_against_ledger") is True:
        report.add(
            "signed counters",
            "established" if certificate_code != 11 else "failed",
            "the signed counters were recomputed from the rows the certificate binds"
            if certificate_code != 11
            else "the signed counters are not supported by the bound ledger",
        )
    else:
        report.add(
            "signed counters",
            "unknown",
            "this ledger predates the fields needed to recompute the signed counters, "
            "so they were not checked against it; this is not agreement",
        )

    # --- archive custody -----------------------------------------------------
    if not receipt.is_file() or not manifest.is_file():
        missing = [p.name for p in (manifest, receipt) if not p.is_file()]
        report.add(
            "archive custody",
            "unknown",
            f"no {' and no '.join(missing)} in this run directory, so no file-level "
            "custody check was possible",
        )
    else:
        argv = [str(TOOLS / "verify_archive_receipt.py"), str(run_directory)]
        if not args.allow_unregistered_key:
            argv += ["--key-registry", args.key_registry, "--require-registry"]
        code, output = _run(argv)
        state, detail = _classify(code, RECEIPT_CODES, "verify_archive_receipt.py")
        if state == "failed" and "listed in manifest is missing" in output:
            # A documented publishing defect rather than a corrupt download. This
            # is still a failure: the signed manifest names a file and the file
            # is not there, so file-level custody is not established. Naming the
            # known cause stops a reader concluding their copy is damaged.
            detail += (
                "; 99 archives published between April and September 2026 name "
                "leaks_count.txt and harmless_blocked.txt in their signed manifests "
                "and a repository ignore rule meant those two were never committed, "
                "so check docs/archive-errata.md before concluding the download is bad"
            )
        report.add(
            "archive custody", state, detail, evidence=output.splitlines()[-1] if output else None
        )

    # --- evidence contract ---------------------------------------------------
    argv = [
        str(TOOLS / "validate_certificate_contract.py"),
        str(certificate),
        "--key-registry",
        args.key_registry,
    ]
    code, output = _run(argv)
    state, detail = _classify(code, CONTRACT_CODES, "validate_certificate_contract.py")
    if code == 8:
        detail = (
            f"no evidence contract governs sir_firewall_version "
            f"{cert.get('sir_firewall_version')!r}; the contracts begin at 2.2.0, and "
            "219 of the 292 certificates published before SIR 2.4.0 are in this position"
        )
    report.add(
        "evidence contract", state, detail, evidence=output.splitlines()[-1] if output else None
    )

    text = report.to_json(run_directory) if args.json else report.to_text(run_directory)
    print(text)
    return report.verdict


if __name__ == "__main__":
    raise SystemExit(main())
