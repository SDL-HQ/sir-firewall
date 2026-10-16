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
    12: ("failed", "this document is not a SIR audit certificate, so nothing about it "
                   "was verified, including its signature"),
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


#: Not an exit code any helper can return, so it cannot be confused with one.
#: A helper that is not there has said nothing about the certificate, and the
#: tables below map low exit codes to statements about the certificate: 2 in
#: CONTRACT_CODES is "the certificate violates its applicable evidence
#: contract", which is what a missing `validate_certificate_contract.py` used
#: to be reported as. Python's own exit code for a file it cannot open is 2.
#: Found by shipping this tool into a public repository without its helper,
#: where the answer would have been that our evidence breaks our own contract.
TOOL_MISSING = 1000


def _run(argv: List[str]) -> Tuple[int, str]:
    script = Path(argv[0])
    if not script.is_file():
        return TOOL_MISSING, f"{script.name} is not present beside this tool"
    result = subprocess.run(
        [sys.executable, *argv], cwd=REPO_ROOT, capture_output=True, text=True
    )
    return result.returncode, (result.stderr or result.stdout).strip()


def _classify(code: int, table: Dict[int, Tuple[str, str]], tool: str) -> Tuple[str, str]:
    if code == TOOL_MISSING:
        # Unknown, not failed. Absence of a check is reported, never counted
        # as the check having found something.
        return (
            "unknown",
            f"{tool} is not present, so this property was not checked; it has not "
            "failed, and a copy of this tool without its helpers cannot establish it",
        )
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


BASELINE_RECORD_CODES = {
    0: ("established", "signature, ledger binding and recomputed counters all verify"),
    2: ("failed", "the document is not a valid baseline record"),
    3: ("failed", "payload hash does not match the signed payload"),
    4: ("failed", "the signature is not valid base64"),
    5: ("failed", "signature verification failed"),
    7: ("failed", "the bound ledger does not support the record"),
    10: ("failed", "the signing key is revoked for this record"),
}

# Codes reached only after the signature verified, so signing trust can be read
# off them. The same rule as SIGNATURE_VERIFIED_CODES for certificates.
BASELINE_SIGNATURE_VERIFIED_CODES = frozenset({0, 7})


def _verify_baseline_archive(*, run_directory, record, ledger, manifest, receipt, args):
    """An archive describing an ungated baseline run.

    The properties are not the certificate's. There is no evidence contract and
    no audit result to establish, because the record claims neither: what can be
    established is that the document is authentic, that the rows it binds are an
    ungated baseline's, and that its counters are those rows'. The report says
    so in those words rather than reporting a firewall certificate property as
    unknown, which would read as a check that failed to run.
    """
    report = Report()

    argv = [str(TOOLS / "verify_baseline_record.py"), str(record)]
    # One or the other, never neither. The record names its own ledger path, so
    # omitting both let an archive with no ledger be verified against a ledger
    # somewhere else on disk, and this tool reports on one archive directory.
    # The certificate branch below has always passed --no-ledger for the same
    # reason; an independent review found the baseline branch did not.
    argv += ["--ledger", str(ledger)] if ledger.is_file() else ["--no-ledger"]
    if args.allow_unregistered_key:
        if args.pubkey:
            argv += ["--pubkey", args.pubkey]
    else:
        argv += ["--key-registry", args.key_registry, "--require-registry"]
    code, output = _run(argv)
    state, detail = _classify(code, BASELINE_RECORD_CODES, "verify_baseline_record.py")
    if not ledger.is_file() and state == "established":
        # Only a pass is downgraded, as in the certificate branch. A signature
        # that failed without a ledger present still failed.
        state, detail = (
            "unknown",
            "no ledger in this run directory, so the record's binding, row "
            "classification and counters establish nothing; the document and its "
            "signature were still checked",
        )
    last_line = output.strip().splitlines()[-1] if output.strip() else None
    report.add("baseline record", state, detail, evidence=last_line)

    if args.allow_unregistered_key:
        report.add(
            "signing trust",
            "unknown",
            "--allow-unregistered-key was given, so the signing key was not resolved "
            "through the approved registry; this establishes that someone signed the "
            "record, not that SDL did",
        )
    elif code in BASELINE_SIGNATURE_VERIFIED_CODES:
        report.add(
            "signing trust",
            "established",
            "the signature verified against a key the registry honours for this record",
        )
    else:
        report.add(
            "signing trust",
            "failed" if state == "failed" else "unknown",
            "the record's signature did not verify through the key registry",
        )

    if manifest.is_file() or receipt.is_file():
        receipt_argv = [str(TOOLS / "verify_archive_receipt.py"), str(run_directory)]
        if not args.allow_unregistered_key:
            receipt_argv += ["--key-registry", args.key_registry, "--require-registry"]
        receipt_code, receipt_output = _run(receipt_argv)
        receipt_state, receipt_detail = _classify(
            receipt_code, RECEIPT_CODES, "verify_archive_receipt.py"
        )
        report.add(
            "archive custody",
            receipt_state,
            receipt_detail,
            evidence=receipt_output.strip().splitlines()[-1] if receipt_output.strip() else None,
        )
    else:
        report.add(
            "archive custody",
            "unknown",
            "this archive carries no manifest or receipt, so file custody was not checked",
        )

    # Deliberately not reported: an evidence contract, and an audit result. A
    # baseline record claims neither, so there is nothing to establish and
    # nothing to report as unknown.
    print(
        report.to_json(run_directory) if args.json else report.to_text(run_directory),
        file=sys.stdout,
    )
    # verdict is a property. Calling it raised TypeError on every baseline
    # archive, after the report had already been printed, so the tool printed a
    # correct report and then exited 1 on an uncaught exception. The gated
    # branch at the bottom of this file never had the bug, which is why it was
    # not noticed: no baseline archive is published yet, so nothing in the
    # repository exercised this line.
    return report.verdict


def main() -> int:
    args = _parse_args()
    run_directory = Path(args.run_directory)

    if not run_directory.is_dir():
        print(f"ERROR: not a directory: {run_directory}", file=sys.stderr)
        return UNREADABLE

    certificate = run_directory / "audit.json"
    baseline_record = run_directory / "baseline.json"
    ledger = run_directory / "proofs/itgl_ledger.jsonl"
    manifest = run_directory / "manifest.json"
    receipt = run_directory / "archive_receipt.json"

    # Which document this archive holds decides what can be established about
    # it. From SIR 2.5 an ungated baseline is described by baseline.json, which
    # carries no audit result and no proof class, and a gated run by audit.json.
    #
    # Both present, or neither, is a failure rather than unknown. An archive
    # with both describes one run two ways, and nothing here can say which is
    # the run; an archive with neither has no signed document to check at all.
    # Reporting either as "not established" would put them beside an archive
    # whose ledger merely predates a field, which is a different thing.
    if certificate.is_file() and baseline_record.is_file():
        print(
            f"ERROR: {run_directory} holds both audit.json and baseline.json. One run is "
            "described by one signed document: a gated run by a certificate, an ungated "
            "baseline by a baseline record.",
            file=sys.stderr,
        )
        return FAILED
    if baseline_record.is_file():
        return _verify_baseline_archive(
            run_directory=run_directory,
            record=baseline_record,
            ledger=ledger,
            manifest=manifest,
            receipt=receipt,
            args=args,
        )
    if not certificate.is_file():
        print(
            f"ERROR: no signed document at {certificate} or {baseline_record}",
            file=sys.stderr,
        )
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
