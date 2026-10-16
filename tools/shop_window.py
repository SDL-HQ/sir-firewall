#!/usr/bin/env python3
"""Select the archives the evidence shop window exhibits, by category.

The shop window is a small, separate, generated repository whose job is to get
a stranger from arriving to holding a verified fact in under two minutes. Its
exhibits are real published archives, each chosen because running our own
verifiers against it produces a different answer, including the answers that
say we got something wrong.

This module does the selecting and nothing else. It does not copy, write or
publish: a selection that can be tested without side effects is worth more
than a generator that has to be run to be understood.

Two rules, both learned by doing it wrong on 16 October 2026.

**Select on the pair of exit codes, never one of them.** The archive first
chosen as the clean exhibit verifies at certificate exit 0 and fails its
receipt at exit 2, because it is also one of the incomplete archives. As the
opening exhibit it would have undercut itself on the second command a visitor
ran. It is instead the best available exhibit for the receipt case, which the
first choice for that slot could not make, because every incomplete archive
sampled there had a certificate at exit 9.

**Name the ledger on the command line; do not rely on discovery.**
`verify_certificate.py` finds a ledger beside a certificate only when the
directory is named for the run id the certificate signs, and legacy
certificates carry no `run_id` field at all. Four of the seven exhibits are
legacy, so a bare command finds no ledger for any of them and reports exit 9,
"no ledger corresponding to the signed identity", whatever is actually in the
directory. `verify_baseline_record.py` resolves only the canonical
`proofs/runs/<run_id>/` path, which does not exist in the shop window, so a
bare command there reports exit 7.

So each exhibit carries the form of the command it is documented with, and the
test runs exactly that. A one-word command hiding the flags in a wrapper was
the alternative and is rejected: for a front door whose pitch is that a
stranger can check our claims, every path in the command should be visible.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "docs" / "archive-figures.json"


@dataclass(frozen=True)
class Exhibit:
    """One archive, and the answer the shop window will claim for it."""

    number: int
    name: str
    teaches: str
    document_exit: int
    receipt_exit: int
    #: "beside" names the ledger in the archive; "none" passes --no-ledger
    #: because the archive ships no ledger at all.
    ledger: str
    run_id: str = ""
    candidates: tuple = field(default=(), repr=False)

    def command(self, directory: str) -> list:
        """Exactly what the shop window tells a visitor to type."""
        document = "baseline.json" if self.number == 7 else "audit.json"
        tool = (
            "verify_baseline_record.py" if self.number == 7 else "verify_certificate.py"
        )
        argv = [f"tools/{tool}", f"{directory}/{document}"]
        if self.ledger == "beside":
            argv += ["--ledger", f"{directory}/proofs/itgl_ledger.jsonl"]
        else:
            argv += ["--no-ledger"]
        return argv


def _sets(figures: dict) -> dict:
    return {
        key: set(value)
        for key, value in figures.items()
        if isinstance(value, list) and value and isinstance(value[0], str)
    }


def _pick(pool: set) -> tuple:
    """Deterministic, and the whole eligible set is kept for the test."""
    return tuple(sorted(pool))


SPECIFICATION = (
    # number, name, what the visitor learns, document exit, receipt exit, ledger, selector
    (
        1,
        "a current certificate",
        "signature, ledger binding and row count all check, and the archive is complete",
        0,
        0,
        "beside",
        lambda s: s["binding_checked_and_holds"] - s["incomplete"] - s["receipt_signature_failed"],
    ),
    (
        2,
        "a signature that fails",
        "a real signature that really does not verify, published anyway",
        5,
        2,
        "beside",
        lambda s: s["certificate_signature_failed"],
    ),
    (
        3,
        "a pre-2.3.4 archive",
        "a documented format boundary is not tampering, and the verifier says which it is",
        9,
        0,
        "beside",
        lambda s: s["exit_9_predates_correction"] - s["incomplete"],
    ),
    (
        4,
        "an archive shipping no ledger",
        'verified, and less than "verified" sounds',
        0,
        3,
        "none",
        lambda s: s["no_ledger_to_bind"] & s["legacy_no_receipt"],
    ),
    (
        5,
        "an archive with no receipt",
        "legacy archives predate the receipt scheme, disclosed",
        0,
        3,
        "none",
        lambda s: s["no_ledger_to_bind"] & s["legacy_no_receipt"],
    ),
    (
        6,
        "a complete-looking archive that is not",
        "the receipt catches what the certificate cannot",
        0,
        2,
        "beside",
        lambda s: s["incomplete"] & s["binding_checked_and_holds"],
    ),
    (
        7,
        "a baseline record",
        "wrong document kind, by design, with its own verifier",
        0,
        0,
        "beside",
        lambda s: s["baseline_records"],
    ),
)


def select(figures: dict | None = None) -> list:
    """The seven exhibits, each bound to a real run id."""
    if figures is None:
        figures = json.loads(FIGURES.read_text(encoding="utf-8"))
    sets = _sets(figures)

    exhibits = []
    for number, name, teaches, document_exit, receipt_exit, ledger, selector in SPECIFICATION:
        pool = _pick(selector(sets))
        if not pool:
            raise LookupError(
                f"exhibit {number}, {name}, has no candidate in the published "
                "archive. The shop window cannot claim a result it cannot show"
            )
        exhibits.append(
            Exhibit(
                number=number,
                name=name,
                teaches=teaches,
                document_exit=document_exit,
                receipt_exit=receipt_exit,
                ledger=ledger,
                run_id=pool[0],
                candidates=pool,
            )
        )
    return exhibits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    exhibits = select()
    payload = [
        {
            "number": e.number,
            "name": e.name,
            "teaches": e.teaches,
            "run_id": e.run_id,
            "document_exit": e.document_exit,
            "receipt_exit": e.receipt_exit,
            "command": " ".join(e.command(f"exhibits/{e.run_id}")),
            "eligible": len(e.candidates),
        }
        for e in exhibits
    ]
    if args.json_out:
        args.json_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        for row in payload:
            print(
                f"{row['number']}. {row['name']:38} "
                f"document exit {row['document_exit']}  receipt exit {row['receipt_exit']}  "
                f"{row['run_id']}  ({row['eligible']} eligible)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
