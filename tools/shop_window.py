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
    #: because the archive ships no ledger at all. Derived in select() from
    #: whether the archive actually ships one, never declared. It was declared
    #: per slot until a parallel audit found that three of the six candidates
    #: for the signature-failure slot ship no ledger while the slot said
    #: "beside". Their documented command still exits 5, because the signature
    #: fails before the ledger is reached, so the claim held and the command
    #: named a file that is not there. A value asserted about an artefact
    #: rather than computed from it is the shape of every significant defect
    #: in this repository's history.
    ledger: str = ""
    #: What `verify_evidence.py` says about the whole archive. The individual
    #: verifiers answer one property each, and exit 0 from two of them is not
    #: the project's own word for a sound archive: this is. An earlier version
    #: of this file had no such field and called an archive clean on two exit
    #: codes while the project's verdict tool said NOT ESTABLISHED.
    verdict: str = "ESTABLISHED"
    #: The errata entry that discloses this archive's defect, where there is
    #: one. The front door and the back room have to agree.
    errata: str = ""
    #: The signed document this exhibit is about, and the tool that reads it.
    document: str = "audit.json"
    tool: str = "verify_certificate.py"
    #: Exit code when the *wrong* verifier is pointed at this document, where
    #: that refusal is the exhibit's point. None where it is not.
    refusal_exit: int | None = None
    run_id: str = ""
    candidates: tuple = field(default=(), repr=False)

    def command(self, directory: str) -> list:
        """Exactly what the shop window tells a visitor to type."""
        argv = [f"tools/{self.tool}", f"{directory}/{self.document}"]
        if self.ledger == "beside":
            argv += ["--ledger", f"{directory}/proofs/itgl_ledger.jsonl"]
        else:
            argv += ["--no-ledger"]
        return argv

    def refusal_command(self, directory: str) -> list:
        """The wrong verifier, for the exhibit whose point is being refused."""
        if self.refusal_exit is None:
            raise ValueError(f"exhibit {self.number} has no refusal to show")
        return [
            "tools/verify_certificate.py",
            f"{directory}/baseline.json",
            "--ledger",
            f"{directory}/proofs/itgl_ledger.jsonl",
        ]


def _ledger_flag(run_id: str) -> str:
    """"beside" when the archive ships a ledger, "none" when it does not."""
    ledger = ROOT / "docs" / "runs" / run_id / "proofs" / "itgl_ledger.jsonl"
    return "beside" if ledger.is_file() else "none"


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
    # The 54 ungated baseline runs published as audit certificates, errata E7,
    # are subtracted from every slot that is not about them. The first version
    # of this file read five other sets out of the same figures file and never
    # subtracted this one, so the exhibit labelled "a current certificate" was
    # one of the 54: AUDIT FAILED, 100 leaks, on a run with no gate in the
    # path. A front door whose lead exhibit is in the project's own errata is
    # the discrediting story written for a hostile reader.
    #
    # number, name, teaches, document exit, receipt exit, verdict, errata,
    # document, tool, selector. The ledger flag is derived, not listed.
    (
        1,
        "an archive that establishes every property",
        "signature, ledger binding, signed counters and archive custody all check",
        0,
        0,
        "ESTABLISHED",
        "",
        "audit.json",
        "verify_certificate.py",
        # Clean means the verdict tool's word, so the counters must have been
        # recomputed rather than absent. Exit 0 from two tools does not reach
        # ESTABLISHED on its own.
        lambda s: (
            s["binding_checked_and_holds"]
            - s["incomplete"]
            - s["receipt_signature_failed"]
            - s["legacy_ungated_certificates"]
        )
        & s["counters_true"],
    ),
    (
        2,
        "a signature that does not verify",
        "a published certificate signed by a key the registry does not hold",
        5,
        2,
        "FAILED",
        "E2",
        "audit.json",
        "verify_certificate.py",
        lambda s: s["certificate_signature_failed"] - s["legacy_ungated_certificates"],
    ),
    (
        3,
        "an archive from before the 2.3.4 correction",
        "a documented format boundary is not tampering, and the verifier says which",
        9,
        0,
        "NOT ESTABLISHED",
        "E4",
        "audit.json",
        "verify_certificate.py",
        lambda s: s["exit_9_predates_correction"]
        - s["incomplete"]
        - s["legacy_ungated_certificates"],
    ),
    (
        # Formerly two exhibits with identical selectors, so they were one
        # archive presented as two and the page said "seven real published
        # archives". `no_ledger_to_bind` and `legacy_no_receipt` are the same
        # 39 archives, so there is no archive that has one and not the other
        # and the two lessons belong to one exhibit.
        4,
        "an archive with no ledger and no receipt",
        'verified, and less than "verified" sounds: nothing bound it and nothing vouches for the files',
        0,
        3,
        "NOT ESTABLISHED",
        "E3",
        "audit.json",
        "verify_certificate.py",
        lambda s: (s["no_ledger_to_bind"] & s["legacy_no_receipt"])
        - s["legacy_ungated_certificates"],
    ),
    (
        5,
        "a complete-looking archive that is not",
        "the receipt catches what the certificate cannot",
        0,
        2,
        "FAILED",
        "E1",
        "audit.json",
        "verify_certificate.py",
        lambda s: (s["incomplete"] & s["binding_checked_and_holds"])
        - s["legacy_ungated_certificates"],
    ),
    (
        6,
        "a baseline record",
        "a certificate verifier refuses it, and its own verifier accepts it",
        0,
        0,
        "ESTABLISHED",
        "",
        "baseline.json",
        "verify_baseline_record.py",
        lambda s: s["baseline_records"],
    ),
)

#: Not an archive. The one answer a sceptic looks for is a changed byte caught,
#: and every exhibit above is a defect we disclosed rather than a detection. So
#: the window ships a recipe against exhibit 1: alter one field in one ledger
#: row and the certificate verifier names the row and both hashes at exit 7.
TAMPER_EXIT = 7

def select(figures: dict | None = None) -> list:
    """The six exhibits, each bound to a real run id.

    Six archives, not seven. Two slots used to share one archive, which made
    "seven real published archives" false and made the count of exhibits that
    do not come back clean count one archive twice.
    """
    if figures is None:
        figures = json.loads(FIGURES.read_text(encoding="utf-8"))
    sets = _sets(figures)

    exhibits = []
    for (
        number,
        name,
        teaches,
        document_exit,
        receipt_exit,
        verdict,
        errata,
        document,
        tool,
        selector,
    ) in SPECIFICATION:
        pool = _pick(selector(sets))
        if not pool:
            raise LookupError(
                f"exhibit {number}, {name}, has no candidate in the published "
                "archive. The shop window cannot claim a result it cannot show"
            )
        ungated = sets["legacy_ungated_certificates"]
        if errata != "E7" and pool[0] in ungated:
            raise LookupError(
                f"exhibit {number}, {name}, selected {pool[0]}, which is one of "
                f"the {len(ungated)} ungated baseline runs published as audit "
                "certificates. An exhibit that is in the errata has to say so"
            )
        exhibits.append(
            Exhibit(
                number=number,
                name=name,
                teaches=teaches,
                document_exit=document_exit,
                receipt_exit=receipt_exit,
                # Derived from the archive, not from this file.
                ledger=_ledger_flag(pool[0]),
                verdict=verdict,
                errata=errata,
                document=document,
                tool=tool,
                # The baseline record's whole point is the refusal, and its own
                # verifier returns 0, so the documented command alone does not
                # show it.
                refusal_exit=12 if document == "baseline.json" else None,
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
