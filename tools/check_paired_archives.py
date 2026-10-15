#!/usr/bin/env python3
"""Admit a paired benchmark's two archives, before anything about them is published.

From SIR 2.5 the two halves of a pair are different documents. The gated half
is an audit certificate at audit.json; the ungated half is a baseline record at
baseline.json, which carries no result and no proof class. Every reader
downstream dispatches on that filename, so the filename is what has to be
right, and it has to be right before the publication steps run rather than
discovered by a verifier afterwards: a benchmark that publishes half an archive
and then fails has already put the archive in front of a reader.

What this refuses, and why each one matters:

- the baseline archive holding audit.json. This is the 2.4 shape, and it is the
  defect the 2.5 work exists to remove: 54 published certificates describe
  ungated runs as failed audits of a gate that was not in the path.
- the gated archive holding baseline.json. The mirror of the same mistake, and
  it would publish a gate run as a document that claims nothing about the gate.
- either archive holding both. tools/verify_evidence.py refuses such an
  archive, so it would be published and then be unverifiable as either kind.
- either archive holding neither, or not existing at all.
- the two halves reporting the same run id, which would make a pair of one run
  with itself.

It prints the two document paths, so the workflow reads the filenames from here
rather than writing them out again in shell.

Exit codes:
  0  both archives admitted
  2  an archive is missing, untyped, ambiguous, or holds the other's document
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

CERTIFICATE_DOCUMENT = "audit.json"
RECORD_DOCUMENT = "baseline.json"

ROLE_DOCUMENTS = {
    "gated": CERTIFICATE_DOCUMENT,
    "baseline": RECORD_DOCUMENT,
}


def _documents_present(archive: Path) -> List[str]:
    return [name for name in (CERTIFICATE_DOCUMENT, RECORD_DOCUMENT) if (archive / name).is_file()]


def check_archive(runs_dir: Path, run_id: str, role: str) -> List[str]:
    """Every reason this archive is not the named role's archive."""
    expected = ROLE_DOCUMENTS[role]
    other = RECORD_DOCUMENT if expected == CERTIFICATE_DOCUMENT else CERTIFICATE_DOCUMENT
    archive = runs_dir / run_id
    problems: List[str] = []

    if not archive.is_dir():
        return [f"the {role} archive does not exist: {archive}"]

    present = _documents_present(archive)
    if len(present) > 1:
        problems.append(
            f"the {role} archive holds both {CERTIFICATE_DOCUMENT} and {RECORD_DOCUMENT}, "
            f"so it cannot be read as either kind: {archive}"
        )
        return problems
    if not present:
        problems.append(
            f"the {role} archive holds no signed document, so it has no kind: {archive} "
            f"(expected {expected})"
        )
        return problems
    if present[0] != expected:
        problems.append(
            f"the {role} archive holds {other} where {expected} is expected: {archive}. "
            f"A {role} run publishes {expected}."
        )
    return problems


def check_pair(runs_dir: Path, baseline_run_id: str, gated_run_id: str) -> List[str]:
    problems: List[str] = []
    if not baseline_run_id or not gated_run_id:
        problems.append("both a baseline run id and a gated run id are required")
        return problems
    if baseline_run_id == gated_run_id:
        problems.append(
            f"both halves report the same run id, so there is no pair: {gated_run_id}"
        )
        return problems
    problems.extend(check_archive(runs_dir, gated_run_id, "gated"))
    problems.extend(check_archive(runs_dir, baseline_run_id, "baseline"))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline-run-id", required=True)
    parser.add_argument("--gated-run-id", required=True)
    parser.add_argument(
        "--runs-dir",
        default="proofs/runs",
        help="Directory of per-run archives. Default: proofs/runs",
    )
    args = parser.parse_args()

    runs_dir = Path(args.runs_dir)
    problems = check_pair(runs_dir, args.baseline_run_id, args.gated_run_id)
    if problems:
        print("ERROR: the paired benchmark's archives are not publishable.")
        for problem in problems:
            print(f"ERROR: {problem}")
        return 2

    gated = runs_dir / args.gated_run_id / CERTIFICATE_DOCUMENT
    baseline = runs_dir / args.baseline_run_id / RECORD_DOCUMENT
    print(f"OK: gated run {args.gated_run_id} holds {CERTIFICATE_DOCUMENT} and not {RECORD_DOCUMENT}")
    print(f"OK: baseline run {args.baseline_run_id} holds {RECORD_DOCUMENT} and not {CERTIFICATE_DOCUMENT}")
    print(f"GATED_AUDIT_JSON={gated.as_posix()}")
    print(f"BASELINE_RECORD_JSON={baseline.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
