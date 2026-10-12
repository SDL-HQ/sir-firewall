#!/usr/bin/env python3
"""
Report what a third party actually gets when they verify the published archive.

Published figures about the archive have been hand-counted, and hand-counted
figures drift. This runs the repository's own verifiers over every published run
archive and reports the exit-code distribution, so any claim about the archive
can be re-derived by anyone with a clone and no network.

By default it writes nothing and changes nothing: output goes to stdout, or to a
JSON file with --json-out. With --update-published-surfaces it also rewrites the
generated figure regions in docs/archive-errata.md and docs/claims-register.md,
and docs/archive-figures.json, so that no published figure about the archive is
transcribed by hand. That mode is for the publication step and for anyone
regenerating the documents deliberately.

Verification is three-valued, not two. A record that cannot be checked and a
record that fails are different results and are reported separately.

Runtime is two verifier subprocesses per archive: about twenty seconds for the
292 archives published at SIR 2.4.0, measured on 12 October 2026.

Usage:
    python3 tools/archive_verification_report.py
    python3 tools/archive_verification_report.py --json-out /tmp/archive.json
"""

import argparse
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

# Anchored to the repository rather than the working directory, so a figure is
# produced by this repository's verifiers wherever the report is run from.
ROOT = Path(__file__).resolve().parents[1]
VERIFY_CERTIFICATE = ROOT / "tools/verify_certificate.py"
VERIFY_RECEIPT = ROOT / "tools/verify_archive_receipt.py"
KEY_REGISTRY = ROOT / "spec/pubkeys/key_registry.v1.json"

CERTIFICATE_EXIT_MEANINGS = {
    0: "verified",
    1: "signing key not in registry",
    2: "required fields missing",
    3: "payload hash mismatch",
    4: "signature not valid base64",
    5: "SIGNATURE VERIFICATION FAILED",
    6: "signature verification error",
    7: "LEDGER BINDING FAILED",
    9: "ledger binding not established (no row count, or predates the 2.3.4 correction)",
    10: "SIGNING KEY REVOKED FOR THIS ARCHIVE",
    11: "SIGNED COUNTERS NOT SUPPORTED BY THE BOUND LEDGER",
}

# Reported separately from "verified", which means the binding was checked and
# holds. This archive has no ledger to check against at all.
NO_LEDGER_TO_BIND = "verified; no ledger in the archive, so no binding was checked"

RECEIPT_EXIT_MEANINGS = {
    0: "verified",
    1: "receipt invalid",
    2: "archive incomplete or signature failed",
    3: "no archive receipt (legacy archive)",
}


def _exit_code(command: list[str]) -> tuple[int, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    first_error = ""
    for line in result.stderr.splitlines():
        if line.startswith(("ERROR", "NOT CHECKED")):
            first_error = line.strip()
            break
    return result.returncode, first_error


# --- published surfaces ------------------------------------------------------
#
# Until 12 October 2026 the figures this script produces were retyped into
# docs/archive-errata.md and docs/claims-register.md by hand, while both
# documents stated that they were generated rather than transcribed.
# tests/test_archive_errata_figures.py held three of them. The rest drifted
# unobserved, and four were wrong in kind rather than by a count: E4 named a
# third cause for the exit 9 set that this measurement cannot produce, E3 sent a
# reader to E4 for records that are not in it, E6's tallies were two runs stale
# and its product list omitted one, and E4's row-count figure read as a
# statement about the archive when it is a statement about a subset of it.
#
# Each figure now lives in a delimited region owned by this script. A region is
# replaced wholesale, so a number edited in the document does not survive the
# next publication, and tests/test_published_archive_figures.py fails when a
# region differs from fresh output.
#
# Historical statements are deliberately outside the regions. "41 archives moved
# from exit 9 to exit 0 on 8 October" is a record of a past measurement and must
# not be rewritten by a later one.

ERRATA_PATH = ROOT / "docs/archive-errata.md"
REGISTER_PATH = ROOT / "docs/claims-register.md"
README_PATH = ROOT / "README.md"
FIGURES_JSON = ROOT / "docs/archive-figures.json"

REGION_BEGIN = "<!-- BEGIN GENERATED ARCHIVE FIGURES: {name} -->"
REGION_END = "<!-- END GENERATED ARCHIVE FIGURES: {name} -->"

# Discriminators taken from the verifiers' own messages rather than
# re-derived here, so the published decomposition is of the output a reviewer
# gets. A record this script cannot classify stops it: silently dropping a case
# would publish a decomposition of a smaller archive than the one measured.
MISSING_MANIFEST_FILE = "file listed in manifest is missing"
BAD_SIGNATURE = "signature verification failed"
NO_ROW_COUNT = "carries no itgl_row_count"
PREDATES_CORRECTION = "predates the SIR 2.3.4 evidence-binding correction"
NO_LEDGER_FOR_IDENTITY = "no ledger corresponding to the signed identity"

CONTRACT_FLOOR = (2, 2, 0)
BINDING_CORRECTION = (2, 3, 4)

MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)


class FigureError(Exception):
    """A figure could not be derived. Publishing a guess is the defect."""


def _semver(value) -> tuple | None:
    if isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value):
        return tuple(int(part) for part in value.split("."))
    return None


def _spoken_date(run_id: str) -> str:
    match = re.match(r"(\d{4})(\d{2})(\d{2})", run_id)
    if not match:
        raise FigureError(f"run id carries no date to report: {run_id!r}")
    year, month, day = (int(part) for part in match.groups())
    if not 1 <= month <= 12:
        raise FigureError(f"run id carries an impossible month: {run_id!r}")
    return f"{day} {MONTHS[month - 1]} {year}"


def _date_span(run_ids: list[str]) -> tuple[str, str]:
    """Run ids begin YYYYMMDD, so lexicographic order is chronological order."""
    if not run_ids:
        raise FigureError("a date span was asked for an empty set of runs")
    ordered = sorted(run_ids)
    return _spoken_date(ordered[0]), _spoken_date(ordered[-1])


def _repository_relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def build_figures(records: list[dict], runs_dir: Path) -> dict:
    """Every published figure about the archive, derived once.

    The verifier decides which bucket a record is in. The certificate explains
    why. Nothing here re-implements a verifier's judgement, because the figures
    are published as a statement about what the shipped tools report.
    """
    runs_dir = Path(runs_dir)
    certificates: dict[str, dict] = {}
    for record in records:
        path = runs_dir / record["run_id"] / "audit.json"
        certificates[record["run_id"]] = (
            json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        )

    def cert_detail(record: dict) -> str:
        return record.get("certificate_detail") or ""

    def receipt_detail(record: dict) -> str:
        return record.get("receipt_detail") or ""

    def rows(exit_field: str, meaning_field: str) -> list[dict]:
        counts: dict = {}
        for record in records:
            key = (record[exit_field], record[meaning_field])
            counts[key] = counts.get(key, 0) + 1
        # Ascending exit code, then meaning, so row order is a property of the
        # outcomes rather than of this run's counts. Ordering by count moves rows
        # around whenever an archive is published, which reads in a diff as a
        # change to the figures when nothing has changed.
        return [
            {"exit": exit_code, "meaning": meaning, "count": count}
            for (exit_code, meaning), count in sorted(
                counts.items(),
                key=lambda kv: (kv[0][0] is None, kv[0][0] or 0, kv[0][1]),
            )
        ]

    # --- receipt outcomes ----------------------------------------------------
    incomplete = sorted(
        r["run_id"] for r in records
        if r["receipt_exit"] == 2 and MISSING_MANIFEST_FILE in receipt_detail(r)
    )
    receipt_signature_failed = sorted(
        r["run_id"] for r in records
        if r["receipt_exit"] == 2 and BAD_SIGNATURE in receipt_detail(r)
    )
    legacy_no_receipt = sorted(r["run_id"] for r in records if r["receipt_exit"] == 3)
    unexplained_receipt = sorted(
        {r["run_id"] for r in records if r["receipt_exit"] == 2}
        - set(incomplete) - set(receipt_signature_failed)
    )

    # --- certificate outcomes ------------------------------------------------
    exit_9 = [r for r in records if r["certificate_exit"] == 9]
    no_row_count = sorted(r["run_id"] for r in exit_9 if NO_ROW_COUNT in cert_detail(r))
    predates_correction = sorted(
        r["run_id"] for r in exit_9 if PREDATES_CORRECTION in cert_detail(r)
    )
    no_ledger_for_identity = sorted(
        r["run_id"] for r in exit_9 if NO_LEDGER_FOR_IDENTITY in cert_detail(r)
    )
    unexplained_exit_9 = sorted(
        {r["run_id"] for r in exit_9}
        - set(no_row_count) - set(predates_correction) - set(no_ledger_for_identity)
    )

    if unexplained_receipt or unexplained_exit_9:
        raise FigureError(
            "the published decomposition does not account for every record, so a "
            "verifier message has changed and the figures below would describe a "
            "smaller archive than the one measured.\n"
            f"  unclassified receipt exit 2: {unexplained_receipt}\n"
            f"  unclassified certificate exit 9: {unexplained_exit_9}"
        )

    certificate_signature_failed = sorted(
        r["run_id"] for r in records if r["certificate_exit"] == 5
    )
    no_ledger_to_bind = sorted(
        r["run_id"] for r in records if r["certificate_meaning"] == NO_LEDGER_TO_BIND
    )
    binding_checked_and_holds = sorted(
        r["run_id"] for r in records
        if r["certificate_exit"] == 0 and r["certificate_meaning"] != NO_LEDGER_TO_BIND
    )
    ships_no_ledger = sorted(
        r["run_id"] for r in records
        if not (runs_dir / r["run_id"] / "proofs/itgl_ledger.jsonl").is_file()
    )

    # --- certificate field tallies ------------------------------------------
    def by_version(predicate) -> list[str]:
        return sorted(
            run_id for run_id, cert in certificates.items()
            if predicate(_semver(cert.get("sir_firewall_version")) or (0, 0, 0))
        )

    governed_by_a_contract = by_version(lambda v: v >= CONTRACT_FLOOR)
    ungoverned_by_a_contract = by_version(lambda v: v < CONTRACT_FLOOR)
    at_or_above_the_correction = by_version(lambda v: v >= BINDING_CORRECTION)
    correction_era_bound = sorted(
        set(at_or_above_the_correction) & set(binding_checked_and_holds)
    )

    row_count_absent = sorted(
        run_id for run_id, cert in certificates.items()
        if "itgl_row_count" not in cert
    )
    counters_absent = sorted(
        run_id for run_id, cert in certificates.items()
        if "counters_checked_against_ledger" not in cert
    )
    counters_false = sorted(
        run_id for run_id, cert in certificates.items()
        if cert.get("counters_checked_against_ledger") is False
    )
    counters_true = sorted(
        run_id for run_id, cert in certificates.items()
        if cert.get("counters_checked_against_ledger") is True
    )

    # --- E6: a model named by a run that called none ------------------------
    zero_call_by_class: dict[str, list[str]] = {}
    named_without_the_counter: list[str] = []
    products: set[str] = set()
    for run_id, cert in sorted(certificates.items()):
        model = cert.get("model")
        if not model:
            continue
        if "model_calls_made" not in cert:
            named_without_the_counter.append(run_id)
            products.add(model)
        elif cert.get("model_calls_made") == 0 and cert.get("provider_call_attempts") == 0:
            zero_call_by_class.setdefault(cert.get("proof_class") or "no proof_class", []).append(run_id)
            products.add(model)

    # --- the two published trees must hold the same runs --------------------
    #
    # The errata counts proofs/runs and the register counts docs/runs. If the
    # two ever diverge, one document becomes wrong about the other's tree with
    # no figure moving, so the divergence is refused here rather than published.
    published_tree_note = None
    if runs_dir.resolve() == (ROOT / "proofs/runs").resolve():
        docs_runs = ROOT / "docs/runs"
        published = {
            path.name for path in docs_runs.iterdir()
            if path.is_dir() and (path / "audit.json").is_file()
        } if docs_runs.is_dir() else set()
        if published != set(certificates):
            only_proofs = sorted(set(certificates) - published)
            only_docs = sorted(published - set(certificates))
            raise FigureError(
                "proofs/runs and docs/runs do not hold the same runs, so a figure "
                "derived from one would misdescribe the other.\n"
                f"  only in proofs/runs: {only_proofs[:5]} ({len(only_proofs)})\n"
                f"  only in docs/runs: {only_docs[:5]} ({len(only_docs)})"
            )
        published_tree_note = len(published)

    return {
        "generated_by": "tools/archive_verification_report.py --update-published-surfaces",
        # Relative to the repository. An absolute path here would publish the
        # path of whatever machine last generated the figures.
        "runs_dir": _repository_relative(runs_dir),
        "total": len(records),
        "docs_runs_total": published_tree_note,
        "certificate_rows": rows("certificate_exit", "certificate_meaning"),
        "receipt_rows": rows("receipt_exit", "receipt_meaning"),
        "incomplete": incomplete,
        "receipt_signature_failed": receipt_signature_failed,
        "legacy_no_receipt": legacy_no_receipt,
        "certificate_signature_failed": certificate_signature_failed,
        "no_ledger_to_bind": no_ledger_to_bind,
        "ships_no_ledger": ships_no_ledger,
        "binding_checked_and_holds": binding_checked_and_holds,
        "exit_9_no_row_count": no_row_count,
        "exit_9_predates_correction": predates_correction,
        "exit_9_no_ledger_for_identity": no_ledger_for_identity,
        "governed_by_a_contract": governed_by_a_contract,
        "ungoverned_by_a_contract": ungoverned_by_a_contract,
        "at_or_above_the_correction": at_or_above_the_correction,
        "correction_era_bound": correction_era_bound,
        "row_count_absent": row_count_absent,
        "counters_absent": counters_absent,
        "counters_false": counters_false,
        "counters_true": counters_true,
        "zero_call_by_class": zero_call_by_class,
        "named_without_the_counter": named_without_the_counter,
        "products_named": sorted(products),
    }


def _wrap(text: str) -> str:
    """Generated prose wraps at the width the surrounding documents use.

    A region whose lines run past the margin is obvious in a diff, and the point
    of generating these paragraphs is that nobody has to tidy them afterwards.
    """
    return "\n\n".join(
        textwrap.fill(
            " ".join(paragraph.split()),
            width=79,
            break_long_words=False,
            break_on_hyphens=False,
        )
        for paragraph in text.split("\n\n")
        if paragraph.strip()
    )


def _wrap_bullets(bullets: list[str]) -> str:
    return "\n".join(
        textwrap.fill(
            " ".join(bullet.split()),
            width=79,
            initial_indent="- ",
            subsequent_indent="  ",
            break_long_words=False,
            break_on_hyphens=False,
        )
        for bullet in bullets
    )


def replace_region(document: str, name: str, generated: str) -> str:
    begin = REGION_BEGIN.format(name=name)
    end = REGION_END.format(name=name)
    if document.count(begin) != 1 or document.count(end) != 1:
        raise FigureError(
            f"the document must carry exactly one {name!r} region; found "
            f"{document.count(begin)} opening and {document.count(end)} closing markers"
        )
    if document.index(begin) > document.index(end):
        raise FigureError(f"the {name!r} region closes before it opens")
    head, _, rest = document.partition(begin)
    _, _, tail = rest.partition(end)
    return f"{head}{begin}\n{generated.rstrip()}\n{end}{tail}"


def read_region(document: str, name: str) -> str:
    begin = REGION_BEGIN.format(name=name)
    end = REGION_END.format(name=name)
    if document.count(begin) != 1 or document.count(end) != 1:
        raise FigureError(f"the document must carry exactly one {name!r} region")
    return document.partition(begin)[2].partition(end)[0].strip("\n")


def _runs(figures: dict, key: str) -> list[str]:
    return figures[key]


def _n(figures: dict, key: str) -> int:
    return len(figures[key])


def _listing(run_ids: list[str]) -> str:
    return "\n".join(f"- `{run_id}`" for run_id in sorted(run_ids))


def _and_list(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"


# --- errata renderers --------------------------------------------------------

def render_measured_totals(figures: dict) -> str:
    lines = [
        _wrap(
            f"Measured across all {figures['total']} published run archives under "
            "`proofs/runs/`:"
        ),
        "",
        "| Check | Result | Count |",
        "|---|---|---|",
    ]
    for tool, key in (
        ("verify_certificate.py", "certificate_rows"),
        ("verify_archive_receipt.py", "receipt_rows"),
    ):
        for row in figures[key]:
            exit_code = "none" if row["exit"] is None else row["exit"]
            lines.append(f"| `{tool}` | {row['meaning']} (exit {exit_code}) | {row['count']} |")
    return "\n".join(lines)


def render_receipt_exit_two(figures: dict) -> str:
    incomplete = _n(figures, "incomplete")
    signature = _n(figures, "receipt_signature_failed")
    return _wrap(
        f"The exit 2 count is {incomplete + signature}: {incomplete} archives that are "
        f"incomplete, described in E1, and {signature} whose receipt signature does not "
        "verify, described in E2."
    )


def render_e1_affected(figures: dict) -> str:
    runs = _runs(figures, "incomplete")
    first, last = _date_span(runs)
    return _wrap(
        f"Affected runs: {len(runs)}, from {first} to {last}. Listed in Appendix A."
    )


def render_e3_effect(figures: dict) -> str:
    """E3's cross-reference, checked rather than asserted.

    Until 12 October 2026 this paragraph sent a reader to E4 for these records.
    They are not in E4: their certificates exit 0 on the no-ledger row. The two
    claims this paragraph makes about set membership are verified here, so the
    sentence cannot drift back into being wrong without stopping the generator.
    """
    legacy = set(_runs(figures, "legacy_no_receipt"))
    exit_9 = (
        set(_runs(figures, "exit_9_no_row_count"))
        | set(_runs(figures, "exit_9_predates_correction"))
        | set(_runs(figures, "exit_9_no_ledger_for_identity"))
    )
    overlap = sorted(legacy & exit_9)
    if overlap:
        raise FigureError(
            "E3 says these archives are not among E4's and some are: "
            f"{overlap[:5]} ({len(overlap)})"
        )
    ships_no_ledger = set(_runs(figures, "ships_no_ledger"))
    shipping = sorted(legacy - ships_no_ledger)
    if shipping:
        raise FigureError(
            "E3 says every receiptless archive also ships no ledger, and these do: "
            f"{shipping[:5]} ({len(shipping)})"
        )
    fail_earlier = sorted(ships_no_ledger & set(_runs(figures, "certificate_signature_failed")))
    return _wrap(
        f"**Effect.** Archive-level integrity cannot be checked for these {len(legacy)} "
        "runs. Their certificates are not among E4's. Each exits 0 on the row above "
        'that reads "verified; no ledger in the archive, so no binding was checked", '
        "because the archive ships no ledger for a binding to be checked against. "
        f"{len(ships_no_ledger)} archives in total ship no ledger; that row reads "
        f"{_n(figures, 'no_ledger_to_bind')} rather than {len(ships_no_ledger)} because "
        f"{len(fail_earlier)} of them stop earlier, on signature, and are counted in E2."
    )


def render_e4_causes(figures: dict) -> str:
    no_row_count = _n(figures, "exit_9_no_row_count")
    predates = _n(figures, "exit_9_predates_correction")
    unreachable = _n(figures, "exit_9_no_ledger_for_identity")
    total = no_row_count + predates + unreachable

    causes = [
        f"Two causes, and they account for all {total}.",
        f"*{no_row_count} carry no `itgl_row_count`.* The field postdates SIR 2.3.4, so "
        "the signed row count cannot be compared with the ledger. The terminal hash "
        "binding is checked for these and holds. Across the whole archive "
        f"{_n(figures, 'row_count_absent')} certificates carry no `itgl_row_count`; the "
        "figure here is the subset that reaches exit 9 for that reason and no other.",
        f"*{predates} sign an `itgl_final_hash` that is not the terminal hash of the "
        "ledger shipped with them.* These predate the SIR 2.3.4 evidence-binding "
        "correction, when certificate generation took that value from an environment "
        "variable or the mutable `proofs/itgl_final_hash.txt` and so could sign a hash "
        "left by an earlier run. `docs/evidence-binding-correction.md` records it.",
    ]
    if unreachable:
        causes.insert(
            1,
            f"*{unreachable} carry no `run_id` from which a ledger could be resolved.* "
            "This cause was unreachable under this measurement between 8 and 12 October "
            "2026, because the report passes either `--ledger` or `--no-ledger` for every "
            "archive. It is populated again, which means the report's invocation has "
            "changed and the figures above should be read with that in mind.",
        )
    return _wrap("\n\n".join(causes))


def render_e4_above_the_correction(figures: dict) -> str:
    bound = _n(figures, "correction_era_bound")
    era = _n(figures, "at_or_above_the_correction")
    predates = _n(figures, "exit_9_predates_correction")
    opening = (
        "**Why this is exit 9 and not exit 7.** A binding that was never made is not a "
        "binding that disagrees. "
    )
    closing = (
        "Below it, reporting a documented and disclosed format boundary as a tampering "
        f"failure would describe {predates} published archives as broken."
    )
    if bound != era:
        unbound = sorted(
            set(_runs(figures, "at_or_above_the_correction"))
            - set(_runs(figures, "correction_era_bound"))
        )
        named = _and_list([f"`{run}`" for run in unbound[:5]])
        return _wrap(
            opening
            + f"{bound} of the {era} certificates at or above SIR 2.3.4 match the ledger "
            f"shipped with them, and {era - bound} "
            f"{'does' if era - bound == 1 else 'do'} not: {named}. A mismatch at or "
            "above the correction is a real failure and is reported as one. " + closing
        )
    return _wrap(
        opening
        + "Every certificate from SIR 2.3.4 onward matches the ledger shipped with it, "
        f"{bound} of {bound}, so a mismatch at or above the correction is a real failure "
        "and is still reported as one. " + closing
    )


def render_e6_counts(figures: dict) -> str:
    ordered = sorted(
        figures["zero_call_by_class"].items(), key=lambda kv: (-len(kv[1]), kv[0])
    )
    total = sum(len(runs) for _, runs in ordered)
    breakdown = _and_list([f"{len(runs)} `{name}`" for name, runs in ordered])
    products = _and_list([f"`{product}`" for product in figures["products_named"]])
    return _wrap(
        f"**Counts.** {total} published certificates name a model and explicitly record "
        f"zero model calls: {breakdown}. A further "
        f"{_n(figures, 'named_without_the_counter')} name a model and do not carry the "
        f"counter at all. The values recorded across both groups are {products}, in the "
        "spellings the certificates carry."
    )


def render_appendix_a(figures: dict) -> str:
    runs = _runs(figures, "incomplete")
    return f"All {len(runs)} of them:\n\n{_listing(runs)}"


def render_appendix_b(figures: dict) -> str:
    runs = _runs(figures, "legacy_no_receipt")
    return f"All {len(runs)} of them:\n\n{_listing(runs)}"


# --- claims register renderers -----------------------------------------------

def render_archive_total(figures: dict) -> str:
    return _wrap(
        f"The archive holds {figures['total']} runs including failed and inconclusive "
        "ones."
    )


def render_incomplete_archives(figures: dict) -> str:
    runs = _runs(figures, "incomplete")
    first, last = _date_span(runs)
    return _wrap(
        f"**{len(runs)} archives published between {first} and {last} name "
        "`leaks_count.txt` and `harmless_blocked.txt` in their signed manifests, and a "
        "repository-wide ignore rule meant those two files were never committed.**"
    )


def _counters_bullet(figures: dict) -> str:
    """Absent, false and true are three states, and the register named one.

    Until 12 October 2026 this bullet read "All 292 report
    counters_checked_against_ledger: false". No published certificate carried the
    field at all, and tools/verify_evidence.py reports those archives as signed
    counters unknown. Absent reported as false is the defect this release is
    named for, in the document that records the release.
    """
    total = figures["total"]
    absent = _n(figures, "counters_absent")
    false = _n(figures, "counters_false")
    true = _n(figures, "counters_true")

    if absent == total:
        return (
            f"**None of the {total} published certificates carries "
            "`counters_checked_against_ledger` at all.** The field arrives with evidence "
            "contract v4 at SIR 2.4.0. `tools/verify_evidence.py` reports the signed "
            "counters as `unknown` for every one of them, which is neither agreement nor "
            "disagreement. Absent is not false."
        )
    carried = false + true
    # Number agreement. Audit 637 produced the first mixed state and this bullet
    # published "1 of the 293 published certificates carry", because it was
    # written when every count in these documents was in the hundreds. This is
    # the only generated figure that can be one: every other count paired with a
    # verb here is already above it and only grows, since the archive is never
    # reduced and the historical sets are closed.
    return (
        f"**{carried} of the {total} published certificates "
        f"{'carries' if carried == 1 else 'carry'} "
        f"`counters_checked_against_ledger`: {true} true and {false} false.** The field "
        f"arrives with evidence contract v4 at SIR 2.4.0. The remaining {absent} do not "
        "carry it, and `tools/verify_evidence.py` reports their signed counters as "
        "`unknown`, which is neither agreement nor disagreement. Absent is not false."
    )


def render_proof_qualifications(figures: dict) -> str:
    total = figures["total"]
    ungoverned = _n(figures, "ungoverned_by_a_contract")
    predates = _n(figures, "exit_9_predates_correction")
    bound = _n(figures, "correction_era_bound")
    era = _n(figures, "at_or_above_the_correction")

    return _wrap_bullets([
        f"**{ungoverned} of the {total} published certificates are governed by no "
        f"evidence contract.** The contracts begin at SIR 2.2.0 and {ungoverned} "
        "archives predate it. They are not invalid; signature, binding and custody "
        "verify. No contract governs their structure. Now disclosed by behaviour: "
        "`tools/verify_evidence.py` reports it on every pre-2.2.0 archive.",
        _counters_bullet(figures),
        f"**{predates} pre-2.3.4 certificates cannot have their ledger binding "
        "established.** Before 2.3.4 `itgl_final_hash` came from an environment "
        "variable or a mutable file. Disclosed in "
        "`docs/evidence-binding-correction.md`. Every certificate at or above 2.3.4 "
        f"matches the ledger shipped with it, {bound} of {era}.",
    ])


def render_errata_appendix_reference(figures: dict) -> str:
    runs = _n(figures, "incomplete")
    share = round(100 * runs / figures["total"])
    return _wrap(
        f"Running the documented one-command verification on any of the {runs} archives "
        "in Appendix A of `docs/archive-errata.md` prints `VERDICT: FAILED` and exits 2, "
        "because their signed manifests name two files a repository ignore rule kept "
        "from ever being committed. A reader doing exactly what the sentence invites "
        f"falsifies it on {share}% of the published archive."
    )


# --- README renderers --------------------------------------------------------

def render_readme_incomplete_archives(figures: dict) -> str:
    runs = _runs(figures, "incomplete")
    first, last = _date_span(runs)
    return _wrap(
        f"{len(runs)} archives published between {first} and {last} name "
        "`leaks_count.txt` and `harmless_blocked.txt` in their signed manifests, and a "
        "repository-wide ignore rule meant those two files were never committed. The "
        "receipt verifier reports `file listed in manifest is missing` for every one of "
        "them. They are listed in Appendix A of `docs/archive-errata.md`."
    )


ERRATA_REGIONS = {
    "measured-totals": render_measured_totals,
    "receipt-exit-2": render_receipt_exit_two,
    "e1-affected": render_e1_affected,
    "e3-effect": render_e3_effect,
    "e4-causes": render_e4_causes,
    "e4-above-the-correction": render_e4_above_the_correction,
    "e6-counts": render_e6_counts,
    "appendix-a": render_appendix_a,
    "appendix-b": render_appendix_b,
}

REGISTER_REGIONS = {
    "archive-total": render_archive_total,
    "incomplete-archives": render_incomplete_archives,
    "proof-qualifications": render_proof_qualifications,
    "errata-appendix-reference": render_errata_appendix_reference,
}

README_REGIONS = {
    "readme-incomplete-archives": render_readme_incomplete_archives,
}

SURFACES = (
    (ERRATA_PATH, ERRATA_REGIONS),
    (REGISTER_PATH, REGISTER_REGIONS),
    (README_PATH, README_REGIONS),
)


def rendered_regions(figures: dict) -> dict:
    """{document path: {region name: text}} without touching any file.

    The drift test compares this against what the documents carry, so a figure
    edited by hand in a document fails rather than being silently replaced on
    some later publication.
    """
    return {
        str(path.relative_to(ROOT)): {
            name: render(figures) for name, render in regions.items()
        }
        for path, regions in SURFACES
    }


def update_published_surfaces(figures: dict, *, dry_run: bool = False) -> list[Path]:
    """Rewrite each owned region, and report which files that changed.

    With dry_run it writes nothing and reports what it would have changed, which
    is what the drift test uses: a test that repaired the documents in order to
    pass would pass on its second run whatever the first one found.
    """
    changed = []
    for path, regions in SURFACES:
        document = path.read_text(encoding="utf-8")
        updated = document
        for name, render in regions.items():
            updated = replace_region(updated, name, render(figures))
        if updated != document:
            if not dry_run:
                path.write_text(updated, encoding="utf-8")
            changed.append(path)
    payload = json.dumps(figures, indent=2, ensure_ascii=False) + "\n"
    if not FIGURES_JSON.is_file() or FIGURES_JSON.read_text(encoding="utf-8") != payload:
        if not dry_run:
            FIGURES_JSON.write_text(payload, encoding="utf-8")
        changed.append(FIGURES_JSON)
    return changed


def measure(runs_dir: Path) -> list[dict]:
    """Run both verifiers over every archive and record what they reported.

    Separated from main() so the drift test can measure without the report's
    stdout, and so no published figure can be derived from anything but a real
    verifier run over the real archive.
    """
    records: list[dict] = []
    for run_dir in sorted(p for p in Path(runs_dir).iterdir() if p.is_dir()):
        certificate = run_dir / "audit.json"
        manifest = run_dir / "manifest.json"
        if not certificate.is_file() and not manifest.is_file():
            continue

        record = {"run_id": run_dir.name}

        if certificate.is_file():
            # Pass this run's own ledger and require the registry.
            #
            # Until 8 October 2026 this script invoked the verifier with the
            # certificate alone. It therefore relied on ledger discovery, which
            # resolves from the working directory and returns nothing for most
            # archives, and it never required registry resolution. The figures
            # this script produces are published in docs/archive-errata.md and
            # read as a statement about the archive, so a check it did not
            # perform was being counted as a check that found nothing wrong.
            ledger = run_dir / "proofs/itgl_ledger.jsonl"
            argv = [sys.executable, str(VERIFY_CERTIFICATE), str(certificate)]
            argv += ["--ledger", str(ledger)] if ledger.is_file() else ["--no-ledger"]
            argv += ["--key-registry", str(KEY_REGISTRY), "--require-registry"]
            code, detail = _exit_code(argv)
            record["certificate_exit"] = code
            meaning = CERTIFICATE_EXIT_MEANINGS.get(code, "unmapped exit code")
            if code == 0 and not ledger.is_file():
                # --no-ledger exits 0, and counting that beside a certificate
                # whose binding was checked and holds would report a skipped
                # check as a passed one. Its own row, so the two cannot be read
                # as the same outcome.
                meaning = NO_LEDGER_TO_BIND
            record["certificate_meaning"] = meaning
            record["certificate_detail"] = detail
        else:
            record["certificate_exit"] = None
            record["certificate_meaning"] = "no certificate in archive"

        if manifest.is_file():
            code, detail = _exit_code(
                [sys.executable, str(VERIFY_RECEIPT), str(run_dir),
                 "--key-registry", str(KEY_REGISTRY),
                 "--require-registry"]
            )
            record["receipt_exit"] = code
            record["receipt_meaning"] = RECEIPT_EXIT_MEANINGS.get(code, "unmapped exit code")
            record["receipt_detail"] = detail
        else:
            record["receipt_exit"] = None
            record["receipt_meaning"] = "no manifest in archive"

        records.append(record)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-derive the published archive verification figures."
    )
    parser.add_argument(
        "--runs-dir",
        default=None,
        help="Directory of per-run archives. Default: this repository's proofs/runs",
    )
    parser.add_argument("--json-out", default=None, help="Also write the full result as JSON.")
    parser.add_argument(
        "--update-published-surfaces",
        action="store_true",
        help="Rewrite the generated figure regions in docs/archive-errata.md and "
             "docs/claims-register.md, and docs/archive-figures.json, from this run.",
    )
    args = parser.parse_args()

    runs_dir = Path(args.runs_dir) if args.runs_dir else ROOT / "proofs/runs"
    if not runs_dir.is_dir():
        print(f"ERROR: no run archive directory at {runs_dir}", file=sys.stderr)
        return 2

    records = measure(runs_dir)

    def tally(field: str) -> list[tuple]:
        counts: dict = {}
        for record in records:
            counts[record[field]] = counts.get(record[field], 0) + 1
        return sorted(counts.items(), key=lambda item: -item[1])

    total = len(records)
    print(f"Published run archives examined: {total}")
    print(f"Source: {runs_dir}\n")

    print("Certificate verification (tools/verify_certificate.py)")
    # Tally on the meaning rather than the exit code, so that exit 0 with a
    # checked binding and exit 0 with no ledger to check are two rows.
    for label, count in tally("certificate_meaning"):
        code = next(
            r["certificate_exit"] for r in records if r["certificate_meaning"] == label
        )
        print(f"  exit {str(code):>4}  {count:>4}  {label}")

    print("\nArchive receipt verification (tools/verify_archive_receipt.py)")
    for code, count in tally("receipt_exit"):
        label = RECEIPT_EXIT_MEANINGS.get(code, "no manifest" if code is None else "unmapped")
        print(f"  exit {str(code):>4}  {count:>4}  {label}")

    failing = [r for r in records if r["certificate_exit"] not in (0, 9, None)]
    if failing:
        print(f"\nCertificates that FAIL verification ({len(failing)}):")
        for record in failing:
            print(f"  {record['run_id']}  exit {record['certificate_exit']}  {record['certificate_detail']}")

    incomplete = [r for r in records if r["receipt_exit"] == 2]
    if incomplete:
        print(f"\nArchives whose receipt does not verify ({len(incomplete)}):")
        for record in incomplete[:5]:
            print(f"  {record['run_id']}  {record['receipt_detail']}")
        if len(incomplete) > 5:
            print(f"  ... and {len(incomplete) - 5} more; use --json-out for the full list")

    if args.json_out:
        payload = {
            "runs_dir": str(runs_dir),
            "total_archives": total,
            "records": records,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nOK: wrote full result to {args.json_out}")

    if args.update_published_surfaces:
        try:
            figures = build_figures(records, runs_dir)
            written = update_published_surfaces(figures)
        except FigureError as exc:
            # A figure that cannot be derived is not published as a guess.
            print(f"\nERROR: {exc}", file=sys.stderr)
            return 2
        if written:
            print("\nUpdated published surfaces:")
            for path in written:
                print(f"  {path.relative_to(ROOT)}")
        else:
            print("\nPublished surfaces already match this run; nothing to write.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
