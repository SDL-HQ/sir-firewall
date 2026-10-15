"""The readers that take an archive and restate it: exports and the report.

Each of these read an archive and say something about it, and each assumed the
archive's signed document was audit.json. On a baseline archive that assumption
produced three different wrong answers:

- tools/export_run_archive.py required audit.json of every archive, so a
  baseline archive could not be exported for retention at all;
- tools/export_review_bundle.py restated the run manifest through certificate
  keys, printing `result: null` and `proof_class: null`, a verdict-shaped hole
  where a reader expects a verdict;
- tools/archive_verification_report.py looked for audit.json and nothing else,
  so a baseline archive counted as an archive with no document in it and no
  verifier ran over the record. The report's figures are published.

The published_pair fixture in tests/conftest.py supplies a real published
baseline archive, because none exists in this repository yet: step 7 of
claude/2.5-spec-baseline-record-2026-10-14.md is what opens that route.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import _module

ROOT = Path(__file__).resolve().parents[1]


def _export_run_archive(tmp_path, run_path, out, *, check=True):
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/export_run_archive.py"),
            "--run-path",
            str(run_path),
            "--out",
            str(out),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if check:
        assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed


def _review_bundle(tmp_path, run_id, out, *, check=True):
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/export_review_bundle.py"),
            "--out",
            str(out),
            "--run-id",
            run_id,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if check:
        assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed


# --- tools/export_run_archive.py ---------------------------------------------


def test_a_baseline_archive_exports_for_retention(published_pair, tmp_path):
    """It could not be exported at all, because audit.json was required.

    Mutation applied to tools/export_run_archive.py: requiring audit.json of
    every archive again, 2 failures (this test and
    test_an_untyped_archive_is_not_exported, whose archive then fails on the
    required-files check rather than on having no kind).
    """
    run_path = published_pair["runs_dir"] / published_pair["baseline_run_id"]
    out = tmp_path / "export-baseline"

    _export_run_archive(published_pair["tmp_path"], run_path, out)

    manifest = json.loads((out / "bundle_manifest.json").read_text(encoding="utf-8"))
    assert manifest["signed_document"] == "baseline.json"
    assert manifest["signed_document_kind"] == "ungated_baseline_record"
    assert manifest["source_run_id"] == published_pair["baseline_run_id"]
    exported = out / "proofs/runs" / published_pair["baseline_run_id"] / "baseline.json"
    assert exported.is_file()
    assert exported.read_bytes() == (run_path / "baseline.json").read_bytes()


def test_a_certificate_archive_still_exports_and_says_which_kind(published_pair, tmp_path):
    run_path = published_pair["runs_dir"] / published_pair["gated_run_id"]
    out = tmp_path / "export-gated"

    _export_run_archive(published_pair["tmp_path"], run_path, out)

    manifest = json.loads((out / "bundle_manifest.json").read_text(encoding="utf-8"))
    assert manifest["signed_document"] == "audit.json"
    assert manifest["signed_document_kind"] == "audit_certificate"


def test_an_archive_holding_both_documents_is_not_exported(published_pair, tmp_path):
    """An archive that cannot be read as either kind is refused, not guessed at.

    Mutation applied to tools/export_run_archive.py: taking the first document
    present instead of refusing, 1 failure (this test).
    """
    run_path = published_pair["runs_dir"] / published_pair["baseline_run_id"]
    certificate = published_pair["runs_dir"] / published_pair["gated_run_id"] / "audit.json"
    (run_path / "audit.json").write_bytes(certificate.read_bytes())

    refused = _export_run_archive(
        published_pair["tmp_path"], run_path, tmp_path / "export-both", check=False
    )

    assert refused.returncode != 0
    assert "more than one signed document" in refused.stdout + refused.stderr


def test_an_untyped_archive_is_not_exported(published_pair, tmp_path):
    """No signed document means no kind, so there is nothing to export as.

    Mutation applied to tools/export_run_archive.py: exporting an archive with
    no signed document, 1 failure (this test).
    """
    run_path = published_pair["runs_dir"] / published_pair["baseline_run_id"]
    (run_path / "baseline.json").unlink()

    refused = _export_run_archive(
        published_pair["tmp_path"], run_path, tmp_path / "export-untyped", check=False
    )

    assert refused.returncode != 0
    assert "no signed document" in refused.stdout + refused.stderr


# --- tools/archive_verification_report.py ------------------------------------


def test_the_report_verifies_a_baseline_record_with_its_own_verifier(published_pair):
    """A record archive is measured, and by the record's verifier.

    Both halves here exit 5, signature verification failed, and that is the
    expected result rather than a defect: the fixture signs with a key
    generated for the test, and the report requires the key registry this
    repository publishes, which does not honour it. Exit 5 is what carries the
    information. tools/verify_baseline_record.py checks the document's type
    first and its structure second, and both of those return exit 2, so a
    record reaching the signature check is a record this report put through the
    record verifier and not through anything else. Exit 0 is covered by
    tests/test_baseline_record.py, which controls the key.

    Mutation applied to tools/archive_verification_report.py: dropping the
    baseline branch from measure, so a record archive reports no document at
    all, 2 failures (this test and
    test_the_report_counts_records_apart_from_certificates).
    """
    report = _module("archive_verification_report_readers", "tools/archive_verification_report.py")
    records = report.measure(published_pair["runs_dir"])

    by_run = {record["run_id"]: record for record in records}
    baseline = by_run[published_pair["baseline_run_id"]]
    gated = by_run[published_pair["gated_run_id"]]

    assert baseline["record_exit"] == 5, baseline.get("record_detail")
    assert baseline["record_meaning"] == report.RECORD_EXIT_MEANINGS[5]
    assert baseline["record_exit"] != 2, "the record failed its type or structure check"
    # And it is not counted as a certificate that happens to be absent.
    assert baseline["certificate_exit"] is None
    assert baseline["certificate_meaning"] == report.NO_CERTIFICATE_BUT_A_RECORD

    assert gated["record_exit"] is None
    assert gated["record_meaning"] == "no baseline record in archive"
    assert gated["certificate_exit"] == 5, gated.get("certificate_detail")


def test_the_report_counts_records_apart_from_certificates(published_pair):
    """The two document kinds get their own exit distributions.

    Mutation applied to tools/archive_verification_report.py: reporting a
    record archive as "no certificate in archive" rather than naming the
    record, 2 failures (this test and
    test_the_report_verifies_a_baseline_record_with_its_own_verifier).
    """
    report = _module("archive_verification_report_rows", "tools/archive_verification_report.py")
    runs_dir = published_pair["runs_dir"]
    figures = report.build_figures(report.measure(runs_dir), runs_dir)

    assert figures["baseline_records"] == [published_pair["baseline_run_id"]]
    assert figures["baseline_record_rows"] == [
        {"exit": 5, "meaning": report.RECORD_EXIT_MEANINGS[5], "count": 1}
    ]
    # One row per certificate, and the record is not among them.
    assert sum(row["count"] for row in figures["certificate_rows"]) == 2
    certificate_meanings = {row["meaning"] for row in figures["certificate_rows"]}
    assert report.NO_CERTIFICATE_BUT_A_RECORD in certificate_meanings


def test_the_report_refuses_an_archive_holding_both_documents(published_pair):
    """Neither figure could describe it, so it stops rather than reporting.

    Mutation applied to tools/archive_verification_report.py: measuring the
    certificate and ignoring the record, 1 failure (this test).
    """
    report = _module("archive_verification_report_both", "tools/archive_verification_report.py")
    runs_dir = published_pair["runs_dir"]
    certificate = runs_dir / published_pair["gated_run_id"] / "audit.json"
    (runs_dir / published_pair["baseline_run_id"] / "audit.json").write_bytes(
        certificate.read_bytes()
    )

    with pytest.raises(report.FigureError, match="holds both"):
        report.measure(runs_dir)


def test_the_report_identifies_the_published_ungated_baseline_certificates():
    """Section 11: the 54 are named by the legacy marker, over the real archive.

    They stay published and are not re-signed. The marker is the issuer's own
    metadata, and the figure exists so a reader of these figures is not left
    to take an AUDIT FAILED on an ungated run at face value.

    The published figure is checked against the certificates, and the
    generator is checked against the published figure. Asserting only the
    first left the generator uncovered: this test read a committed file, so a
    change to how the marker is matched could not fail it.

    The exit fields handed to build_figures here are fabricated, which is
    sound for this one figure and for nothing else in that function: the
    legacy list is derived from the certificates it loads and not from any
    verifier's output. Measuring for real takes about forty seconds, and
    tests/test_published_archive_figures.py already pays that once.

    Mutation applied to tools/archive_verification_report.py: matching on
    gate_mode anywhere in the certificate rather than inside
    benchmark_execution, 1 failure (this test).
    """
    report = _module("archive_verification_report_marker", "tools/archive_verification_report.py")
    runs_dir = ROOT / "proofs/runs"

    figures = json.loads((ROOT / "docs/archive-figures.json").read_text(encoding="utf-8"))
    legacy = figures["legacy_ungated_certificates"]

    assert len(legacy) == 54
    assert len(set(legacy)) == 54
    for run_id in legacy:
        certificate = json.loads(
            (runs_dir / run_id / "audit.json").read_text(encoding="utf-8")
        )
        assert certificate["benchmark_execution"]["gate_mode"] == "ungated"
        # Every one of them, which is what makes the qualification necessary.
        assert certificate["result"] == "AUDIT FAILED"

    unmeasured = [
        {
            "run_id": path.name,
            "certificate_exit": 0,
            "certificate_meaning": "verified",
            "receipt_exit": 0,
            "receipt_meaning": "verified",
            "record_exit": None,
            "record_meaning": "no baseline record in archive",
        }
        for path in sorted(p for p in runs_dir.iterdir() if p.is_dir())
    ]
    assert report.build_figures(unmeasured, runs_dir)["legacy_ungated_certificates"] == legacy


def test_the_two_published_trees_may_hold_a_record(published_pair):
    """The tree comparison counts either document.

    It counted audit.json alone, so a baseline record published to both trees
    read as a divergence between them and stopped the figures.

    Mutation applied to tools/archive_verification_report.py: counting
    audit.json alone in the docs/runs comparison, 1 failure (this test).
    """
    report = _module("archive_verification_report_trees", "tools/archive_verification_report.py")
    runs_dir = published_pair["runs_dir"]
    docs_runs = published_pair["tmp_path"] / "docs/runs"
    docs_runs.mkdir(parents=True, exist_ok=True)

    monkey_root = report.ROOT
    try:
        report.ROOT = published_pair["tmp_path"]
        import shutil

        for run_id in (published_pair["baseline_run_id"], published_pair["gated_run_id"]):
            shutil.copytree(runs_dir / run_id, docs_runs / run_id, dirs_exist_ok=True)
        figures = report.build_figures(report.measure(runs_dir), runs_dir)
    finally:
        report.ROOT = monkey_root

    assert figures["docs_runs_total"] == 2


# --- tools/export_review_bundle.py -------------------------------------------


def test_the_review_bundle_restates_a_record_as_a_record(published_pair, tmp_path, monkeypatch):
    """No result and no proof class, so neither is printed as null.

    Mutation applied to tools/export_review_bundle.py: restating a record
    through the certificate keys, 1 failure (this test).
    """
    run_id = published_pair["baseline_run_id"]
    staged = ROOT / "proofs/runs" / run_id
    import shutil

    shutil.copytree(published_pair["runs_dir"] / run_id, staged)
    out = tmp_path / "review-bundle"
    try:
        _review_bundle(published_pair["tmp_path"], run_id, out)
    finally:
        shutil.rmtree(staged)

    report = (out / "HUMAN_AUDIT_REPORT.md").read_text(encoding="utf-8")

    assert "## Selected run: ungated baseline record" in report
    assert "tools/verify_baseline_record.py" in report
    assert "`record_kind`" in report
    assert "`proof_class`: `null`" not in report
    assert "`result`: `null`" not in report


def test_the_review_bundle_ships_what_verifies_either_document():
    """A reviewer handed a baseline archive needs its verifier and its schema."""
    bundle = _module("export_review_bundle_readers", "tools/export_review_bundle.py")

    for required in (
        "tools/verify_certificate.py",
        "tools/verify_baseline_record.py",
        "spec/baseline_record.v1.schema.json",
        "spec/evidence_contract.v4.json",
    ):
        assert required in bundle.EXPLICIT_FILES, required
        assert (ROOT / required).is_file(), required


def test_the_one_command_verifier_runs_to_completion_on_a_baseline_archive(published_pair):
    """It crashed on every baseline archive, and exited 1 doing it.

    tools/verify_evidence.py printed a correct report and then called
    Report.verdict, which is a property, so every baseline archive raised
    TypeError after the report had been printed. Python exits 1 on an uncaught
    exception, and the benchmark workflow accepted exit 1 as NOT ESTABLISHED,
    so the crash was swallowed on the path that publishes evidence.

    Nothing in the repository exercised that line, because no baseline archive
    is published and the gated branch never had the bug. Found by an
    independent implementation review on 15 October 2026.

    Mutation applied to tools/verify_evidence.py: restoring the call, 2
    failures (this test and
    test_the_one_command_verifier_agrees_with_its_own_report).
    """
    for role in ("baseline_run_id", "gated_run_id"):
        archive = published_pair["runs_dir"] / published_pair[role]
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/verify_evidence.py"), str(archive)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            check=False,
        )
        assert "Traceback" not in completed.stderr, (role, completed.stderr)
        assert completed.returncode in (0, 1, 2), (role, completed.returncode)
        assert completed.stdout.strip(), role


def test_the_one_command_verifier_agrees_with_its_own_report(published_pair):
    """The JSON's exit_code is what the workflow checks the process code against.

    A crash after the report is printed produces a report whose exit_code
    disagrees with the process's. That disagreement is how the workflow tells
    an incomplete run from an unknown property, so it has to hold whenever the
    tool does finish.
    """
    for role in ("baseline_run_id", "gated_run_id"):
        archive = published_pair["runs_dir"] / published_pair[role]
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/verify_evidence.py"), str(archive), "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            check=False,
        )
        report = json.loads(completed.stdout)
        assert report["exit_code"] == completed.returncode, (role, report["exit_code"])
        assert report["verdict"] in ("ESTABLISHED", "NOT ESTABLISHED", "FAILED"), role


# --- the one-command verifier must not overstate what it established --------


def _verify_evidence(archive, *extra):
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/verify_evidence.py"), str(archive), "--json", *extra],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )
    report = json.loads(completed.stdout) if completed.stdout.strip() else {}
    states = {entry["property"]: entry for entry in report.get("properties", [])}
    return completed.returncode, states


def _verify_record(record, *extra, pubkey=None, cwd=None):
    """The record verifier with the fixture's own key.

    --key-registry is pointed at a path that does not exist, so registry
    resolution finds nothing and the verifier falls back to --pubkey. Without
    that, the published registry resolves signing_key_id "default" to the real
    key and the fixture's signature fails, which leaves every
    signature-dependent behaviour uncheckable.
    """
    argv = [sys.executable, str(ROOT / "tools/verify_baseline_record.py"), str(record)]
    argv += ["--key-registry", "no/such/registry.json"]
    if pubkey is not None:
        argv += ["--pubkey", str(pubkey)]
    return subprocess.run(
        [*argv, *extra],
        capture_output=True,
        text=True,
        cwd=str(cwd or ROOT),
        check=False,
    )


def test_a_record_names_its_own_ledger_and_no_ledger_stops_that(published_pair):
    """The fallback is right for a reviewer and wrong for a per-archive report.

    tools/verify_baseline_record.py resolves the ledger the record names when
    no --ledger is given, which is what a reviewer holding a record beside its
    ledger needs. tools/verify_evidence.py reports on one archive directory,
    and its baseline branch passed no ledger argument at all when the archive
    had none, so the fallback applied and an archive with no ledger could be
    reported on against a ledger elsewhere on disk. The certificate branch has
    always passed --no-ledger for this reason. Found by an independent
    implementation review on 15 October 2026.

    This case proves the two halves of the mechanism: the fallback exists, and
    --no-ledger suppresses it. That the one-command verifier now passes
    --no-ledger is held by
    test_the_one_command_verifier_passes_a_ledger_or_says_it_has_none, which is
    an assertion about the call it builds rather than about a verdict, because
    the fixture's key cannot be resolved through the published registry that
    verifier insists on.

    Mutation applied to tools/verify_baseline_record.py: dropping the
    --no-ledger branch, 2 failures (this test and
    test_the_record_verifier_can_check_a_document_without_a_ledger).
    """
    archive = published_pair["runs_dir"] / published_pair["baseline_run_id"]
    record = archive / "baseline.json"
    pubkey = published_pair["pubkey"]

    # The path the record names is relative, so the fallback resolves it
    # against the working directory rather than against the archive. Run from
    # the tree the archive sits in, the record finds its ledger and the
    # binding is established without any --ledger argument.
    verified = _verify_record(record, pubkey=pubkey, cwd=published_pair["tmp_path"])
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "bound to" in verified.stdout

    # Run from anywhere else, the same record resolves nothing. Which ledger a
    # record is checked against therefore depends on where the tool was run,
    # which is the reason a per-archive report must say which it used.
    elsewhere = _verify_record(record, pubkey=pubkey, cwd=ROOT)
    assert elsewhere.returncode != 0
    assert "was not found at" in elsewhere.stderr

    # --no-ledger suppresses the resolution, and says what is then unestablished.
    without = _verify_record(
        record, "--no-ledger", pubkey=pubkey, cwd=published_pair["tmp_path"]
    )
    assert without.returncode == 0, without.stdout + without.stderr
    assert "not established" in without.stdout
    assert "bound to" not in without.stdout


def test_the_one_command_verifier_passes_a_ledger_or_says_it_has_none(published_pair):
    """Never neither, which is what let the record's own path be used.

    Mutation applied to tools/verify_evidence.py: passing no ledger argument
    when the archive has none, 1 failure (this test).
    """
    source = (ROOT / "tools/verify_evidence.py").read_text(encoding="utf-8")
    # The baseline branch only, by function: the certificate branch in main()
    # has its own copy of both of these and has always had them, so an
    # unscoped search would pass on that copy.
    baseline = source.split("def _verify_baseline_archive(", 1)[1].split("\ndef main(", 1)[0]
    assert "verify_baseline_record.py" in baseline, "the slice is not the baseline branch"
    assert "verify_certificate.py" not in baseline, "the slice reaches the certificate branch"

    assert '["--ledger", str(ledger)] if ledger.is_file() else ["--no-ledger"]' in baseline
    # The whole condition line, not the message: `if False and ...` keeps the
    # message and disables the downgrade, and an earlier version of this
    # assertion passed against exactly that.
    assert '\n    if not ledger.is_file() and state == "established":\n' in baseline
    assert "no ledger in this run directory" in baseline


def test_signing_trust_is_unknown_after_a_public_key_fallback(published_pair):
    """--allow-unregistered-key means the registry did not resolve the key.

    The baseline branch reported "the signature verified against a key the
    registry honours for this record" whenever the signature verified, whatever
    route resolved the key. The certificate branch reports unknown and says
    what it does establish: that someone signed it, not that SDL did.

    Mutation applied to tools/verify_evidence.py: reporting established
    whenever the signature verified, 1 failure (this test).
    """
    archive = published_pair["runs_dir"] / published_pair["baseline_run_id"]

    code, states = _verify_evidence(
        archive, "--allow-unregistered-key", "--pubkey", str(published_pair["pubkey"])
    )

    assert states["signing trust"]["state"] == "unknown", states["signing trust"]
    assert "not that SDL did" in states["signing trust"]["detail"]


def test_the_record_verifier_can_check_a_document_without_a_ledger(published_pair):
    """--no-ledger, as the certificate verifier has, and it says what is missing."""
    record = published_pair["runs_dir"] / published_pair["baseline_run_id"] / "baseline.json"
    pubkey = published_pair["pubkey"]

    completed = _verify_record(record, "--no-ledger", pubkey=pubkey)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "not established" in completed.stdout
    assert "does not establish that no gate ran" in completed.stdout

    both = _verify_record(record, "--no-ledger", "--ledger", str(record), pubkey=pubkey)
    assert both.returncode != 0
    assert "mutually exclusive" in both.stdout + both.stderr
