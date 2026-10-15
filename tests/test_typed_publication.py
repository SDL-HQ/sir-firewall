"""Publishing two kinds of signed document, and pairing them.

From SIR 2.5 an archive holds one signed document: audit.json for a gated run,
baseline.json for an ungated baseline. The publisher is told which it is being
given rather than inferring it, and the two cannot be swapped: every reader
downstream dispatches on that filename.

Two rules here are the ones worth arguing with.

**A baseline record is not a row in the run index.** proofs/runs/index.json is
a single-run truth surface: every row carries a result and a proof class, and
docs/latest-run.json and the monitor window are read from it. A baseline has
neither. Publishing one there with nulls would put a verdict-shaped hole where
every other row has a verdict, which is the shape that made 54 published
baselines read as failed audits.

**So the benchmark index v3 is built from the archives.** An index derived from
the run index could never see a baseline record. v3 walks the archive
directories, and keeps every archive a pair references however old it is, so a
pair never points at an entry the document does not contain.

Checked on 15 October 2026 against five mutations of a scratch copy, never the
repository. Each count is what pytest reported:

    1. --baseline accepts a certificate                      1 failed
    2. a baseline record inserted into the run index         1 failed
    3. v3 built from the run index rather than the archives   1 failed
    4. the pair window drops archives a pair references       1 failed
    5. both documents allowed in one archive                  1 failed

and the restored copy passed 12 of 12. Each mutation is caught by exactly one
case, which is thin: these are five separate rules and each has one test. The
cases are behavioural rather than textual, so a rule removed anywhere fails the
case that exercises it, but a sixth rule added without a case would not be
covered by any of them.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

# The fixture that publishes a real pair, and the helpers it is built from,
# are in tests/conftest.py because test_typed_evidence_readers.py needs them
# too.
from conftest import _module, _publish_cli, _run_half  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

V3_SCHEMA = json.loads((ROOT / "spec/benchmark_index.v3.schema.json").read_text(encoding="utf-8"))


def test_each_half_is_archived_as_its_own_kind(published_pair):
    runs = published_pair["runs_dir"]
    baseline = runs / published_pair["baseline_run_id"]
    gated = runs / published_pair["gated_run_id"]

    assert (baseline / "baseline.json").is_file()
    assert not (baseline / "audit.json").exists(), (
        "the baseline half was archived as a certificate"
    )
    assert (gated / "audit.json").is_file()
    assert not (gated / "baseline.json").exists()

    for archive in (baseline, gated):
        assert (archive / "manifest.json").is_file()
        assert (archive / "archive_receipt.json").is_file()


def test_the_baseline_manifest_claims_no_proof_class(published_pair):
    manifest = json.loads(
        (published_pair["runs_dir"] / published_pair["baseline_run_id"] / "manifest.json")
        .read_text(encoding="utf-8")
    )

    assert manifest["extras"]["record_kind"] == "sir_ungated_baseline"
    assert "proof_class" not in manifest["extras"], (
        "a baseline enforces nothing, so its manifest names no proof class"
    )
    assert any(entry["path"] == "baseline.json" for entry in manifest["files"])


def test_the_baseline_archive_verifies_end_to_end(published_pair):
    """The published record, through the verifier, from its archive."""
    import subprocess

    archive = published_pair["runs_dir"] / published_pair["baseline_run_id"]
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/verify_baseline_record.py"),
            str(archive / "baseline.json"),
            "--ledger",
            str(archive / "proofs/itgl_ledger.jsonl"),
        ],
        cwd=published_pair["tmp_path"],
        capture_output=True,
        text=True,
        check=False,
    )
    # The signing key is ephemeral and not in the registry, so resolution falls
    # back to the public key file, which this archive does not carry. What is
    # asserted is that it got past type and structure to the key, rather than
    # being refused as the wrong kind of document.
    assert "not a SIR ungated baseline record" not in result.stderr
    assert "not valid" not in result.stderr, result.stderr


def test_the_run_index_holds_the_gate_run_only(published_pair):
    """The rule that keeps a verdict-shaped hole out of the truth surface."""
    index = json.loads(
        (published_pair["runs_dir"] / "index.json").read_text(encoding="utf-8")
    )
    run_ids = [row["run_id"] for row in index["runs"]]

    assert published_pair["gated_run_id"] in run_ids
    assert published_pair["baseline_run_id"] not in run_ids, (
        "the baseline record became a single-run truth row, which gives it a null result "
        "where every other row has a verdict"
    )
    for row in index["runs"]:
        assert row["result"] is not None


def test_the_v3_index_holds_both_kinds(published_pair):
    index = json.loads(
        (published_pair["runs_dir"] / "benchmark_index.v3.json").read_text(encoding="utf-8")
    )

    kinds = {entry["run_id"]: entry["entry_kind"] for entry in index["entries"]}
    assert kinds[published_pair["baseline_run_id"]] == "ungated_baseline_record"
    assert kinds[published_pair["gated_run_id"]] == "audit_certificate"

    baseline_entry = next(
        entry for entry in index["entries"]
        if entry["run_id"] == published_pair["baseline_run_id"]
    )
    assert baseline_entry["forwarding"] == {
        "prompts_forwarded": 2,
        "expected_block_prompts_forwarded": 1,
        "expected_allow_prompts_forwarded": 1,
        "provider_call_attempts": 2,
        "provider_call_successes": 2,
        "provider_call_failures": 0,
    }
    assert "result" not in baseline_entry
    assert "proof_class" not in baseline_entry


def test_the_v3_index_satisfies_its_published_contract(published_pair):
    index = json.loads(
        (published_pair["runs_dir"] / "benchmark_index.v3.json").read_text(encoding="utf-8")
    )
    errors = [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in Draft202012Validator(V3_SCHEMA).iter_errors(index)
    ]
    assert not errors, errors[:10]


def test_the_v3_pointers_name_gate_runs_only(published_pair):
    index = json.loads(
        (published_pair["runs_dir"] / "benchmark_index.v3.json").read_text(encoding="utf-8")
    )
    kinds = {entry["run_id"]: entry["entry_kind"] for entry in index["entries"]}

    for pointer in ("latest_run", "latest_passing_run"):
        row = index.get(pointer)
        if row:
            assert kinds.get(row["run_id"]) == "audit_certificate", (pointer, row)


def test_a_pair_of_the_two_published_documents_is_valid(published_pair):
    """The pair, assessed from the two archived documents."""
    import pair_validation

    runs = published_pair["runs_dir"]
    record = json.loads(
        (runs / published_pair["baseline_run_id"] / "baseline.json").read_text(encoding="utf-8")
    )
    certificate = json.loads(
        (runs / published_pair["gated_run_id"] / "audit.json").read_text(encoding="utf-8")
    )

    assessment = pair_validation.validate_pair(record, certificate)

    assert assessment["pair_status"] == "valid_complete", assessment
    figures = assessment["gate_figures"]
    assert figures["expected_block_prompts"] == 1
    assert figures["expected_block_prompts_reset"] == 0
    assert (
        figures["expected_block_prompts_blocked_by_gate"]
        + figures["expected_block_prompts_passed_by_gate"]
        == 1
    )
    # The gate stopped the blocked prompt from reaching the provider, which is
    # the observed quantity rather than a claim about harm.
    assert assessment["deltas"]["provider_call_attempts_delta"] < 0


def test_the_index_keeps_every_archive_a_pair_references(published_pair):
    """A pair must never point at an entry the index does not contain.

    The window is the most recent archives, so without this the older half of a
    pair falls out and a reader cannot tell the difference between an archive
    that aged out and one that was never published.
    """
    publisher = _module("publish_run_window", "tools/publish_run.py")
    runs_dir = published_pair["runs_dir"]
    pairs_dir = runs_dir / "pairs"
    pairs_dir.mkdir(parents=True, exist_ok=True)
    (pairs_dir / "p1.json").write_text(
        json.dumps(
            {
                "pair_id": "p1",
                "pair_key": "k",
                "baseline_run_id": published_pair["baseline_run_id"],
                "gated_run_id": published_pair["gated_run_id"],
            }
        ),
        encoding="utf-8",
    )

    index = publisher._build_benchmark_index_v3(
        runs_dir=runs_dir, pairs_dir=pairs_dir, keep=1
    )

    run_ids = {entry["run_id"] for entry in index["entries"]}
    assert published_pair["baseline_run_id"] in run_ids
    assert published_pair["gated_run_id"] in run_ids
    assert index["pairs"][0]["pair_form"] == "record_and_certificate"


def test_publishing_a_certificate_as_a_baseline_is_refused(published_pair):
    """The flag and the document must agree, or a document of one kind lands at
    the other's filename and every reader downstream dispatches on it."""
    tmp_path = published_pair["tmp_path"]

    certificate = published_pair["runs_dir"] / published_pair["gated_run_id"] / "audit.json"
    staged = tmp_path / "proofs/moved-audit.json"
    staged.write_text(certificate.read_text(encoding="utf-8"), encoding="utf-8")

    refused = _publish_cli(
        tmp_path, "--baseline", "proofs/moved-audit.json", check=False
    )

    assert refused.returncode != 0
    assert "audit_certificate" in refused.stderr
    assert "--cert" in refused.stderr


def test_both_flags_at_once_are_refused(published_pair):
    refused = _publish_cli(
        published_pair["tmp_path"], "--cert", "a.json", "--baseline", "b.json", check=False
    )

    assert refused.returncode != 0
    assert "mutually exclusive" in refused.stderr


def test_an_archive_cannot_gain_a_second_document(published_pair):
    """One run, one signed document, enforced at publication."""
    tmp_path = published_pair["tmp_path"]

    record = published_pair["runs_dir"] / published_pair["baseline_run_id"] / "baseline.json"
    again = tmp_path / "proofs/again.json"
    again.write_text(record.read_text(encoding="utf-8"), encoding="utf-8")

    refused = _publish_cli(tmp_path, "--baseline", "proofs/again.json", check=False)

    assert refused.returncode != 0
    assert "already contains a signed document" in refused.stderr


# --- the superseded index must not contradict the typed one -----------------


def _write_pair_artifact(published_pair):
    """The unsigned artefact the paired runner writes, for a 2.5 pair."""
    pairs = published_pair["runs_dir"] / "pairs"
    pairs.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pair_id": "20261015-000000-aaaaaaaaaaaa",
        "pair_key": "provider=xai|model=xai/grok-3-beta",
        "baseline_run_id": published_pair["baseline_run_id"],
        "gated_run_id": published_pair["gated_run_id"],
        "pair_status": "valid_complete",
    }
    (pairs / f"{artifact['pair_id']}.json").write_text(
        json.dumps(artifact, indent=2), encoding="utf-8"
    )
    return pairs


def test_the_superseded_index_omits_a_pair_it_cannot_express(published_pair):
    """Two published indexes must not disagree about one pair.

    benchmark_index.v2.json's pair reader assumes both halves are
    certificates: it reads runs/<id>/audit.json for each side. Handed a pair
    from 2.5 it read a file that does not exist for the baseline half,
    reported the pair invalid_evidence_gap, and published an evidence link to
    that nonexistent file, while v3 reported the same pair valid_complete. A
    reader comparing the two cannot tell which is current. Found by an
    independent implementation review on 15 October 2026.

    The omission is named in the document, with the count and the reason, so
    the difference between the two indexes' pair counts is explained where a
    reader finds it rather than left as a discrepancy.

    Mutations applied to tools/publish_run.py, both detected: putting the pair
    through the legacy reader again, 1 failure (this test); dropping the
    omission record from the document, 1 failure (this test).
    """
    publisher = _module("publish_run_v2_omission", "tools/publish_run.py")
    runs_dir = published_pair["runs_dir"]
    pairs_dir = _write_pair_artifact(published_pair)

    v2 = publisher._build_benchmark_index_v2(runs_dir=runs_dir, runs=[], pairs_dir=pairs_dir)
    v3 = publisher._build_benchmark_index_v3(runs_dir, pairs_dir, keep=200)

    assert v2["pairs"] == []
    assert v2["pairs_omitted"] == ["20261015-000000-aaaaaaaaaaaa"]
    assert "cannot be expressed in this index" in v2["pairs_omitted_reason"]
    assert v2["superseded_by"] == publisher.BENCHMARK_INDEX_V3_VERSION

    # The pair is in v3, as the omission reason says.
    assert [p["pair_form"] for p in v3["pairs"]] == ["record_and_certificate"]


def test_no_index_publishes_an_evidence_link_to_a_file_that_is_not_there(published_pair):
    """The legacy reader's link was runs/<baseline>/audit.json, which a 2.5
    baseline archive does not have.

    Checked against both indexes rather than only the one that had the defect,
    because the property is about what either may publish.
    """
    publisher = _module("publish_run_links", "tools/publish_run.py")
    runs_dir = published_pair["runs_dir"]
    pairs_dir = _write_pair_artifact(published_pair)

    for index in (
        publisher._build_benchmark_index_v2(runs_dir=runs_dir, runs=[], pairs_dir=pairs_dir),
        publisher._build_benchmark_index_v3(runs_dir, pairs_dir, keep=200),
    ):
        for pair in index["pairs"]:
            for name, reference in (pair.get("evidence") or {}).items():
                relative = str(reference).split("runs/", 1)[-1]
                assert (runs_dir / relative).is_file(), (index["version"], name, reference)


def test_a_legacy_certificate_pair_still_appears_in_the_superseded_index(published_pair):
    """Guard the guard: the omission is scoped to pairs with a record.

    Mutation applied to tools/publish_run.py: omitting every pair, 1 failure
    (this test).
    """
    publisher = _module("publish_run_legacy_pair", "tools/publish_run.py")
    runs_dir = published_pair["runs_dir"]
    pairs_dir = _write_pair_artifact(published_pair)

    # Make the baseline half look like a pre-2.5 certificate archive.
    baseline = runs_dir / published_pair["baseline_run_id"]
    certificate = runs_dir / published_pair["gated_run_id"] / "audit.json"
    (baseline / "baseline.json").unlink()
    (baseline / "audit.json").write_bytes(certificate.read_bytes())

    v2 = publisher._build_benchmark_index_v2(runs_dir=runs_dir, runs=[], pairs_dir=pairs_dir)

    assert v2["pairs_omitted"] == []
    assert len(v2["pairs"]) == 1
