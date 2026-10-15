"""What the benchmark workflow admits, and what it verifies, before publishing.

Two things are held here.

The first is tools/check_paired_archives.py, which decides whether a dispatch's
two archives may be published at all. From SIR 2.5 the gated half is a
certificate at audit.json and the ungated half is a record at baseline.json,
and every reader downstream dispatches on that filename. A baseline archive
holding audit.json is the 2.4 shape, which is the defect the 2.5 work exists to
remove: 54 published certificates describe ungated runs as failed audits of a
gate that was not in the path.

The second is the benchmark job's own shape: that it admits before it
publishes, that it verifies each half with the verifier for its kind, and that
the live-audit pointer is offered the gate run only. Those are assertions about
the workflow's text, because a dispatch calls a provider and publishes by pull
request. What is behavioural is the tool the workflow now calls, which is why
the shell in that step is three lines and a read of its output rather than a
set of file tests written out in bash.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import _module

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/audit-and-sign.yml"
TOOL = ROOT / "tools/check_paired_archives.py"

CERTIFICATE_DOCUMENT = "audit.json"
RECORD_DOCUMENT = "baseline.json"


def _admit(runs_dir, baseline_run_id, gated_run_id):
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--runs-dir",
            str(runs_dir),
            "--baseline-run-id",
            baseline_run_id,
            "--gated-run-id",
            gated_run_id,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _benchmark_steps():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return workflow["jobs"]["benchmark-dispatch"]["steps"]


def _step(name_fragment: str) -> dict:
    steps = [step for step in _benchmark_steps() if name_fragment in str(step.get("name", ""))]
    assert len(steps) == 1, f"expected one step naming {name_fragment!r}, found {len(steps)}"
    return steps[0]


# --- admission ---------------------------------------------------------------


def test_a_record_and_a_certificate_are_admitted(published_pair):
    """The shape a 2.5 dispatch produces, and the paths come from the tool.

    Mutation applied to tools/check_paired_archives.py: returning without the
    per-archive checks, 5 failures, which are the five refusals below. Not
    this test: a pair that is already well formed is admitted either way, so
    what this case holds is the path the workflow reads, not the checks.
    """
    admitted = _admit(
        published_pair["runs_dir"],
        published_pair["baseline_run_id"],
        published_pair["gated_run_id"],
    )

    assert admitted.returncode == 0, admitted.stdout + admitted.stderr
    assert admitted.stdout.count("GATED_AUDIT_JSON=") == 1
    assert admitted.stdout.count("BASELINE_RECORD_JSON=") == 1
    gated_line = next(
        line for line in admitted.stdout.splitlines() if line.startswith("GATED_AUDIT_JSON=")
    )
    record_line = next(
        line for line in admitted.stdout.splitlines() if line.startswith("BASELINE_RECORD_JSON=")
    )
    assert gated_line.endswith(f"{published_pair['gated_run_id']}/{CERTIFICATE_DOCUMENT}")
    assert record_line.endswith(f"{published_pair['baseline_run_id']}/{RECORD_DOCUMENT}")


def test_a_baseline_archive_holding_a_certificate_is_refused(published_pair):
    """The 2.4 shape. This is the one refusal that had to exist.

    Mutation applied to tools/check_paired_archives.py: accepting whichever
    document an archive holds, 2 failures (this test and
    test_a_gated_archive_holding_a_record_is_refused).
    """
    runs_dir = published_pair["runs_dir"]
    baseline = runs_dir / published_pair["baseline_run_id"]
    certificate = runs_dir / published_pair["gated_run_id"] / CERTIFICATE_DOCUMENT
    (baseline / RECORD_DOCUMENT).unlink()
    (baseline / CERTIFICATE_DOCUMENT).write_bytes(certificate.read_bytes())

    refused = _admit(
        runs_dir, published_pair["baseline_run_id"], published_pair["gated_run_id"]
    )

    assert refused.returncode == 2
    assert "holds audit.json where baseline.json is expected" in refused.stdout


def test_a_gated_archive_holding_a_record_is_refused(published_pair):
    """The mirror of the same mistake: a gate run claiming nothing about the gate."""
    runs_dir = published_pair["runs_dir"]
    gated = runs_dir / published_pair["gated_run_id"]
    record = runs_dir / published_pair["baseline_run_id"] / RECORD_DOCUMENT
    (gated / CERTIFICATE_DOCUMENT).unlink()
    (gated / RECORD_DOCUMENT).write_bytes(record.read_bytes())

    refused = _admit(
        runs_dir, published_pair["baseline_run_id"], published_pair["gated_run_id"]
    )

    assert refused.returncode == 2
    assert "holds baseline.json where audit.json is expected" in refused.stdout


def test_an_archive_holding_both_documents_is_refused(published_pair):
    """It cannot be read as either kind, so publishing it helps no one.

    Mutation applied to tools/check_paired_archives.py: checking only that the
    expected document is present, 1 failure (this test).
    """
    runs_dir = published_pair["runs_dir"]
    baseline = runs_dir / published_pair["baseline_run_id"]
    certificate = runs_dir / published_pair["gated_run_id"] / CERTIFICATE_DOCUMENT
    (baseline / CERTIFICATE_DOCUMENT).write_bytes(certificate.read_bytes())

    refused = _admit(
        runs_dir, published_pair["baseline_run_id"], published_pair["gated_run_id"]
    )

    assert refused.returncode == 2
    assert "holds both" in refused.stdout


def test_an_untyped_archive_is_refused(published_pair):
    runs_dir = published_pair["runs_dir"]
    (runs_dir / published_pair["baseline_run_id"] / RECORD_DOCUMENT).unlink()

    refused = _admit(
        runs_dir, published_pair["baseline_run_id"], published_pair["gated_run_id"]
    )

    assert refused.returncode == 2
    assert "holds no signed document" in refused.stdout


def test_a_missing_archive_is_refused(published_pair):
    runs_dir = published_pair["runs_dir"]
    shutil.rmtree(runs_dir / published_pair["baseline_run_id"])

    refused = _admit(
        runs_dir, published_pair["baseline_run_id"], published_pair["gated_run_id"]
    )

    assert refused.returncode == 2
    assert "does not exist" in refused.stdout


def test_one_run_is_not_a_pair_with_itself(published_pair):
    """Both halves reporting one run id is a pair of nothing.

    Mutation applied to tools/check_paired_archives.py: dropping the equal-id
    check, 1 failure (this test).
    """
    runs_dir = published_pair["runs_dir"]

    refused = _admit(runs_dir, published_pair["gated_run_id"], published_pair["gated_run_id"])

    assert refused.returncode == 2
    assert "same run id" in refused.stdout


def test_the_tool_decides_the_two_filenames(published_pair):
    """The workflow reads the filenames from here rather than writing them again.

    Two places naming audit.json for the baseline half is how the workflow came
    to point at a document the 2.5 runner does not write.
    """
    tool = _module("check_paired_archives", "tools/check_paired_archives.py")

    assert tool.ROLE_DOCUMENTS == {"gated": "audit.json", "baseline": "baseline.json"}


# --- the benchmark job -------------------------------------------------------


def test_the_job_admits_the_archives_before_it_publishes():
    """Admission is in the run step, which is before every publishing step.

    A benchmark that publishes an archive and then fails has already put that
    archive in front of a reader, so the check cannot come after.
    """
    steps = _benchmark_steps()
    names = [str(step.get("name", "")) for step in steps]
    bodies = [str(step.get("run", "")) for step in steps]

    admitting = [i for i, body in enumerate(bodies) if "check_paired_archives.py" in body]
    publishing = [
        i
        for i, (name, body) in enumerate(zip(names, bodies))
        if "Publish" in name or "docs/runs" in body
    ]

    assert admitting, "no step in the benchmark job admits the pair's archives"
    assert publishing, "no publishing step found, so this test proves nothing"
    assert max(admitting) < min(publishing), (
        f"admission at steps {admitting} is not before publication at steps {publishing}"
    )


def test_each_half_is_verified_by_the_verifier_for_its_kind():
    """And the certificate verifier is never pointed at the record.

    It would fail, because tools/verify_certificate.py refuses a document that
    is not a certificate on every path including --no-ledger. Failing for the
    right reason while telling a reader nothing about the record is not
    verification.
    """
    step = _step("Verify each half with the verifier for its document kind")
    body = str(step["run"])

    assert "verify_certificate.py \"$GATED_AUDIT_JSON\"" in body
    assert "verify_baseline_record.py \"$BASELINE_RECORD_JSON\"" in body
    assert "verify_certificate.py \"$BASELINE_RECORD_JSON\"" not in body
    assert "verify_baseline_record.py \"$GATED_AUDIT_JSON\"" not in body
    # And the archive as a whole, by the command a third party runs.
    assert "verify_evidence.py" in body


def test_no_benchmark_step_names_a_baseline_certificate():
    """The old output was baseline_audit_json, naming a file 2.5 does not write.

    Mutation applied to .github/workflows/audit-and-sign.yml: restoring
    baseline_audit_json alongside the record output, 1 failure (this test).
    """
    for step in _benchmark_steps():
        body = str(step.get("run", "")) + str(step.get("env", ""))
        assert "baseline_audit_json" not in body, step.get("name")
        assert "BASELINE_AUDIT_JSON" not in body, step.get("name")


def test_the_live_pointer_is_offered_the_gate_run_only():
    """D5: latest-live-audit is a single-run truth surface for gate runs.

    Mutation applied to .github/workflows/audit-and-sign.yml: adding the
    baseline back to the candidate list, 1 failure (this test).
    """
    step = _step("Compute benchmark live-pointer truth")
    body = str(step["run"])

    assert 'candidates = [Path(os.environ.get("GATED_AUDIT_JSON", ""))]' in body
    assert "BASELINE" not in body


def test_both_jobs_check_the_typed_index_against_its_schema():
    """A published index that does not satisfy its contract is not published.

    Parsing it is not enough. What a reader needs from that document is that
    each entry declares its kind and that no entry of the wrong kind carries a
    verdict, and those are schema properties.

    Mutation applied to .github/workflows/audit-and-sign.yml: removing the
    schema check from the benchmark job, 1 failure (this test).
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    for job_name, job in workflow["jobs"].items():
        bodies = [str(step.get("run", "")) for step in job["steps"]]
        checking = [
            body
            for body in bodies
            if "benchmark_index.v3.schema.json" in body and "iter_errors" in body
        ]
        assert checking, f"{job_name} publishes the typed index without checking its schema"
        for body in checking:
            assert "proofs/runs/benchmark_index.v3.json" in body, job_name
            assert "docs/runs/benchmark_index.v3.json" in body, job_name


def test_the_benchmark_artifact_carries_the_typed_index():
    """A reader of the artifact alone gets the index that names both kinds."""
    step = _step("Upload benchmark artifact")
    paths = str(step["with"]["path"])

    assert "proofs/runs/benchmark_index.v3.json" in paths


# --- a failed admission or verification must stop publication ---------------


def _publication_steps():
    """Every step in the benchmark job that writes to the published tree."""
    out = []
    for step in _benchmark_steps():
        name = str(step.get("name", ""))
        body = str(step.get("run", ""))
        if name in ("Upload benchmark artifact (always)",):
            continue
        if "Publish" in name or "docs/runs" in body or "docs/" in body:
            out.append(step)
    return out


def test_every_publication_step_requires_admission_and_verification():
    """always() must not mean "even if the archives were refused".

    Found by an independent implementation review on 15 October 2026. Every
    publication step in this job carried `always()` and nothing else, so a
    refused admission or a failed verification did not stop the archive being
    copied to docs/runs, the markers being written, or the publishing pull
    request being opened. The admission-order test passed throughout, because
    it checks textual ordering and not whether admission succeeded.

    always() stays. It is there so a run whose *result* is AUDIT FAILED or
    INCONCLUSIVE still publishes its archive, which is a standing position of
    this project: a run that fails is evidence and is published. Neither the
    runner nor the generators exit non-zero for a failing result, so gating on
    these two steps does not touch that. What it stops is publishing an
    archive that was refused as mistyped, or that did not verify.

    Mutation applied to .github/workflows/audit-and-sign.yml: removing the
    gate from the pull-request publication step, 1 failure (this test).
    """
    steps = _publication_steps()
    assert len(steps) >= 8, [str(s.get("name")) for s in steps]

    for step in steps:
        condition = str(step.get("if", ""))
        assert "steps.run_benchmark.outcome == 'success'" in condition, step.get("name")
        assert "steps.verify_halves.outcome == 'success'" in condition, step.get("name")


def test_the_verification_step_is_addressable_by_the_publication_gate():
    """A gate on a step id is only a gate while the id exists."""
    assert _step("Verify each half with the verifier for its document kind")["id"] == (
        "verify_halves"
    )
    assert _step("Run paired benchmark through SIR")["id"] == "run_benchmark"


def test_the_verification_step_refuses_a_verifier_that_did_not_finish():
    """A crash is not an unknown, and the exit code alone cannot tell them apart.

    Python exits 1 on an uncaught exception, and this step accepts exit 1 as
    NOT ESTABLISHED. The review found that every baseline archive crashed
    after printing its report, so the step accepted a verifier that had not
    run to completion. It now reads the verifier's own verdict from its JSON
    and requires that to agree with the process exit code.

    Mutation applied to .github/workflows/audit-and-sign.yml: dropping the
    agreement check, 1 failure (this test).
    """
    body = str(_step("Verify each half with the verifier for its document kind")["run"])
    # The raw file, because YAML strips the block scalar's indentation and
    # these assertions are about whole lines.
    raw = WORKFLOW.read_text(encoding="utf-8")

    assert "--json" in body
    # The whole line, not the expression: `if False and reported != exit_code`
    # contains the expression and disables the check, and an earlier version of
    # this assertion passed against exactly that.
    assert "\n          if reported != exit_code:\n" in raw
    assert "did not run" in body
    assert "no readable report" in body
    # And the shell itself fails, rather than relying on set -e to carry an
    # embedded interpreter's status.
    assert "exit 1" in body
