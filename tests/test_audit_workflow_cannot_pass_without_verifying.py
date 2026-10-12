"""A green audit job must mean the certificate was verified, not skipped.

Item 1's condition is that a failed or unassessed execution cannot resemble a
clean assessment, in stdout, exit code, summary counters or certificate. That
was applied to the runner and to the certificate. It was not applied to the
workflow's own verification steps, which is where this file comes in.

Until 12 October the steps that validate the certificate contract and verify
the certificate signature each began:

    if [ -z "${AUDIT_JSON:-}" ] || [ ! -f "$AUDIT_JSON" ]; then
      echo "SKIP: generate_certificate.py did not produce a current-run certificate path."
      exit 0
    fi

so a job could go green having verified nothing. The finalize step does carry a
missing-certificate net, but it is gated on the publication context and
therefore only applies on main. A branch dispatch has no net, and a branch
dispatch is precisely what docs/key-custody.md tells us to trust before calling
a rotation complete, and what was used to validate the 2.4.0 version bump.

A certificate is produced for failed and inconclusive runs too, because the
archive holds artefacts for both passes and failures. An absent certificate is
therefore a defect rather than a state to step over.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/audit-and-sign.yml"

# The tools whose job is to establish something about the certificate. A step
# that runs one of these and can exit 0 without running it is the defect.
VERIFYING_TOOLS = (
    "validate_certificate_contract.py",
    "verify_certificate.py",
    "verify_archive_receipt.py",
    "verify_evidence.py",
)


def _steps():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step.get("run"), str):
                steps.append((step.get("name") or "unnamed", step["run"]))
    return steps


def _verifying_steps():
    return [
        (name, run)
        for name, run in _steps()
        if any(tool in run for tool in VERIFYING_TOOLS)
    ]


def test_the_workflow_has_verifying_steps():
    """Guard the guard. A rename must not make this file vacuous."""
    found = _verifying_steps()

    assert found, (
        "no step in the audit workflow runs a certificate verification tool; "
        f"looked for {VERIFYING_TOOLS}"
    )
    assert len(found) >= 2, [name for name, _ in found]


@pytest.mark.parametrize("name", [name for name, _ in _verifying_steps()])
def test_no_verifying_step_can_exit_zero_without_verifying(name):
    """The escape hatch, by name, so a failure says which step grew one."""
    run = next(body for step_name, body in _verifying_steps() if step_name == name)

    assert not re.search(r"^\s*exit 0\s*$", run, flags=re.MULTILINE), (
        f"step {name!r} contains a bare `exit 0`, so it can report success "
        "without having verified anything. A missing certificate is a defect: "
        "fail instead of skipping"
    )


@pytest.mark.parametrize("name", [name for name, _ in _verifying_steps()])
def test_a_missing_certificate_fails_the_step(name):
    """Every guard on the certificate path must refuse rather than step over."""
    run = next(body for step_name, body in _verifying_steps() if step_name == name)
    if "AUDIT_JSON" not in run:
        pytest.skip(f"{name} does not guard on the certificate path")

    assert "exit 1" in run, (
        f"step {name!r} guards on the certificate path but never fails; a run "
        "that produced no certificate would pass this step"
    )


def test_the_skip_wording_is_gone_everywhere():
    """It was in three places, and two of them ran on every branch.

    Keyed to the wording rather than to a count, so reintroducing it anywhere in
    the workflow fails here.
    """
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "SKIP: generate_certificate.py did not produce" not in text, (
        "the skip-on-missing-certificate guard is back; a green job would again "
        "be compatible with nothing having been verified"
    )


def test_the_finalize_net_is_still_publication_gated_and_so_not_relied_on():
    """Records why the step guards exist rather than leaning on the net.

    The finalize step's missing-certificate check is gated on the publication
    context, so it covers main and not a branch. That is reasonable, because the
    signal it reads is a marker only produced when publishing. This asserts the
    gating is still there, so that if it ever becomes unconditional someone
    revisits whether the per-step failures are still the thing carrying this.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    index = text.find("Run marker was not produced")

    assert index > 0, "the finalize net is gone; the per-step guards are now the only cover"
    preceding = text[max(0, index - 400):index]
    assert "CANONICAL_PUBLICATION_CONTEXT" in preceding, (
        "the finalize net no longer looks publication-gated; if it now applies on "
        "a branch, the comments in the verifying steps need updating"
    )
