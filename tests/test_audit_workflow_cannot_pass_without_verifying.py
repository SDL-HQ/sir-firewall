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

import json
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
    # From SIR 2.5 an archive holds one of two signed documents, and a step
    # that verifies only the record is as much a verifying step as one that
    # verifies only a certificate. Without this name such a step would not be
    # a verifying step to the guards below, so a bare `exit 0` in it would
    # pass unnoticed.
    "verify_baseline_record.py",
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


def _step_conditions():
    """Every run step's own `if:` and its job's, which _steps() discards.

    _steps() returns shell bodies only. Until 13 October 2026 every test in this
    file therefore examined what a step does and nothing about whether it runs,
    so gating a whole step at YAML level was invisible here: a one-line
    `if: ${{ env.CANONICAL_PUBLICATION_CONTEXT == 'true' }}` on the finalize
    step would have reopened the branch-dispatch gap with every assertion in
    this file still passing. CANONICAL_PUBLICATION_CONTEXT is itself a job-level
    `env:` expression, so YAML is where someone would naturally reach for it.
    Found by an independent review, not by this file.

    Returns {step name: (step if, job if, job env)}.
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    conditions = {}
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step.get("run"), str):
                conditions[step.get("name") or "unnamed"] = (
                    str(step.get("if") or ""),
                    str(job.get("if") or ""),
                    json.dumps(job.get("env") or {}, sort_keys=True),
                )
    return conditions


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
    """The marker net reads a publication-only signal, so it stays gated.

    This records why the per-step guards exist rather than leaning on that net.
    The run-marker check reads LATEST_RUN_STATUS, which only a publishing run
    produces, so gating it is correct and making it unconditional would be
    wrong.

    Since 13 October 2026 it is no longer the only cover on a branch: the
    finalize step also requires the certificate's own result, unconditionally,
    which is held by test_a_branch_dispatch_cannot_go_green_on_a_bad_certificate
    below. This assertion remains because the two are different mechanisms and
    the gating of this one is still deliberate.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    index = text.find("Run marker was not produced")

    assert index > 0, "the finalize net is gone; the per-step guards are now the only cover"
    preceding = text[max(0, index - 400):index]
    assert "CANONICAL_PUBLICATION_CONTEXT" in preceding, (
        "the finalize net no longer looks publication-gated; if it now applies on "
        "a branch, the comments in the verifying steps need updating"
    )

# --- published archives reach main through a pull request ---------------------


def _publication_steps():
    """Every step that stages an archive and publishes it.

    There are two, one per publishing job. Until 14 October 2026 this helper
    returned the first step it found, so every guard below ran against the
    audit job alone. The benchmark job was still pushing to main directly, and
    the first paired benchmark after the 2.4.0 merge failed on "GH013:
    Repository rule violations" with the run already complete: the evidence it
    had produced was never published. Collecting every publishing step is what
    makes a second publication path inherit this contract rather than sit
    outside it.
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    found = []
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            run = step.get("run")
            if isinstance(run, str) and "check_archive_staged.py" in run:
                found.append((job_name, job, step))
    return found


PUBLICATION_STEPS = _publication_steps()
PUBLICATION_IDS = [job_name for job_name, _job, _step in PUBLICATION_STEPS]
PUBLICATION_CASE = pytest.mark.parametrize(
    "job_name,job,step", PUBLICATION_STEPS, ids=PUBLICATION_IDS or ["none"]
)


def test_every_publishing_job_is_covered():
    """Guard the guard. A rename must not make the rest of this vacuous."""
    assert len(PUBLICATION_STEPS) == 2, (
        "this file expects two publishing steps, the audit job's and the "
        f"benchmark job's, and found {PUBLICATION_IDS}. A new publishing path "
        "must be held to the guards below, not counted around them"
    )


@PUBLICATION_CASE
def test_the_publication_step_says_what_it_does(job_name, job, step):
    assert "pull request" in (step.get("name") or "").lower(), (
        f"the publication step in {job_name} no longer says it opens a pull "
        f"request: {step.get('name')!r}"
    )


@PUBLICATION_CASE
def test_the_archive_is_not_pushed_straight_to_main(job_name, job, step):
    """The first run after the 2.4.0 merge could not publish.

    It pushed to main directly and the Protect Main ruleset declined it with
    "4 of 4 required status checks are expected", because a push from
    automation arrives with no checks against it. That is item 0's freeze
    mechanism working: a direct push from automation is what item 0 set out to
    prevent, and this workflow had been relying on being able to do it.

    Publishing through a pull request keeps the ruleset intact and puts every
    published archive on a path where the required checks ran.
    """
    run = step["run"]

    assert "gh pr create" in run, (
        f"{job_name} does not publish its archive as a pull request"
    )

    branches = re.findall(r'git (?:switch -c|checkout -b) "\$(\w+)"', run)
    assert branches, (
        f"{job_name} does not create a branch of its own to publish from"
    )
    for branch in branches:
        assert f'--set-upstream origin "${branch}"' in run, (
            f"{job_name} creates ${branch} but does not push it"
        )

    # A push that names no branch of its own goes to main. That is the GH013
    # path, and it is what the benchmark job did until 14 October 2026.
    for line in run.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("echo "):
            continue
        if "git push" not in stripped:
            continue
        remainder = stripped.split("git push", 1)[1]
        assert remainder.startswith(" --set-upstream origin"), (
            f"{job_name} runs {stripped!r}. A push that names no branch of its "
            "own targets main, which the Protect Main ruleset declines"
        )

    for forbidden in ("git push origin main", "git pull --rebase origin main"):
        assert forbidden not in run, (
            f"the publication step in {job_name} contains {forbidden!r}, which "
            "is the direct-push path the Protect Main ruleset declines"
        )


@PUBLICATION_CASE
def test_the_job_can_open_a_pull_request(job_name, job, step):
    """Permissions, so the step fails at review rather than in production."""
    permissions = job.get("permissions") or {}

    assert permissions.get("pull-requests") == "write", (
        f"{job_name} opens a pull request but lacks pull-requests: write"
    )
    assert permissions.get("contents") == "write"


@PUBLICATION_CASE
def test_a_pending_publication_is_reported_rather_than_hidden(job_name, job, step):
    """Auto-merge may be unavailable, and then nothing publishes.

    That is acceptable only if it is visible. A step that opened a pull request
    nobody merges and said nothing would be the same shape as the skip this
    file was written for: the run looks complete and the archive is not there.
    """
    run = step["run"]

    assert "--auto" in run, (
        f"{job_name} does not attempt auto-merge, so publication needs a human "
        "every run"
    )
    assert "Publication is pending, not failed" in run, (
        "a pull request that could not auto-merge must say so in the log"
    )
    assert "Nothing to publish" in run, (
        "a run that changed no files should say so rather than committing "
        "nothing silently"
    )


@PUBLICATION_CASE
def test_a_failed_push_is_not_reported_as_nothing_to_publish(job_name, job, step):
    """The retry loop must not be able to turn a failure into a clean exit.

    The benchmark job's first conversion kept its old sync-and-retry loop and
    put the commit inside it. A second pass round that loop finds its own
    commit already made, so `git diff --cached --quiet` is true and the step
    exits 0 saying "Nothing to publish", with the push never having succeeded
    and no pull request opened. That is item 1's shape again: a run that
    published nothing, reporting as a run with nothing to publish.
    """
    run = step["run"]

    lines = run.splitlines()
    loop_depth = 0
    depth_at_commit = None
    for line in lines:
        stripped = line.strip()
        if re.match(r"^(for|while|until)\b.*\bdo$", stripped):
            loop_depth += 1
        elif stripped == "done":
            loop_depth -= 1
        elif stripped.startswith("git commit"):
            depth_at_commit = loop_depth

    assert depth_at_commit == 0, (
        f"{job_name} commits inside a retry loop (depth {depth_at_commit}). A "
        "second pass finds nothing staged and exits 0 as though there had been "
        "nothing to publish"
    )


def test_publishing_cannot_retrigger_the_audit():
    """A proof branch must not start another audit, which would not terminate."""
    import yaml

    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow.get(True) or workflow.get("on")

    assert "pull_request" not in triggers, (
        "this workflow now runs on pull_request, so a proof pull request would "
        "start another audit, which would open another pull request"
    )
    ignored = set(triggers["push"].get("paths-ignore") or [])
    for path in ("proofs/**", "docs/**"):
        assert path in ignored, (
            f"{path} is not in paths-ignore, so merging a proof pull request would "
            "start another audit"
        )

    # Derived from what the publication steps actually stage rather than from a
    # fixed list. On 12 October the publication step began regenerating the
    # archive figures the README carries, so it staged README.md, which the
    # fixed list above did not cover: a merged proof would have started another
    # audit, which would have published another proof.
    staged = set()
    for _, run in _steps():
        if "git add " not in run:
            continue
        for line in run.splitlines():
            line = line.strip()
            if not line.startswith("git add "):
                continue
            for token in line[len("git add "):].split():
                if token.startswith("$") or token in {"||", "true", "&&"}:
                    continue
                staged.add(token.rstrip("/"))

    assert staged, "no publication step stages anything; this guard is vacuous"

    def covered(path: str) -> bool:
        for pattern in ignored:
            if pattern == path:
                return True
            if pattern.endswith("/**") and (
                path == pattern[:-3] or path.startswith(pattern[:-2])
            ):
                return True
        return False

    uncovered = sorted(path for path in staged if not covered(path))
    assert not uncovered, (
        f"the publication steps stage {uncovered}, which paths-ignore does not "
        "cover, so merging a published proof would start another audit and that "
        "audit would publish another proof"
    )


def test_the_proof_pull_request_is_not_opened_by_the_actions_bot():
    """A bot-authored pull request cannot run the checks it exists to run.

    A pull request opened with GITHUB_TOKEN is authored by the Actions bot, and
    GitHub does not let that event start further workflows. Proof pull request
    #342 therefore sat with "4 workflows awaiting approval" and could never
    merge: publication was permanently pending while the audit itself was
    complete and verified.

    The step now prefers SIR_AUDIT_PUSH_TOKEN, which this workflow already
    checks out with on main, so the pull request is opened by the same identity
    that pushed the branch. The fallback to GITHUB_TOKEN is deliberate, so a
    fork or a repository without the secret keeps the old behaviour rather than
    failing to publish at all, which is why this asserts the preference rather
    than the absence of the default.

    That token needs pull-requests write as well as the contents write it
    already carries. With contents write alone the branch pushes and gh pr
    create fails, which reports as publication pending rather than as a failed
    audit, so it looks like the defect this replaced.

    This route is only safe while the workflow has no pull_request trigger,
    which test_publishing_cannot_retrigger_the_audit holds. Opening the pull
    request as a person means its creation does start workflows, and an audit
    among them would publish another proof.
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if "gh pr create" in (step.get("run") or "")
    ]

    assert steps, "no step opens the proof pull request; this guard is vacuous"
    for step in steps:
        token = (step.get("env") or {}).get("GH_TOKEN", "")
        assert "SIR_AUDIT_PUSH_TOKEN" in token, (
            f"step {step.get('name')!r} opens the proof pull request with "
            f"GH_TOKEN={token!r}. Opened with GITHUB_TOKEN alone it is authored "
            "by the Actions bot, its required checks never run, and publication "
            "stays pending forever"
        )
        assert token.index("SIR_AUDIT_PUSH_TOKEN") < token.index("GITHUB_TOKEN"), (
            "the dedicated token must be preferred, not used as the fallback"
        )


def _result_mapping_steps():
    """Every step that turns a recorded run result into the published marker.

    Keyed to what the step writes rather than to the result strings it names.
    The previous key was the literal "AUDIT PASSED" plus a `status = `
    assignment, which stopped matching anything the moment the mapping moved to
    tools/certificate_results.py, and a guard that matches nothing passes.
    """
    return [
        (name, run)
        for name, run in _steps()
        if "docs/latest-run.json" in run and "write_text" in run
    ]


def _marker_program(run: str) -> str:
    """The Python a marker step runs, exactly as the runner would see it."""
    match = re.search(r"python - <<'PY'\n(.*?)\n\s*PY\s*$", run, re.S)
    assert match, "marker step no longer runs a python heredoc; update this extractor"
    lines = match.group(1).splitlines()
    indent = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
    return "\n".join(l[indent:] for l in lines) + "\n"


def test_there_are_two_result_markers():
    """Guard the guard: the tests below iterate these, and an empty list passes."""
    names = [name for name, _ in _result_mapping_steps()]
    assert len(names) == 2, names


def test_an_unrecognised_run_result_is_not_published_as_a_verdict():
    """Unknown is not a verdict, in either marker.

    Until 13 October 2026 the benchmark marker read:

        else:
            status = "FAIL"

    so an absent, malformed or unrecognised result became a conclusive failure.
    The single-run marker already raised SystemExit on the same input. Both
    behaviours are safe in the sense that neither publishes a false pass, and
    they are not equally true: a conclusive FAIL describes a run the evidence
    does not describe, which is the defect this release is named for, reported
    in the other direction.

    The behaviour itself is exercised in
    test_each_marker_publishes_exactly_the_declared_results; this checks the
    shape, so the failure message says where to look.
    """
    for name, run in _result_mapping_steps():
        assert "except UnrecognisedResult" in run and "raise SystemExit" in run, (
            f"step {name!r} does not refuse a result outside the declared set"
        )
        assert not re.search(r"else:\s*\n\s*status = ", run), (
            f"step {name!r} assigns a status in an else branch, so a result it "
            "does not recognise is published as a conclusive verdict"
        )


def test_every_marker_takes_its_results_from_the_declared_set():
    """One declaration, so a fourth value is authorised in one place.

    Replaces test_both_markers_recognise_the_same_three_results, which checked
    that each marker contained the three result strings. Codex added a fourth
    accepted branch to a marker in memory, kept the original three, and that
    test still passed: it tested presence, not the accepted set. A marker that
    compares a result against a literal of its own is a second declaration,
    whatever the literal is.
    """
    for name, run in _result_mapping_steps():
        assert "from certificate_results import" in run and "status_for(" in run, (
            f"step {name!r} does not map results through tools/certificate_results.py"
        )
        for literal in ('"AUDIT PASSED"', '"AUDIT FAILED"', '"INCONCLUSIVE"'):
            assert literal not in run, (
                f"step {name!r} names {literal} itself, which is a second "
                "declaration of the recognised results"
            )
        import ast

        compared = [
            node.lineno
            for node in ast.walk(ast.parse(_marker_program(run)))
            if isinstance(node, ast.Compare)
            and any(
                isinstance(operand, ast.Name) and operand.id == "result"
                for operand in [node.left, *node.comparators]
            )
        ]
        assert not compared, (
            f"step {name!r} compares the result itself rather than through "
            f"status_for, at program lines {compared}"
        )


# Values a marker must refuse. Near misses of declared values first, because
# the markers used to normalise with strip().upper() and would have accepted
# them; then the candidate a 2.5 baseline result might take, which has to be
# declared in tools/certificate_results.py before any reader accepts it.
_UNDECLARED_RESULTS = (
    "audit passed",
    " AUDIT PASSED",
    "AUDIT PASSED\n",
    "Inconclusive",
    "BASELINE COMPLETE",
    "",
    None,
    17,
)


def _run_marker(tmp_path, run: str, result, extra: dict | None = None) -> tuple[int, dict | None, str]:
    """Execute a marker's own program against a run whose result is `result`.

    `extra` is merged into both documents a marker can read, the current-run
    certificate and the latest row of the run index, so one call exercises
    whichever of the two the step under test reads.
    """
    import os
    import shutil
    import subprocess
    import sys

    work = tmp_path / "work"
    if work.exists():
        shutil.rmtree(work)
    (work / "tools").mkdir(parents=True)
    shutil.copy(ROOT / "tools" / "certificate_results.py", work / "tools")
    (work / "proofs" / "runs").mkdir(parents=True)

    certificate = {"result": result, "jailbreaks_leaked": 0, "harmless_blocked": 0, **(extra or {})}
    (work / "audit.json").write_text(json.dumps(certificate), encoding="utf-8")
    index = {
        "runs": [
            {"result": result, "run_id": "r", "date": "2026-10-14T00:00:00Z", **(extra or {})}
        ]
    }
    (work / "proofs" / "runs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    env_file = work / "github_env"
    env_file.write_text("", encoding="utf-8")

    env = {
        **os.environ,
        "AUDIT_JSON": str(work / "audit.json"),
        "GITHUB_ENV": str(env_file),
        "GITHUB_SHA": "0" * 40,
        "GITHUB_REPOSITORY": "SDL-HQ/sir-firewall",
        "GITHUB_RUN_ID": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-"],
        input=_marker_program(run),
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    marker = work / "docs" / "latest-run.json"
    published = json.loads(marker.read_text(encoding="utf-8")) if marker.is_file() else None
    return completed.returncode, published, completed.stderr


def test_each_marker_publishes_exactly_the_declared_results(tmp_path):
    """Behaviour, not text: run each marker and see what it accepts.

    Every declared result is published with its declared status, and every
    undeclared one stops the step with nothing published. An extra branch in a
    marker, a normalisation step, or a mapping that disagrees with the
    declaration each fails here, whatever the step's text looks like.
    """
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    try:
        from certificate_results import RESULT_STATUS
    finally:
        sys.path.pop(0)

    for name, run in _result_mapping_steps():
        for result, expected in RESULT_STATUS.items():
            code, published, stderr = _run_marker(tmp_path, run, result)
            assert code == 0, f"step {name!r} refused declared result {result!r}: {stderr}"
            assert published is not None, f"step {name!r} accepted {result!r} and published nothing"
            assert (
                published["status"],
                published["audit_pass"],
                published["inconclusive"],
            ) == tuple(expected), f"step {name!r} published {result!r} as {published}"

        for result in _UNDECLARED_RESULTS:
            code, published, stderr = _run_marker(tmp_path, run, result)
            assert code != 0 and published is None, (
                f"step {name!r} accepted undeclared result {result!r} and published {published}"
            )
            assert "unsupported" in stderr, (
                f"step {name!r} stopped on {result!r} for a reason other than the result: {stderr}"
            )


def test_no_marker_publishes_a_verdict_for_a_baseline_record(tmp_path):
    """A document declaring record_kind stops both markers, declared result or not.

    D5 of claude/2.5-spec-baseline-record-2026-10-14.md: latest-run,
    latest-audit, the monitor window and the run index describe gate runs. A
    baseline record carries no result and is not written into the run index,
    so neither marker can reach one by the published route. This is the check
    at the point of reading: a document that says what it is is refused on its
    own declaration, before its result is consulted.

    The result here is a declared one, so nothing but the declaration can be
    what stops the step.

    Mutation applied to .github/workflows/audit-and-sign.yml: removing the
    record_kind refusal from either marker, 1 failure each (this test).
    """
    for name, run in _result_mapping_steps():
        code, published, stderr = _run_marker(
            tmp_path, run, "AUDIT PASSED", extra={"record_kind": "sir_ungated_baseline"}
        )
        assert code != 0 and published is None, (
            f"step {name!r} published a verdict for a baseline record: {published}"
        )
        assert "record_kind" in stderr, (
            f"step {name!r} stopped for a reason other than the document kind: {stderr}"
        )


FINALIZE_STEP_NAME = "Finalize CI status (fail if audit failed or inconclusive)"


def _finalize_step():
    return next(run for name, run in _steps() if name and name.startswith("Finalize CI status"))


def test_the_finalize_step_is_named_as_the_assertions_expect():
    """Guard the guard: the condition checks look the step up by exact name."""
    assert FINALIZE_STEP_NAME in _step_conditions(), (
        "the finalize step was renamed, so the YAML-condition assertions would "
        f"raise KeyError rather than check anything. Known steps: {sorted(_step_conditions())}"
    )


def test_a_branch_dispatch_cannot_go_green_on_a_bad_certificate():
    """The counters and the certificate must agree, on every ref.

    AUDIT_PASS comes from tools/ci_audit_verdict.sh, which reads three counter
    files at a step that runs before the certificate exists. The certificate has
    six inconclusive conditions that script cannot see: systemic_reset_count
    above zero, a domain pack that failed to load, prompts_tested at or below
    zero, configurations_observed above one, and, on a LIVE_GATING_CHECK, any
    provider call failing or every attempt failing. A seventh,
    content_evaluated at or below zero, is shared and both refuse it.

    On main the marker step wrote the certificate's INCONCLUSIVE back into the
    environment, so those were caught. That step is gated on the publication
    context, so on a branch dispatch nothing caught them and the job went green
    while its own certificate said the run was inconclusive. A run with some
    systemic resets and some content still evaluated is the ordinary shape of
    that: content_evaluated is above zero and the leak counters are zero, which
    the shell reads as clean.

    This matters beyond tidiness because docs/key-custody.md step 5 tells an
    operator to validate a key rotation with exactly that dispatch.
    """
    run = _finalize_step()

    assert "AUDIT_JSON" in run, (
        "the finalize step does not look at the certificate at all, so its "
        "verdict rests entirely on counters computed before the certificate existed"
    )
    assert '"AUDIT PASSED"' in run, (
        "the finalize step does not require the certificate's own result"
    )
    assert "exit 1" in run

    # Unconditional. Gating any of this on the publication context would leave
    # the gap exactly where it was, because branch dispatches are the uncovered
    # case.
    #
    # Two corrections are recorded in this block. The first version sliced the
    # step from the first occurrence of "AUDIT_JSON:-", so a mutation that put
    # the publication context earlier on the same line sat outside the slice and
    # passed. The second version checked per line but only lines containing
    # AUDIT_JSON, which is the existence guard and not the result comparison, so
    # a mutation gating only `cert_result != "AUDIT PASSED"` on the publication
    # context passed while reopening the branch-dispatch gap. That was found by
    # an independent review, not by this test.
    #
    # Both parts of the certificate check are required to exist, and neither may
    # be publication-gated.
    #
    # Scoped to the certificate check rather than to every conditional in the
    # step. The first attempt at this correction asserted that no conditional
    # anywhere in the finalize step mentions the publication context, which
    # sounded like the general form of the defect and was simply false: the step
    # already carries a correct publication-gated conditional, requiring the run
    # marker's status when a marker was supposed to exist. That assertion failed
    # on unmutated code, which is how it was found. A broader invariant is not a
    # safer one when the code does not hold it.
    conditionals = [
        line for line in run.splitlines()
        if line.strip().startswith(("if ", "elif "))
    ]

    existence_guards = [line for line in conditionals if "AUDIT_JSON" in line]
    assert existence_guards, (
        "nothing in the finalize step branches on whether a certificate exists"
    )

    result_guards = [line for line in conditionals if "cert_result" in line]
    assert result_guards, (
        "nothing in the finalize step branches on the certificate's own result, "
        "so a certificate reporting INCONCLUSIVE would not fail the job"
    )

    # The compared operand, not merely the name appearing on the line. A guard
    # reading `if [ "$other" != "AUDIT PASSED" ]  # cert_result` satisfies a
    # substring test while comparing something else entirely.
    assert any(
        re.search(r'"\$\{?cert_result\}?"\s*!=\s*"AUDIT PASSED"', line)
        for line in result_guards
    ), (
        "no conditional compares $cert_result against AUDIT PASSED; the name "
        f"appears but is not what is being tested: {result_guards}"
    )

    for line in existence_guards + result_guards:
        assert "CANONICAL_PUBLICATION_CONTEXT" not in line, (
            "part of the certificate check is gated on the publication context, "
            "which leaves branch dispatches uncovered and is the defect this "
            f"exists to close: {line.strip()}"
        )

    # The shell is not the only place the step can be gated. An independent
    # review pointed out that three mutations reopened the gap while every
    # assertion above still passed: gating the whole step at YAML level, gating
    # a shell guard on a variable assigned from the publication context rather
    # than naming it, and an early `exit 0` leaving the guards present but
    # unreachable. Each is checked below.
    step_if, job_if, job_env = _step_conditions()[FINALIZE_STEP_NAME]

    assert "CANONICAL_PUBLICATION_CONTEXT" not in step_if, (
        "the finalize step is gated at YAML level on the publication context, "
        f"so a branch dispatch never reaches the certificate check at all: {step_if}"
    )
    assert "CANONICAL_PUBLICATION_CONTEXT" not in job_if, (
        f"the whole audit job is publication-gated: {job_if}"
    )
    assert step_if == "always()", (
        "the finalize step no longer runs unconditionally. It is the step that "
        "decides whether CI is green, and a condition on it is a condition on "
        f"the verdict: {step_if}"
    )
    assert "CANONICAL_PUBLICATION_CONTEXT" in job_env, (
        "the publication context is no longer a job-level env, so what the "
        "assertions above check for by name may have moved"
    )

    # Indirect gating. Any variable assigned from the publication context is the
    # publication context under another name, so the guards must not mention one.
    aliases = set(
        re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=.*CANONICAL_PUBLICATION_CONTEXT", run, re.MULTILINE)
    )
    for alias in aliases:
        for line in existence_guards + result_guards:
            assert alias not in line, (
                f"the certificate check is gated on {alias}, which is assigned "
                f"from the publication context: {line.strip()}"
            )

    # Unreachability. The guards above are worthless if the step returns first.
    #
    # No bare `exit 0` anywhere in this step, rather than none before the
    # certificate check. The first version of this assertion compared against
    # the earliest guard, so an `exit 0` placed between the existence guard and
    # the result comparison passed it while making the comparison unreachable.
    # That mutation was run and did pass. The step ends by falling off the end
    # after echoing success, so it has no legitimate explicit `exit 0`: its only
    # job is deciding whether CI is green, and an unconditional success return
    # part-way through is that decision made early.
    early_exits = re.findall(r"^[ \t]*exit 0[ \t]*$", run, re.MULTILINE)
    assert not early_exits, (
        "the finalize step contains an unconditional `exit 0`, which makes "
        "every check after it unreachable while leaving it present to read"
    )


def test_a_run_with_no_certificate_is_not_a_pass():
    """Absent is not clean, in the step that decides whether CI is green."""
    run = _finalize_step()

    # Keyed to the guard rather than to the message. The first version asserted
    # the sentence, and rewording the echo broke it while the behaviour was
    # unchanged. A test that fails when prose moves is noise; a test that fails
    # when the guard goes is the point.
    assert '[ ! -f "${AUDIT_JSON:-}" ]' in run or "[ ! -f \"$AUDIT_JSON\" ]" in run, (
        "the finalize step does not check whether a certificate file exists, so "
        "a run that produced none would be judged on counters alone"
    )
    assert '[ -z "${AUDIT_JSON:-}" ]' in run, (
        "the finalize step does not check whether a certificate path was set at all"
    )


def test_the_counter_verdict_and_the_certificate_are_separate_sources():
    """Guard the guard: the point is agreement between two things, not one thing.

    If the counter check were ever removed in favour of the certificate, this
    would become a single-source verdict again and the divergence it exists to
    surface would stop being detectable.
    """
    run = _finalize_step()

    # The condition, not the variable. The first version asserted that
    # "$AUDIT_PASS" appeared anywhere in the step, which the diagnostic echo at
    # the top satisfies, so deleting the check itself left the test green.
    assert 'if [ "$AUDIT_PASS" != "true" ]' in run, (
        "the counter-derived verdict is no longer checked, so nothing can "
        "disagree with the certificate and a divergence would not be visible"
    )
