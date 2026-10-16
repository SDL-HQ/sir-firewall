"""The release checklist gate must fail closed, and must not accept prose as evidence."""

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "check_release_checklist.py"


def _run(checklist: Path, root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), "--checklist", str(checklist), "--root", str(root), *extra],
        capture_output=True,
        text=True,
    )


def _write(tmp_path: Path, items: list[dict]) -> Path:
    path = tmp_path / "checklist.json"
    path.write_text(
        json.dumps({"checklist_version": "v1", "target_version": "test", "items": items}),
        encoding="utf-8",
    )
    return path


def test_open_item_blocks_the_merge(tmp_path):
    checklist = _write(tmp_path, [{"id": 0, "name": "x", "status": "open", "evidence": []}])
    assert _run(checklist, REPO).returncode == 1


def test_met_without_evidence_blocks_the_merge(tmp_path):
    checklist = _write(tmp_path, [{"id": 0, "name": "x", "status": "met", "evidence": []}])
    result = _run(checklist, REPO)
    assert result.returncode == 1
    assert "no evidence" in result.stderr


def test_prose_is_not_evidence(tmp_path):
    """A document explaining why an item is acceptable must not tick it."""
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "doc", "ref": "docs/key-custody.md"}],
            }
        ],
    )
    result = _run(checklist, REPO)
    assert result.returncode == 2
    assert "not permitted" in result.stderr


def test_missing_test_does_not_resolve(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "test", "ref": "tests/test_release_checklist.py::test_absent"}],
            }
        ],
    )
    result = _run(checklist, REPO)
    assert result.returncode == 2
    assert "test not defined" in result.stderr


def test_missing_artefact_does_not_resolve(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "artefact", "ref": "no/such/path"}],
            }
        ],
    )
    result = _run(checklist, REPO)
    assert result.returncode == 2
    assert "artefact not found" in result.stderr


def test_command_must_reach_its_stated_exit_code(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [{"type": "command", "ref": "python3 -c \"raise SystemExit(3)\"", "expect_exit": 0}],
            }
        ],
    )
    result = _run(checklist, REPO, "--run-commands")
    assert result.returncode == 2
    assert "expected 0" in result.stderr


def test_resolving_evidence_passes(tmp_path):
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [
                    {"type": "test", "ref": "tests/test_release_checklist.py::test_prose_is_not_evidence"},
                    {"type": "artefact", "ref": "tools/check_release_checklist.py"},
                    {"type": "command", "ref": "python3 -c \"pass\"", "expect_exit": 0},
                ],
            }
        ],
    )
    assert _run(checklist, REPO, "--run-commands").returncode == 0


def test_summary_only_never_fails(tmp_path):
    """The release branch reports status without blocking day-to-day work."""
    checklist = _write(tmp_path, [{"id": 0, "name": "x", "status": "open", "evidence": []}])
    assert _run(checklist, REPO, "--summary-only").returncode == 0


def test_the_real_checklist_is_wellformed():
    """The summary names the release the checklist targets.

    This held the target version as a literal, which meant the version bump of
    every release turned it red for a reason unrelated to anything the test is
    about, and it also made this file a version surface that
    tests/test_evidence_version.py then had to classify. The version is read
    from the checklist instead, so what is held is the thing that matters: the
    summary reports the release the file declares, rather than a release some
    other file remembers.
    """
    checklist = REPO / "release-checklist.json"
    target = json.loads(checklist.read_text(encoding="utf-8"))["target_version"]
    result = _run(checklist, REPO, "--summary-only")

    assert result.returncode == 0
    assert f"Release checklist for {target}" in result.stdout
    assert re.fullmatch(r"\d+\.\d+\.\d+", target), target


def test_command_evidence_never_reaches_a_shell(tmp_path):
    """The checklist is editable by anyone who can open a pull request.

    Command evidence is split into an executable and its arguments, so a shell
    metacharacter in the checklist is an argument rather than a second command.
    """
    marker = tmp_path / "side-effect"
    checklist = _write(
        tmp_path,
        [
            {
                "id": 0,
                "name": "x",
                "status": "met",
                "evidence": [
                    {
                        "type": "command",
                        "ref": f'python3 -c "pass" ; touch {marker}',
                        "expect_exit": 0,
                    }
                ],
            }
        ],
    )
    _run(checklist, REPO, "--run-commands")
    assert not marker.exists(), "a shell interpreted the checklist entry"


def test_a_tick_means_the_evidence_resolved_not_that_the_status_says_met(tmp_path):
    """The checkbox list and the count above it must not disagree.

    The mark was read from the status field alone, so an item claiming 'met'
    with evidence that did not resolve printed as [x] while the count said
    otherwise, and nothing in the list said which item was at fault. A tick that
    can be wrong is precisely what this file exists to prevent, and this one was
    wrong on item 9 on 8 October 2026 after a test was renamed.
    """
    checklist = _write(tmp_path, [
        {"id": 0, "name": "resolves", "status": "met",
         "evidence": [{"type": "artefact", "ref": "present.txt"}]},
        {"id": 1, "name": "claims met, does not resolve", "status": "met",
         "evidence": [{"type": "artefact", "ref": "absent.txt"}]},
        {"id": 2, "name": "open", "status": "open", "evidence": []},
    ])
    (tmp_path / "present.txt").write_text("x", encoding="utf-8")

    result = _run(checklist, tmp_path)
    # The mark is one character which may be a space, so the line is parsed by
    # shape rather than split on whitespace.
    marks = dict(
        (match.group(2), match.group(1))
        for match in (
            re.match(r"^  \[(.)\] (\S+)  ", line) for line in result.stdout.splitlines()
        )
        if match
    )

    assert "1 of 3 items met" in result.stdout
    assert marks == {"0": "x", "1": "!", "2": " "}, marks
    assert "marked met, but its evidence does not resolve" in result.stdout
    assert result.returncode != 0


def test_the_marks_and_the_count_always_agree(tmp_path):
    """Derived rather than asserted: the number of ticks is the number counted."""
    checklist = _write(tmp_path, [
        {"id": 0, "name": "a", "status": "met",
         "evidence": [{"type": "artefact", "ref": "present.txt"}]},
        {"id": 1, "name": "b", "status": "met",
         "evidence": [{"type": "artefact", "ref": "absent.txt"}]},
        {"id": 2, "name": "c", "status": "met", "evidence": []},
        {"id": 3, "name": "d", "status": "open", "evidence": []},
    ])
    (tmp_path / "present.txt").write_text("x", encoding="utf-8")

    result = _run(checklist, tmp_path)
    ticks = sum(1 for line in result.stdout.splitlines() if line.startswith("  [x]"))
    counted = int(result.stdout.split("items met")[0].split(":")[-1].strip().split(" of ")[0])

    assert ticks == counted == 1

# --- the gate job must be able to run what the checklist names -----------------


GATE_WORKFLOW = REPO / ".github/workflows/release-gate.yml"


def _gate_run_steps() -> str:
    """Every shell line the release-gate job runs, as one blob."""
    import yaml

    workflow = yaml.safe_load(GATE_WORKFLOW.read_text(encoding="utf-8"))
    steps = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step.get("run"), str):
                steps.append(step["run"])
    return "\n".join(steps)


def _command_evidence() -> list:
    checklist = json.loads((REPO / "release-checklist.json").read_text(encoding="utf-8"))
    return [
        entry.get("ref", "")
        for item in checklist["items"]
        for entry in (item.get("evidence") or [])
        if entry.get("type") == "command"
    ]


def test_the_gate_installs_what_its_command_evidence_needs():
    """The gate ran `python3 -m pytest` in a job that had no pytest.

    On 12 October the gate installed cryptography alone, under a step named for
    verification dependencies, while items 7 and 8 named command evidence that
    shells out to pytest. Both were reported as marked met with evidence that
    does not resolve, which is the mark doing its job and the workflow being
    wrong. The item status was right; the job could not prove it.

    This derives the requirement from the checklist rather than listing it, so
    the next command evidence needing a package the gate does not install fails
    here instead of on the merge path.
    """
    modules = {
        ref.split("-m ", 1)[1].split()[0]
        for ref in _command_evidence()
        if "-m " in ref
    }
    assert modules, "no command evidence invokes a module; this test is now vacuous"

    installs = _gate_run_steps()
    declared = (REPO / "pyproject.toml").read_text(encoding="utf-8")

    assert "pip install -e ." in installs, (
        "the gate does not install the package, so it cannot run module-invoking "
        f"command evidence: {sorted(modules)}"
    )
    for module in sorted(modules):
        assert module in declared, (
            f"command evidence runs `python3 -m {module}` and the gate installs the "
            "package, but that package does not declare it as a dependency"
        )


def test_every_command_evidence_entry_states_an_expected_exit_code():
    """A command whose exit code is unstated cannot fail."""
    checklist = json.loads((REPO / "release-checklist.json").read_text(encoding="utf-8"))

    for item in checklist["items"]:
        for entry in item.get("evidence") or []:
            if entry.get("type") != "command":
                continue
            assert "expect_exit" in entry, (
                f"item {item['id']} names a command with no expected exit code: "
                f"{entry.get('ref')!r}"
            )


def test_the_gate_can_run_every_command_its_items_name():
    """A command needing a release tag cannot run in a clone that has none.

    `actions/checkout` fetches the tip and no tags unless asked. Item 10's
    command builds the evidence window, which is pinned at a release tag and
    refuses rather than guessing, so the gate failed on a tagless checkout for
    a reason that said nothing about the release. The mark was working and the
    workflow was wrong, which is the same shape as the dependency note already
    written into that file.

    Mutations measured on 16 October 2026:

    - remove `fetch-depth: 0` from the gate's checkout: this test fails
      (1 failed). Confirmed against the real failure first, by running the
      item's command in a clone with its tags deleted: it exits 1 with
      "REFUSED: the pin must be a release tag and this clone has none".
    - drop the tag requirement from the generator instead, so it builds
      unpinned: not taken. A window pinned to nothing is the one thing it must
      never publish, so the refusal is the correct behaviour and the checkout
      is the defect.
    """
    import yaml

    workflow = yaml.safe_load(
        (REPO / ".github" / "workflows" / "release-gate.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["release-checklist"]["steps"]
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout.get("with", {}).get("fetch-depth") == 0, (
        "the gate runs a command that needs a release tag and checks out without one"
    )
