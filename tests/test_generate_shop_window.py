"""The generator refuses to publish a claim that does not hold.

`tools/generate_shop_window.py` builds the shop window from the published
archive: it copies the exhibits, writes the documents, and then verifies every
exhibit inside the generated directory before it will finish. The refusal is
the part worth testing. A generator that produces a plausible repository and
checks nothing is the hand-maintained copy this design exists to avoid, with
extra steps.

Everything the documents say is derived. Exit-code meanings come from
`docs/archive-figures.json`, the limits come verbatim from the evidence
perimeter with their own lead-in sentences, the archive counts come from the
figures, and the commands come from `tools/shop_window.py`. The tests below
hold that, because the failure with the worst consequence for this repository
is a front door that describes the vault wrongly.

The generated directory has no `docs/runs` and no `proofs/runs`. That is
asserted rather than assumed: `verify_certificate.py` falls back to the
canonical archive path resolved against the working directory, so a generator
that copied the archive in would verify its exhibits against the vault and
pass whatever it had written.

Mutations measured on 16 October 2026, each run against the full file:

Run against this file and `tests/test_shop_window_exhibits.py` together,
because three of the mutations make the generator refuse, which fails the
module fixture and is reported as errors rather than failures. A first
measurement counted only `FAILED` lines and recorded three of these as
undetected, which was wrong about the code and right about one thing: see the
last entry.

- claim a passing receipt for the incomplete exhibit: 2 failed, 7 errors.
- copy `docs/runs` into the generated window, so the canonical fallback can
  answer: 7 errors, the generator refusing because no exhibit now proves
  anything about itself.
- write `LIMITS.md` without the perimeter's lead-in sentences:
  `test_the_limits_are_lifted_from_the_perimeter_with_their_lead_ins` fails
  (1 failed).
- drop `itgl.py` from the copied verifier set: 7 errors, every exhibit failing
  to verify because the verifiers cannot import.
- stop asserting the refusal: 1 failed, and this one was a real gap. Removing
  the generator's refusal check originally changed nothing, because every
  other assertion is about the documented command, and for that exhibit the
  documented command exits 0 whether the refusal works or not. The page would
  have published an exit code nothing had run.
  `test_the_generator_refuses_a_wrong_refusal_claim` was written for it.

Three further mutations, measured on 16 October 2026 against the window's
licence and the workflow that rebuilds it:

- stop copying the licence:
  `test_the_window_carries_the_licence_it_was_derived_from` fails (1 failed).
- stop writing the rebuild workflow: 2 failed, both workflow tests.
- let the rebuild ignore its own workflow, by replacing the diff with a
  condition that is never true:
  `test_the_rebuild_stops_rather_than_letting_its_own_workflow_rot` fails
  (1 failed). This is the one that matters. A token issued to Actions cannot
  update a workflow file, so a rebuild that stopped comparing would leave that
  one file frozen at whatever was first pushed while every other file in the
  repository moved, and nothing would say so.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = _load("generate_shop_window", "tools/generate_shop_window.py")
FIGURES = json.loads((ROOT / "docs/archive-figures.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def window(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("generated") / "shop-window"
    GENERATOR.generate(out, "v0.0.0-test")
    return out


def test_a_generated_window_verifies_end_to_end(window):
    """generate() raises SystemExit unless every exhibit produced its claim."""
    for name in ("README.md", "LIMITS.md", "VERIFY.md", "GENERATED"):
        assert (window / name).is_file(), name
    assert (window / "exhibits").is_dir()
    assert len(list((window / "exhibits").iterdir())) >= 6


def test_the_window_holds_no_archive_of_its_own(window):
    """Or the canonical fallback answers for every exhibit and nothing is tested."""
    assert not (window / "docs" / "runs").exists()
    assert not (window / "proofs" / "runs").exists()


def test_the_generator_refuses_a_claim_that_does_not_hold(tmp_path, monkeypatch):
    """The refusal, exercised rather than trusted."""
    real = GENERATOR._shop_window().select

    def wrong(figures=None):
        exhibits = real(figures)
        broken = exhibits[0]
        exhibits[0] = type(broken)(
            number=broken.number,
            name=broken.name,
            teaches=broken.teaches,
            document_exit=(broken.document_exit + 1) % 10,
            receipt_exit=broken.receipt_exit,
            ledger=broken.ledger,
            refusal_exit=broken.refusal_exit,
            run_id=broken.run_id,
            candidates=broken.candidates,
        )
        return exhibits

    module = GENERATOR._shop_window()
    monkeypatch.setattr(module, "select", wrong)
    monkeypatch.setattr(GENERATOR, "_shop_window", lambda: module)

    with pytest.raises(SystemExit) as refused:
        GENERATOR.generate(tmp_path / "window", "v0.0.0-test")

    assert "REFUSED" in str(refused.value)
    assert "produces" in str(refused.value)


def test_the_generator_refuses_a_wrong_refusal_claim(tmp_path, monkeypatch):
    """Exhibit 7's point is the refusal, so the refusal is a claim too.

    Found by mutation on 16 October 2026: removing the generator's refusal
    check changed nothing, because every other assertion here is about the
    documented command, which for that exhibit exits 0 either way. The page
    would have claimed an exit code nothing had run.
    """
    real = GENERATOR._shop_window().select

    def wrong(figures=None):
        exhibits = real(figures)
        for index, exhibit in enumerate(exhibits):
            if exhibit.refusal_exit is None:
                continue
            exhibits[index] = type(exhibit)(
                number=exhibit.number,
                name=exhibit.name,
                teaches=exhibit.teaches,
                document_exit=exhibit.document_exit,
                receipt_exit=exhibit.receipt_exit,
                ledger=exhibit.ledger,
                refusal_exit=exhibit.refusal_exit + 1,
                run_id=exhibit.run_id,
                candidates=exhibit.candidates,
            )
        return exhibits

    module = GENERATOR._shop_window()
    monkeypatch.setattr(module, "select", wrong)
    monkeypatch.setattr(GENERATOR, "_shop_window", lambda: module)

    with pytest.raises(SystemExit) as refused:
        GENERATOR.generate(tmp_path / "window", "v0.0.0-test")

    assert "refuses it" in str(refused.value), str(refused.value)


def test_the_limits_are_lifted_from_the_perimeter_with_their_lead_ins(window):
    """A bullet list without its lead-in produced an ungrammatical claim."""
    perimeter = (ROOT / "docs/evidence-perimeter.v6.md").read_text(encoding="utf-8")
    limits = (window / "LIMITS.md").read_text(encoding="utf-8")

    lead = "Current evidence and implementation do not claim that SIR:"
    assert lead in perimeter
    assert lead in limits, "the lead-in its bullets continue is missing"

    for section in ("Explicit non-claims", "What current evidence does not support"):
        body = perimeter.split(f"\n## {section}\n", 1)[1].split("\n## ", 1)[0]
        for bullet in [b for b in body.splitlines() if b.startswith("- ")]:
            assert bullet in limits, bullet


def test_the_exit_code_meanings_come_from_the_published_figures(window):
    verify = (window / "VERIFY.md").read_text(encoding="utf-8")

    for row in FIGURES["certificate_rows"]:
        if row["exit"] is None:
            continue
        assert row["meaning"] in verify, row
    for row in FIGURES["receipt_rows"]:
        assert row["meaning"] in verify, row


def test_the_counts_come_from_the_figures(window):
    readme = (window / "README.md").read_text(encoding="utf-8")
    generated = (window / "GENERATED").read_text(encoding="utf-8")

    assert str(FIGURES["total"]) in readme
    assert str(FIGURES["certificates_total"]) in readme
    assert f"archives {FIGURES['total']}" in generated
    assert f"certificates {FIGURES['certificates_total']}" in generated


def test_every_documented_command_names_its_ledger_or_says_there_is_none(window):
    """The finding that changed the design, held in the published page."""
    verify = (window / "VERIFY.md").read_text(encoding="utf-8")
    exhibits = GENERATOR._shop_window().select()

    for exhibit in exhibits:
        argv = exhibit.command(f"exhibits/{exhibit.run_id}")
        assert "--ledger" in argv or "--no-ledger" in argv, exhibit.number
    assert "Older certificates carry no run id" in verify


def test_the_window_ships_only_the_verifiers_a_visitor_runs(window):
    """"Nothing else" is the rule. The vault's tools directory is not shipped."""
    shipped = {p.name for p in (window / "tools").glob("*.py")}

    assert shipped == set(GENERATOR.VERIFIER_FILES), sorted(shipped)
    assert len(list((ROOT / "tools").glob("*.py"))) > len(shipped) + 10


def test_the_pin_must_be_a_tag_that_exists():
    """A pin to a branch or a bare commit is a fork that stops getting fixes."""
    tag = GENERATOR._release_tag()

    assert tag.startswith("v"), tag
    assert (ROOT / ".git").exists()


def test_the_window_carries_the_licence_it_was_derived_from(window):
    """Copied, byte for byte.

    A licence is the one file in a generated repository that a hand edit is
    most tempting for and least visible in. Copying it from the source means a
    relicence in the archive of record reaches the window on the next rebuild
    rather than leaving two different grants of the same material in public.
    """
    assert (window / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()


def test_the_window_carries_the_workflow_that_rebuilds_it(window):
    """The window pulls; the archive of record never pushes.

    A rebuild driven from the vault would need a token with write access to a
    second public repository, held in the repository with the most CI traffic.
    A rebuild driven from the window needs write access only to itself.
    """
    workflow = window / ".github" / "workflows" / "rebuild.yml"
    assert workflow.is_file()
    parsed = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    steps = parsed["jobs"]["rebuild"]["steps"]
    run = "\n".join(step.get("run", "") for step in steps)
    assert GENERATOR.VAULT in run, "the rebuild does not say what it rebuilds from"
    assert "generate_shop_window.py --out" in run
    assert "--sort=-v:refname" in run, "the rebuild does not pin to a release tag"


def test_the_rebuild_stops_rather_than_letting_its_own_workflow_rot(window):
    """A token issued to Actions cannot update a workflow file.

    So the rebuild cannot write this file even when the generator changes it.
    The alternative to failing loudly is a workflow that silently stays at the
    version it was first pushed with, which is the hand-maintained file this
    whole design exists to remove.
    """
    workflow = (window / ".github" / "workflows" / "rebuild.yml").read_text(encoding="utf-8")
    assert "diff -r built/.github window/.github" in workflow
    assert "exit 1" in workflow


def test_check_mode_builds_the_window_and_keeps_nothing(tmp_path):
    """The release gate wants the refusal, not the output."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "generate_shop_window.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "reproduces" in result.stdout
    assert not (ROOT / "window").exists()


def test_check_mode_and_an_output_directory_are_not_both_given(tmp_path):
    """Two answers to "where does this go" is a question, not a default."""
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "generate_shop_window.py"),
            "--check",
            "--out",
            str(tmp_path / "w"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not (tmp_path / "w").exists()
