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

The window shipped compiled bytecode until this was measured. Four further
mutations, 16 October 2026:

- stop filtering `__pycache__` out of the copies: 2 failed, 11 errors, the
  module fixture refusing. The refusal is reachable, which is the answer to
  the undetected one below.
- remove `-B` from the verifier subprocesses: 2 failed, 11 errors. Running the
  verifiers inside the window is itself what compiled the modules.
- remove `PYTHONDONTWRITEBYTECODE` from their environment: nothing failed, and
  removing `-B` alone also failed nothing. Each was sufficient on its own, so
  neither could be measured and the pair said less than one of them would. The
  environment variable was removed; `-B` is detectable now, above.
- drop the refusal and keep the filters: undetected, 17 passed. With the
  filters working nothing produces bytecode for it to find, so it is a
  backstop rather than dead code, and the first mutation above is what shows
  it fires. Kept on that basis and recorded rather than claimed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import shutil
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
SHOP_WINDOW = _load("shop_window", "tools/shop_window.py")
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
        # dataclasses.replace, not a field-by-field rebuild. The rebuild
        # listed the fields that existed when it was written, so `document`
        # and `tool` silently fell back to their defaults and the baseline
        # exhibit was handed an audit.json path that does not exist. The same
        # brittleness as indexing the specification tuple, in a different
        # costume.
        return [
            dataclasses.replace(e, refusal_exit=e.refusal_exit + 1)
            if e.refusal_exit is not None
            else e
            for e in exhibits
        ]

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


def test_the_window_ships_nothing_compiled(window):
    """Bytecode in the window is three problems, and the third is structural.

    A repository about care should not look careless, and a stranger asked to
    run our code should not be handed a precompiled copy of it, since a `.pyc`
    can differ from the `.py` beside it and Python will prefer the cache. But
    the one that breaks the design is that bytecode varies with whichever
    Python versions have run in the source clone, so the rebuild's comparison
    between what it builds and what is committed would never settle.

    Checked after the verifier runs, not only at the copy: running them inside
    the window is itself what compiled the modules before `-B` was passed.
    """
    compiled = [
        str(path.relative_to(window))
        for path in window.rglob("*")
        if path.name == "__pycache__" or path.suffix in (".pyc", ".pyo")
    ]
    assert compiled == [], compiled


def test_two_builds_of_the_same_tag_agree_except_on_when_they_were_built(tmp_path):
    """The weekly rebuild compares what it builds against what is committed.

    If two builds of one tag can differ, that comparison is noise and the
    self-rebuilding design does not work. `GENERATED` carries the build time
    and is expected to differ; everything else is expected not to.
    """
    first, second = tmp_path / "first", tmp_path / "second"
    GENERATOR.generate(first, "v0.0.0-test")
    GENERATOR.generate(second, "v0.0.0-test")

    def tree(root):
        return {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.name != "GENERATED"
        }

    left, right = tree(first), tree(second)
    assert left.keys() == right.keys(), set(left) ^ set(right)
    assert left == right, [name for name in left if left[name] != right[name]]


def test_the_rebuild_skips_a_release_that_predates_the_generator(window):
    """The window is rebuilt from the tag it is pinned at, so the tag must hold the tool.

    The first published window was pinned at a release made before the
    generator existed, and the first scheduled rebuild failed on it with
    `can't open file`. Failing weekly for a condition nobody can act on until
    the next release trains a person to ignore the one workflow whose whole
    job is to notice drift, so the job checks and skips with a notice instead.

    It is a bounded state, not a permanent exemption: it is false from the
    first release that contains the generator onward, and nothing in the
    window can change while it holds, because everything the window is built
    from is frozen at that same tag.

    Mutations measured on 16 October 2026:

    - remove the gate step: this test fails (1 failed). Confirmed against the
      real failure first, by running the job's own two commands locally
      against the release the first window was pinned at: exit 2, and
      `can't open file`.
    - leave the gate but drop the `if` from the build step: this test fails
      (1 failed), which is the case that would still have gone red weekly.
    """
    import yaml

    parsed = yaml.safe_load(
        (window / ".github" / "workflows" / "rebuild.yml").read_text(encoding="utf-8")
    )
    steps = parsed["jobs"]["rebuild"]["steps"]
    gate = next(s for s in steps if s.get("id") == "pin")
    assert "generate_shop_window.py" in gate["run"]
    assert "buildable=no" in gate["run"]

    guarded = [s for s in steps if s.get("if") == "steps.pin.outputs.buildable == 'yes'"]
    names = {s.get("name", "") for s in guarded}
    assert any("Build" in name for name in names), names
    assert any("Commit" in name for name in names), names
    # Everything after the gate is conditional on it, or the job still fails.
    after = steps[steps.index(gate) + 1 :]
    assert all(s.get("if") == "steps.pin.outputs.buildable == 'yes'" for s in after), [
        s.get("name") for s in after if "if" not in s
    ]


def test_the_exit_table_keeps_both_rows_that_share_exit_zero(window):
    """The table was a dict keyed on the exit code, so one row overwrote the other.

    `certificate_rows` publishes two exit-0 rows: 80 archives verified with
    their binding checked, and 39 verified with no ledger to check it against.
    The dict kept the second, so the page told a reader that exit 0 means no
    binding was checked, directly beneath two exhibits that exit 0 with the
    binding checked and say so on the same page.
    """
    verify = (window / "VERIFY.md").read_text(encoding="utf-8")
    # Scoped to the certificate table. A first version counted "| `0` |" lines
    # across the whole file, so the receipt table's 206 and the baseline
    # table's 2 kept it green with the certificate table collapsed to one
    # exit-0 row, and the meaning check passed because "verified" is a
    # substring of the receipt row. The test read correctly and measured
    # nothing, which only a mutation showed.
    block = verify.split("Certificate verifier.", 1)[1].split("Archive receipt verifier", 1)[0]
    zero_rows = [line for line in block.splitlines() if line.startswith("| `0` |")]
    figures = json.loads((ROOT / "docs" / "archive-figures.json").read_text(encoding="utf-8"))
    published = [row for row in figures["certificate_rows"] if row["exit"] == 0]

    assert len(zero_rows) == len(published), zero_rows
    for row in published:
        assert any(line.startswith(f"| `0` | {row['meaning']} |") for line in zero_rows), (
            row["meaning"],
            zero_rows,
        )
    assert "| `12` |" in verify, "the exit the baseline exhibit exists to show is absent"
    assert "| `7` |" in verify, "the exit a tampered ledger produces is absent"


def test_the_generator_refuses_a_verdict_that_does_not_hold(tmp_path):
    """The claim that was missing entirely, so nothing could disagree with it.

    The window reported exit 0 from two single-property verifiers and called
    the archive clean, while the project's own `verify_evidence.py` said NOT
    ESTABLISHED about it. The verdict is now a field on the exhibit, and the
    generator runs the verdict tool inside the window it has built. This
    mutates the claim and requires the refusal.
    """
    # The generator loads its own copy of shop_window.py, so mutating this
    # module's copy changes nothing. Patch what the generator reads.
    #
    # Patched through `select` rather than by index into SPECIFICATION. The
    # first version rewrote the seventh element of each entry, and when the
    # declared ledger flag was removed from those tuples the verdict moved to
    # a different position, so the mutation silently rewrote the errata label
    # instead and the test passed while asserting nothing.
    module = GENERATOR._shop_window()
    real = module.select

    def with_a_wrong_verdict(figures=None):
        return [
            dataclasses.replace(e, verdict="FAILED") if e.number == 1 else e
            for e in real(figures)
        ]

    module.select = with_a_wrong_verdict
    loaded = GENERATOR._shop_window
    GENERATOR._shop_window = lambda: module
    try:
        with pytest.raises(SystemExit) as refused:
            GENERATOR.generate(tmp_path / "window", "v0.0.0-test")
        assert "verdict" in str(refused.value), str(refused.value)
    finally:
        module.select = real
        GENERATOR._shop_window = loaded


def test_an_exhibit_the_errata_does_not_list_says_so(window):
    """"Written up in our errata" is half-true if a reader greps for the id.

    Three exhibits are listed individually in an appendix. The fourth is
    covered by E4, which describes the 223 archives whose ledger binding
    cannot be established and enumerates none of them. A reader who checks
    the errata for each exhibit finds three and not the fourth, and that
    asymmetry belongs on the page rather than in the discovery.
    """
    verify = (window / "VERIFY.md").read_text(encoding="utf-8")
    errata = (ROOT / "docs" / "archive-errata.md").read_text(encoding="utf-8")
    module = GENERATOR._shop_window()
    exhibits = [e for e in module.select() if e.errata]
    assert exhibits, "no exhibit carries an errata entry, so this test is obsolete"

    listed = [e for e in exhibits if e.run_id in errata]
    classed = [e for e in exhibits if e.run_id not in errata]
    assert listed, "no exhibit is listed individually, so the distinction is untested"
    assert classed, "no exhibit is class-covered only, so the distinction is untested"

    for e in listed:
        assert f"listed individually under **{e.errata}**" in verify, e.number
    for e in classed:
        assert "does not enumerate its members" in verify, e.number
        assert f"**{e.errata}** in the archive of record's" in verify, e.number


def test_the_published_tamper_recipe_is_the_one_that_was_measured(window):
    """The page prints the exact text the generator ran, not a paraphrase of it.

    The generator reimplemented something similar in Python and measured that.
    The recipe it published was then found to be neither idempotent nor
    one-way: it copied into a directory that may already exist, which nests
    rather than replaces, and it flipped a field between two values, which
    restores the original on a second run. A reader who ran it twice, which is
    what a sceptic does, got exit 0 and the reasonable conclusion that we
    cannot detect a changed byte. It was found by running the published page
    twice, not by reading it.
    """
    verify = (window / "VERIFY.md").read_text(encoding="utf-8")
    module = GENERATOR._shop_window()
    exhibit = module.select()[0]
    ledger = window / "exhibits" / exhibit.run_id / "proofs" / "itgl_ledger.jsonl"
    row = len(ledger.read_text(encoding="utf-8").splitlines()) // 2
    recipe = GENERATOR._tamper_recipe(exhibit.run_id, row)

    assert recipe in verify, "the page does not print the text that was measured"
    assert recipe.splitlines()[0].startswith("rm -rf "), (
        "the recipe must clear its destination, or a second run copies into it"
    )
    assert '"allow" if' not in recipe, (
        "the edit must not toggle between two values, or a second run restores the original"
    )


def test_running_the_published_recipe_twice_still_catches_it(window):
    """Exit 7 once is not a measurement of something a reader may repeat."""
    module = GENERATOR._shop_window()
    result = GENERATOR._tamper(window, module.select()[0])

    assert result["exit"] == module.TAMPER_EXIT, result
    assert result["exit_again"] == module.TAMPER_EXIT, result
    assert "ledger_hash" in result["message"], result["message"]


def test_the_generator_refuses_a_recipe_that_undoes_itself(tmp_path):
    """The guard for the defect that shipped, made to fire.

    Measuring showed that removing the second-run check changed nothing, which
    is true only because the recipe is now idempotent: the guard could not be
    reached, so it was defence nobody could test. This injects the recipe as it
    was published, which copies into a directory that may already exist and
    toggles a field between two values, and requires the refusal.
    """
    shutil.rmtree("/tmp/tampered", ignore_errors=True)

    def recipe_that_undoes_itself(run_id: str, row: int) -> str:
        return "\n".join([
            f"cp -r exhibits/{run_id} /tmp/tampered",
            "python3 - <<'EOF'",
            "import json, pathlib",
            'p = pathlib.Path("/tmp/tampered/proofs/itgl_ledger.jsonl")',
            "rows = p.read_text().splitlines()",
            f"row = json.loads(rows[{row}])",
            'row["expected"] = "allow" if row["expected"] == "block" else "block"',
            f'rows[{row}] = json.dumps(row, separators=(",", ":"), sort_keys=True)',
            'p.write_text("\\n".join(rows) + "\\n")',
            "EOF",
            "python3 tools/verify_certificate.py /tmp/tampered/audit.json "
            "--ledger /tmp/tampered/proofs/itgl_ledger.jsonl",
        ])

    real = GENERATOR._tamper_recipe
    GENERATOR._tamper_recipe = recipe_that_undoes_itself
    try:
        with pytest.raises(SystemExit) as refused:
            GENERATOR.generate(tmp_path / "window", "v0.0.0-test")
        assert "second run" in str(refused.value), str(refused.value)
    finally:
        GENERATOR._tamper_recipe = real
        shutil.rmtree("/tmp/tampered", ignore_errors=True)


def test_the_window_ships_no_gate_implementation(window):
    """An evidence display case is not a copy of the product.

    `src/sir_firewall` shipped for one optional import inside a
    `try/except ImportError`: the certificate verifier's canonical-path
    fallback, which resolves `docs/runs/<id>/...` against the working
    directory and so cannot resolve anything in a window that asserts it has
    no `docs/runs`. The branch was already dead here, and it cost 416K
    containing the gate itself, the deterministic rules and the policy packs,
    in a repository whose own limits say the exhibits do not show the gate is
    adequate. A visitor never sets `PYTHONPATH` either, so the import always
    failed for them while the generator set one and measured a path no reader
    reaches.
    """
    assert not (window / "src").exists(), "the window ships the gate"
    shipped = {p.name for p in (window / "tools").iterdir()}
    assert shipped == set(GENERATOR.VERIFIER_FILES), sorted(shipped)
    for name in ("core.py", "deterministic_rules.py", "policy.py", "cli.py"):
        assert not list(window.rglob(name)), name


def test_every_exhibit_says_whether_its_named_model_ran(window):
    """The property the verifiers do not have, so the page has to carry it.

    Every evidence contract requires `model` and `provider` non-empty, and the
    workflow supplies a default when none was selected, so a firewall-only
    audit names a commercial product and records zero calls against it. That
    is errata E6. The verifiers establish every property they know about on
    such a certificate, which is how the window came to present one as the
    archive that establishes everything with nothing said about the model.

    Three-valued, and that was learned the hard way twice. The first version
    read `model_calls_made` on every document. A baseline record has no such
    field: its counters live under `counters` as `provider_call_attempts` and
    `provider_call_successes`, so the lookup returned None, read as zero, and
    the page said the named model did not run on a record of fifty calls to
    it. The second version refused when it could not tell, and that refusal
    fired immediately on a January archive that names a model and carries no
    counters at all because they postdate it. Unknown is not zero, and it is
    not a reason to refuse.
    """
    verify = (window / "VERIFY.md").read_text(encoding="utf-8")
    module = GENERATOR._shop_window()
    seen = set()
    for exhibit in module.select():
        document = json.loads(
            (ROOT / "docs" / "runs" / exhibit.run_id / exhibit.document).read_text(
                encoding="utf-8"
            )
        )
        model, _, calls = GENERATOR._model_invocation(exhibit)
        if not document.get("model"):
            assert model is None
            continue

        # Derived here from the document's own shape, independently of the
        # generator, so agreement means something.
        if "model_calls_made" in document:
            expected = document["model_calls_made"]
        elif isinstance(document.get("counters"), dict) and (
            "provider_call_successes" in document["counters"]
        ):
            expected = document["counters"]["provider_call_successes"]
        else:
            expected = None
        assert calls == expected, (exhibit.number, calls, expected)

        note = GENERATOR._model_note(exhibit)
        if expected is None:
            assert "cannot be told from this" in note, (exhibit.number, note)
            seen.add("unknown")
        elif expected:
            assert "The named model did run" in note, (exhibit.number, note)
            assert str(expected) in note, (exhibit.number, note)
            seen.add("ran")
        else:
            assert "The named model did not run" in note, (exhibit.number, note)
            seen.add("did not")
        assert note in verify, exhibit.number

    assert seen == {"ran", "did not", "unknown"}, (
        f"the exhibits only demonstrate {sorted(seen)}, so this test does not "
        "show the three states are distinguished"
    )


def test_a_baseline_records_its_calls_under_counters_not_at_the_top(window):
    """The defect this introduced, pinned to the document that exposed it.

    A note written for a certificate was applied to a baseline record, which
    has no `model_calls_made`. The lookup returned None, the page said the
    model did not run, and the record shows fifty successful provider calls.
    """
    module = GENERATOR._shop_window()
    baselines = [e for e in module.select() if e.document == "baseline.json"]
    assert baselines, "no baseline exhibit, so this test cannot show the difference"
    for exhibit in baselines:
        document = json.loads(
            (ROOT / "docs" / "runs" / exhibit.run_id / exhibit.document).read_text(
                encoding="utf-8"
            )
        )
        assert "model_calls_made" not in document, (
            "the baseline now carries the certificate's field, so reading the "
            "wrong one would no longer be visible here"
        )
        calls = document["counters"]["provider_call_successes"]
        assert calls > 0, document["counters"]
        _, _, read = GENERATOR._model_invocation(exhibit)
        assert read == calls, (read, calls)
        assert "did run" in GENERATOR._model_note(exhibit)


def test_the_table_says_which_verifier_produced_each_document_exit(window):
    """Two tools produce a document exit, and the table used to hide which.

    Exhibit 6 is a baseline record: `verify_baseline_record.py` exits 0, and
    `verify_certificate.py` on the same file exits 12. The table gave 0
    without naming the tool, so a reader taking the table as the answer would
    run the certificate verifier, get a refusal, and conclude the page is
    wrong when the page was merely incomplete.
    """
    readme = (window / "README.md").read_text(encoding="utf-8")
    module = GENERATOR._shop_window()
    tools = {e.tool for e in module.select()}
    assert len(tools) > 1, "every exhibit uses one tool, so the column proves nothing"
    for exhibit in module.select():
        row = [
            line
            for line in readme.splitlines()
            if line.startswith(f"| {exhibit.number} | {exhibit.name} |")
        ]
        assert row, exhibit.number
        assert f"`{exhibit.tool}`" in row[0], (exhibit.number, row[0])


def test_the_table_itself_says_whether_the_named_model_ran(window):
    """Putting it one file down is not putting it where the claim is.

    The note under the commands in VERIFY.md was the first fix, and an outside
    reader pointed out that the README row still said an archive establishes
    every property with nothing beside it about the model it names never
    having been called. A reader who stops at the table stops at the table.
    """
    readme = (window / "README.md").read_text(encoding="utf-8")
    module = GENERATOR._shop_window()
    for exhibit in module.select():
        _, _, calls = GENERATOR._model_invocation(exhibit)
        row = next(
            line
            for line in readme.splitlines()
            if line.startswith(f"| {exhibit.number} | {exhibit.name} |")
        )
        if calls is None:
            assert "unknown" in row, (exhibit.number, row)
        elif calls:
            assert f"yes, {calls}" in row, (exhibit.number, row)
        else:
            assert "**no**" in row, (exhibit.number, row)
