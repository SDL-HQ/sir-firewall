"""Every shop-window exhibit produces, from a copy, the answer it claims.

The shop window is a separate generated repository holding seven real
published archives, each chosen because our own verifiers give it a different
answer. Its whole value is that a stranger can check our claims, so the
failure with the worst consequence is the front door describing the vault
wrongly. This is the check that stops it, and it lives here rather than in the
generator so the claim is held on every commit instead of only at publish
time.

What it does: builds a miniature shop window in a scratch directory, copies
each exhibit's complete archive directory into it, and runs the real verifiers
there.

**It runs outside the vault, and that is not incidental.**
``verify_certificate.py`` resolves a ledger from the signed run id: beside the
certificate when the containing directory is named for that run, and otherwise
from the canonical ``docs/runs/<run_id>/`` path resolved against the current
working directory. A test that ran inside this repository would have the
vault's own copy of every ledger within reach, so it would pass whatever the
copy contained. The scratch directory has no ``docs/runs``, so each exhibit has
to answer for itself.

Three things were learned by doing this by hand on 16 October 2026, before any
of it was written down, and each is held below.

- **Both exit codes, never one.** The archive first chosen as the clean
  exhibit verifies at certificate exit 0 and fails its receipt at exit 2. It
  is now exhibit 6, where that pair is the point.
- **The directory is named for the run id.** Rename it and the same bytes,
  with the same ledger beside them, verify at exit 9 instead of exit 0.
- **Copying the whole directory is the rule, and the usual reason given for it
  is wrong.** Lifting a certificate alone does not reliably change the exit
  code; inside a checkout it still exits 0, against the vault's ledger. What
  changes is which ledger answered, and the exit code does not say.

Mutations measured on 16 October 2026, each run against the full file:

- select exhibit 1 on the certificate exit alone, dropping the
  ``- incomplete`` term: ``test_every_exhibit_produces_the_pair_it_claims``
  fails on the receipt code (1 failed).
- claim a passing receipt for exhibit 6: that test and
  ``test_the_exhibits_cover_distinct_answers`` fail (2 failed).
- document exhibit 4 with its ledger instead of ``--no-ledger``, when the
  archive ships none: 1 failed.
- verify the baseline record with the certificate verifier: 1 failed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_shop_window():
    """Registered in sys.modules before execution: the module defines a
    dataclass, and dataclasses resolve their annotations through the module
    entry, which a bare spec load has not created yet."""
    name = "shop_window"
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/shop_window.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SHOP_WINDOW = _load_shop_window()
FIGURES = json.loads((ROOT / "docs" / "archive-figures.json").read_text(encoding="utf-8"))
EXHIBITS = SHOP_WINDOW.select(FIGURES)


def _archive(run_id: str) -> Path:
    for base in (ROOT / "docs/runs", ROOT / "proofs/runs"):
        candidate = base / run_id
        if candidate.is_dir():
            return candidate
    raise AssertionError(f"{run_id} is selected as an exhibit and is not in the archive")


@pytest.fixture(scope="module")
def window(tmp_path_factory) -> Path:
    """A miniature shop window: the verifiers, the keys, and the exhibits."""
    built = tmp_path_factory.mktemp("shop-window")
    shutil.copytree(ROOT / "tools", built / "tools")
    shutil.copytree(ROOT / "spec", built / "spec")
    shutil.copytree(ROOT / "src", built / "src")
    (built / "exhibits").mkdir()
    for exhibit in EXHIBITS:
        destination = built / "exhibits" / exhibit.run_id
        if not destination.exists():
            shutil.copytree(_archive(exhibit.run_id), destination)
    return built


def _run(window: Path, argv: list):
    return subprocess.run(
        [sys.executable, *argv],
        cwd=window,
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(window / "src")),
    )


def _verify(window: Path, exhibit, directory: str) -> tuple:
    """Run exactly the command the shop window documents for this exhibit."""
    document = _run(window, exhibit.command(directory)).returncode
    receipt = _run(window, ["tools/verify_archive_receipt.py", directory]).returncode
    return document, receipt


def test_there_are_exhibits_to_check():
    """Guard the guard. A selector returning nothing must fail, not pass."""
    assert len(EXHIBITS) == 6, [e.number for e in EXHIBITS]
    assert all(e.run_id for e in EXHIBITS)


def test_every_exhibit_is_a_different_archive():
    """Six exhibits were seven, and two of them were the same run.

    Two slots had identical selectors, so `pool[0]` returned the same archive
    for both and the documented commands were byte-identical. The page said
    "seven real published archives" and its count of exhibits that do not come
    back clean counted that one archive twice. `no_ledger_to_bind` and
    `legacy_no_receipt` are the same 39 archives, so no archive has one
    property without the other and the two lessons belong to one exhibit.
    """
    runs = [e.run_id for e in EXHIBITS]
    assert len(set(runs)) == len(runs), sorted(runs)


def test_no_exhibit_is_one_of_the_ungated_baseline_certificates():
    """The defect that put an errata record on the front door.

    54 ungated baseline runs were published as audit certificates, errata E7.
    The set is in the same figures file as the five sets the selectors already
    read, and none of them subtracted it, so the exhibit labelled "a current
    certificate" was one of the 54: `AUDIT FAILED`, 100 leaks, on a run with
    no gate in the path. Anything drawn from that set has to say so, and no
    exhibit currently is.
    """
    ungated = set(FIGURES["legacy_ungated_certificates"])
    offenders = {
        e.number: e.run_id for e in EXHIBITS if e.run_id in ungated and e.errata != "E7"
    }
    assert not offenders, offenders


def test_an_exhibit_with_a_disclosed_defect_names_its_errata_entry():
    """The front door and the back room have to agree.

    Three of the six are archives whose defect the errata already records. A
    page that frames every failure as disclosure, beside an errata that frames
    them as defects with dates and causes, invites a reader to ask which
    document is for them.
    """
    disclosed = {e.number: e.errata for e in EXHIBITS if e.errata}
    assert len(disclosed) >= 3, disclosed
    assert all(entry.startswith("E") for entry in disclosed.values()), disclosed


def test_the_scratch_window_cannot_reach_the_vaults_ledgers(window):
    """Otherwise every exhibit below passes on the vault's copy, not its own."""
    assert not (window / "docs" / "runs").exists()
    assert not (window / "proofs" / "runs").exists()


@pytest.mark.parametrize("exhibit", EXHIBITS, ids=[f"{e.number}-{e.name}" for e in EXHIBITS])
def test_every_exhibit_produces_the_pair_it_claims(window, exhibit):
    document, receipt = _verify(window, exhibit, f"exhibits/{exhibit.run_id}")

    assert (document, receipt) == (exhibit.document_exit, exhibit.receipt_exit), (
        f"exhibit {exhibit.number}, {exhibit.name}, run {exhibit.run_id}: the "
        f"shop window would claim document exit {exhibit.document_exit} and "
        f"receipt exit {exhibit.receipt_exit}, and the copy produces "
        f"{document} and {receipt}"
    )


def test_naming_the_ledger_is_what_makes_the_commands_work(window):
    """Why every documented command names its ledger instead of relying on discovery.

    `verify_certificate.py` finds a ledger beside a certificate only when the
    directory is named for the `run_id` the certificate signs, and legacy
    certificates carry no `run_id` at all. A bare command therefore reports
    exit 9, "no ledger corresponding to the signed identity", for every legacy
    exhibit however complete the directory is.

    This holds the difference, so that shortening the documented command to
    one path fails here rather than on the front page.
    """
    # Exhibit 3 only. Exhibit 2 is also legacy and also ships a ledger, but its
    # signature fails first and returns exit 5 whatever the ledger does, so it
    # cannot isolate discovery.
    legacy = [e for e in EXHIBITS if e.number == 3]
    assert legacy, "this test needs a legacy exhibit whose archive ships a ledger"

    for exhibit in legacy:
        directory = f"exhibits/{exhibit.run_id}"
        bare = _run(window, [f"tools/verify_certificate.py", f"{directory}/audit.json"])

        assert bare.returncode == 9, (
            f"exhibit {exhibit.number} run without --ledger returned "
            f"{bare.returncode}; if discovery now works for legacy archives the "
            "documented command can be shortened, and this test should say so"
        )
        assert "no ledger corresponding to the signed identity" in bare.stdout + bare.stderr


def test_a_modern_certificate_still_needs_its_directory_named_for_its_run(window):
    """Discovery does work for a certificate that signs a run_id, and only then."""
    exhibit = next(e for e in EXHIBITS if e.number == 1)
    renamed = window / "exhibits" / "exhibit-1-a-clean-certificate"
    if not renamed.exists():
        shutil.copytree(window / "exhibits" / exhibit.run_id, renamed)

    found = _run(window, ["tools/verify_certificate.py",
                          f"exhibits/{exhibit.run_id}/audit.json"]).returncode
    lost = _run(window, ["tools/verify_certificate.py",
                         "exhibits/exhibit-1-a-clean-certificate/audit.json"]).returncode

    assert found == 0, found
    assert lost == 9, (
        "a directory not named for the signed run should lose its ledger, and "
        f"this one returned {lost}. The documented commands name the ledger so "
        "this cannot reach a visitor, and the layout keeps run-id names anyway"
    )


def test_each_exhibit_is_drawn_from_a_set_with_more_than_one_member(window):
    """A category with one member is a fact about today, not a category.

    Exhibit 7 is the exception and is allowed to be scarce: only two baseline
    records have been published, because the document kind arrived in 2.5.
    """
    scarce = {e.number: len(e.candidates) for e in EXHIBITS if len(e.candidates) < 2}

    assert not scarce, (
        "these exhibits have a single eligible archive, so the shop window "
        f"would be describing one run rather than a class of them: {scarce}"
    )


def test_the_exhibits_cover_distinct_answers():
    """Six commands, and not six ways of printing the same thing.

    This used to be the whole of the distinctness guarantee, and it is not
    enough on its own: it asserts distinct exit-code *pairs*, which two
    different slots holding one archive can still satisfy. The run-id test
    above is the one that caught that.
    """
    pairs = {(e.document_exit, e.receipt_exit) for e in EXHIBITS}

    assert len(pairs) >= 4, sorted(pairs)
    assert (0, 0) in pairs and (5, 2) in pairs and (9, 0) in pairs and (0, 2) in pairs


def test_an_archive_can_exit_zero_twice_and_still_not_be_established():
    """Why the verdict is a field and not a reading of the exit codes.

    The two verifiers answer one property each. `verify_evidence.py` answers
    over all of them, and an archive whose signed counters were never
    recomputed is NOT ESTABLISHED while exiting 0 from both. The window called
    exactly such an archive clean.

    Asserted from the figures rather than from the six, because none of the
    six is now in that state, and a test that only held while the selection
    happened to contain one would be a fact about today.
    """
    clean_pair = (
        set(FIGURES["binding_checked_and_holds"])
        - set(FIGURES["incomplete"])
        - set(FIGURES["receipt_signature_failed"])
    )
    unestablished = clean_pair - set(FIGURES["counters_true"])

    assert unestablished, (
        "no archive exits 0 from both verifiers with its counters unchecked, "
        "so the verdict could be read off the pair and this test is obsolete"
    )
    chosen = {e.run_id for e in EXHIBITS if (e.document_exit, e.receipt_exit) == (0, 0)}
    assert not (chosen & unestablished), sorted(chosen & unestablished)


def test_no_candidate_in_any_slot_is_one_of_the_ungated_certificates():
    """Asserted over the whole pool, not only over the archive that was picked.

    Checking the pick alone is not enough, and measuring showed why: removing
    the subtraction from exhibit 1's selector changes no exhibit, because the
    requirement that the signed counters were recomputed already excludes the
    54. The subtraction would then be defence with no effect, and the next
    change to that selector could silently rely on it being absent.
    """
    ungated = set(FIGURES["legacy_ungated_certificates"])
    offenders = {
        e.number: sorted(set(e.candidates) & ungated)[:3]
        for e in EXHIBITS
        if e.errata != "E7" and set(e.candidates) & ungated
    }
    assert not offenders, offenders


def test_the_ledger_flag_is_derived_from_the_archive_not_declared():
    """The command must name a file that is there.

    This was declared per slot. A parallel audit of every member of every pool
    found that three of the six candidates for the signature-failure slot ship
    no ledger while the slot said "beside". Their documented command still
    exits 5, because the signature fails before the ledger is reached, so the
    advertised exit code held and the command named a path that does not
    exist. Nothing on the page would have looked wrong except the file.

    It held only because `sorted(pool)[0]` happens to pick an archive from the
    April 5 group, which does ship one, and the three that do not are dated
    April 16 and sort later. That is a fact about today's run ids.
    """
    for exhibit in EXHIBITS:
        ledger = ROOT / "docs" / "runs" / exhibit.run_id / "proofs" / "itgl_ledger.jsonl"
        expected = "beside" if ledger.is_file() else "none"
        assert exhibit.ledger == expected, (exhibit.number, exhibit.ledger, expected)
        argv = exhibit.command(f"exhibits/{exhibit.run_id}")
        if expected == "beside":
            assert "--ledger" in argv, exhibit.number
        else:
            assert "--no-ledger" in argv, exhibit.number


def test_at_least_one_pool_disagrees_with_itself_about_shipping_a_ledger():
    """Why deriving it is necessary rather than tidy.

    If every pool were homogeneous in whether its archives ship a ledger, a
    declared flag would be correct by luck and this would be a style
    preference. One pool is not, so any change to the choice rule could put a
    `--ledger` path on the page for an archive that has none.
    """
    mixed = {}
    for exhibit in EXHIBITS:
        present = {
            (ROOT / "docs" / "runs" / run / "proofs" / "itgl_ledger.jsonl").is_file()
            for run in exhibit.candidates
        }
        if len(present) > 1:
            mixed[exhibit.number] = len(exhibit.candidates)
    assert mixed, (
        "every pool now agrees with itself about shipping a ledger, so this "
        "test no longer shows why the flag is derived; keep the derivation"
    )
