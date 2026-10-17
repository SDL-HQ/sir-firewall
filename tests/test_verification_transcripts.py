"""The published transcripts are what the verdict tool prints, not a paraphrase.

`docs/verification-transcripts.json` exists so that no consumer has to build a
verification result out of fields. The website did exactly that: it assembled
the expected output in JavaScript from the certificate's `signing_key_id`,
`itgl_final_hash`, `itgl_row_count` and `prompts_tested`, and published the
string as what the command prints. It matched on the day it was written,
because a person kept it in step by hand, and nothing held it there. That is
this repository's cardinal defect wearing a different hat, on the block of the
website most likely to be screenshotted.

The file is therefore only worth anything if it cannot drift. These tests
re-run the tool and compare, which is the same relationship
`tests/test_published_archive_figures.py` has with the generated figure
regions: the committed artefact is held against fresh output rather than read.

Two readings of one run also have to agree. The stored `verdict` label comes
from the tool's documented exit-code table, and the captured `stdout` ends in
its own `VERDICT:` line. Those are produced by different code paths, so a
disagreement between them is a real signal, and asserting it is cheaper than
either one alone.

What the scope is coupled to, and why it is not a round number. The file
covers both halves of the newest six valid-complete pairs, because the website
renders the newest six pairs and pins one of them. A run the site might show
and a run with no transcript must not be the same run, so the coupling is
asserted here rather than left as a comment in two repositories.

Mutations measured on 17 October 2026, each run against the full file:

- hand-edit one character of a stored `stdout`: `test_the_published_transcripts_are_what_the_tool_prints` fails (1 failed).
- change a stored `verdict` to a label the exit code does not carry: 2 failed,
  the agreement test and the drift test.
- drop a run from the committed file: 2 failed, the drift test and the
  coverage test.
- set `PAIRS` to 1: 2 failed, the drift test and the coverage test. This is
  the one worth having: it is the mutation that decouples this file from what
  the website can pin, which is the only reason the number is six.
- sort the scope by `pair_id` rather than by the gated run's timestamp:
  undetected, 30 passed. The two keys select the same eight newest pairs
  today, so nothing can distinguish them, and the test is written against the
  consumer's key so that it will distinguish them on the day they part. A pair
  is created after the run it pairs, so they can. Recorded rather than
  claimed.
- replace the exit-code table with every code mapping to "ESTABLISHED":
  10 failed. Predicted as 3 before measuring, and the gap is the useful part:
  the agreement test fires once per mislabelled run, which is the eight that
  are NOT ESTABLISHED, and the single-verdict test fires too, because a table
  where everything is ESTABLISHED makes the published set read as uniformly
  clean. Three tests, ten failures, and the figure here is the measured one.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = ROOT / "docs" / "verification-transcripts.json"


def _tool():
    spec = importlib.util.spec_from_file_location(
        "publish_verification_transcripts", ROOT / "tools/publish_verification_transcripts.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = _tool()
DOCUMENT = json.loads(PUBLISHED.read_text(encoding="utf-8"))
TRANSCRIPTS = DOCUMENT["transcripts"]


def test_the_file_covers_something():
    """Guard the guard. An empty set would make everything below vacuous."""
    assert len(TRANSCRIPTS) >= 2 * TOOL.PAIRS - 2, len(TRANSCRIPTS)
    assert DOCUMENT["verifier"] == "tools/verify_evidence.py"


def test_the_published_transcripts_are_what_the_tool_prints():
    """Re-captured and compared. The committed text is held, not read.

    This is the whole point of the file. A stored transcript that nothing
    re-runs is the same artefact as a hand-maintained string, with more steps.
    """
    completed = subprocess.run(
        [sys.executable, "tools/publish_verification_transcripts.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("run_id", sorted(TRANSCRIPTS))
def test_the_exit_code_and_the_printed_verdict_agree(run_id):
    """Two readings of one run, from different code paths."""
    entry = TRANSCRIPTS[run_id]
    expected = TOOL.VERDICTS[entry["exit_code"]]
    assert entry["verdict"] == expected

    lines = [line for line in entry["stdout"].splitlines() if line.startswith("VERDICT:")]
    assert len(lines) == 1, entry["stdout"]
    assert lines[0] == f"VERDICT: {expected}", (lines[0], expected)


@pytest.mark.parametrize("run_id", sorted(TRANSCRIPTS))
def test_every_transcript_names_the_archive_it_describes(run_id):
    """A transcript that names another run would bind the wrong pair."""
    entry = TRANSCRIPTS[run_id]
    assert entry["command"] == f"python3 tools/verify_evidence.py docs/runs/{run_id}"
    assert run_id in entry["stdout"]
    assert (ROOT / "docs" / "runs" / run_id).is_dir()


def test_the_scope_is_the_set_a_public_surface_can_pin():
    """Coupled to the website on purpose, and asserted rather than assumed.

    The site builds its table from the newest six pairs and selects the pinned
    row among them, so every run it could show has to have a transcript here.
    Six is that number, not a round one.
    """
    assert TOOL.PAIRS == 6
    assert DOCUMENT["pairs_covered"] == TOOL.PAIRS

    index = json.loads((ROOT / "docs/runs/benchmark_index.v3.json").read_text(encoding="utf-8"))
    entries = {entry["run_id"] for entry in index["entries"]}
    pairs = [
        pair
        for pair in index["pairs"]
        if pair.get("pair_status") == "valid_complete"
        and pair["gated_run_id"] in entries
        and pair["baseline_run_id"] in entries
    ]
    # The consumer's key, not the index's. See the note in the tool.
    pairs.sort(
        key=lambda pair: next(
            e for e in index["entries"] if e["run_id"] == pair["gated_run_id"]
        ).get("run_timestamp_utc") or pair["pair_id"],
        reverse=True,
    )

    for pair in pairs[: TOOL.PAIRS]:
        assert pair["gated_run_id"] in TRANSCRIPTS, pair["pair_id"]
        assert pair["baseline_run_id"] in TRANSCRIPTS, pair["pair_id"]


def test_the_exit_code_table_is_the_documented_one():
    """It is the tool's contract, and `CLAUDE.md` is where it is written down."""
    assert TOOL.VERDICTS == {
        0: "ESTABLISHED",
        1: "NOT ESTABLISHED",
        2: "FAILED",
        3: "UNREADABLE",
    }
    notes = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert "0 established, 1 **not established**, 2 failed" in notes


def test_the_published_set_reports_more_than_one_verdict():
    """A file in which everything passes would hide the thing it exists to show.

    Eight of the twelve runs the website can render are NOT ESTABLISHED, which
    is the fact the site could not state while it was building its own output
    from certificate fields. If this ever reads as a single verdict for every
    run, either the archive changed a great deal or the capture stopped
    capturing.
    """
    verdicts = {entry["verdict"] for entry in TRANSCRIPTS.values()}
    assert len(verdicts) > 1, verdicts
    assert "ESTABLISHED" in verdicts


def test_no_transcript_was_written_into_a_published_archive():
    """The archives are signed over their own file lists.

    `manifest.json` is signed over what a run directory holds and
    `check_archive_staged.py` compares it against the git index, so a
    transcript dropped into a published archive would make it disagree with
    its own signed manifest. That is the incomplete-archive defect, which was
    live for ninety-nine published archives.
    """
    for run_id in TRANSCRIPTS:
        directory = ROOT / "docs" / "runs" / run_id
        assert not (directory / "verification.txt").exists(), run_id
        assert not (directory / "verification-transcript.json").exists(), run_id
