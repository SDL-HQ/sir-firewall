#!/usr/bin/env python3
"""Publish what the verdict tool actually prints, captured rather than described.

Every public surface that shows a verification result has, until now, built
that result out of fields rather than running the command. The website
assembles its expected output in JavaScript from the certificate's
`signing_key_id`, `itgl_final_hash`, `itgl_row_count` and `prompts_tested`,
and claims the string is what the command prints. It matched, on the day it
was written, because a person kept it in step by hand. Nothing held it there.

That is this repository's cardinal defect in its usual shape: an assertion
derived from a second copy of an identity rather than computed from the thing
it names. `CLAUDE.md` says nothing detects it except deriving the value from
the referent, and the referent here is the tool's own stdout.

So this captures it. For each run in scope it runs
`tools/verify_evidence.py docs/runs/<run_id>`, stores the exact command, the
exact bytes it printed and the exit code it returned, and writes them to
`docs/verification-transcripts.json`. `docs/` is the GitHub Pages root, so a
consumer fetches the transcript and renders it verbatim. No consumer ever has
to reconstruct a sentence again.

Two things this deliberately does not do.

It does not write into a run directory. `manifest.json` is signed over the
files a run archive holds and `check_archive_staged.py` compares that manifest
against the git index, so adding a file to an already-published archive would
make it disagree with its own signed manifest. That is the incomplete-archive
defect, which was live for ninety-nine published archives. New runs could
carry a transcript signed with them; retrofitting published ones cannot be
done without breaking what they claim.

It does not record a verdict in its own words. The exit code is the tool's
own contract, documented in `CLAUDE.md`: 0 established, 1 not established,
2 failed, 3 the run directory could not be read. The label stored beside each
transcript comes from that table, and
`tests/test_verification_transcripts.py` holds it against the VERDICT line in
the captured stdout, so the two readings of one run have to agree.

Scope. The newest `PAIRS` valid-complete pairs in the benchmark index, both
halves of each. That is exactly the set the website can pin: it renders the
newest six pairs and chooses among them, so a run it might show and a run with
no transcript cannot be the same run. The coupling is deliberate and tested.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "runs" / "benchmark_index.v3.json"
OUTPUT = ROOT / "docs" / "verification-transcripts.json"
VERIFIER = "tools/verify_evidence.py"

#: How many pairs are covered. The website renders the newest six and pins one
#: of them, so six here is not a round number: it is that number.
PAIRS = 6

#: The verdict tool's documented exit codes. Its contract, not a paraphrase.
VERDICTS = {
    0: "ESTABLISHED",
    1: "NOT ESTABLISHED",
    2: "FAILED",
    3: "UNREADABLE",
}


def runs_in_scope() -> list:
    """Both halves of the newest valid-complete pairs, gated half first."""
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    entries = {entry["run_id"]: entry for entry in index.get("entries", [])}
    pairs = [
        pair
        for pair in index.get("pairs", [])
        if pair.get("pair_status") == "valid_complete"
        # A pair whose halves are not both in entries is one no consumer can
        # render, because it has nowhere to read the other half from.
        and pair.get("gated_run_id") in entries
        and pair.get("baseline_run_id") in entries
    ]

    def newest_first(pair):
        # The gated run's own timestamp, because that is the key the consumer
        # sorts by. Sorting by `pair_id` instead agreed with it on all eight
        # newest pairs when checked on 17 October 2026, and agreeing is not
        # the same as being the same key: a pair is created after the run it
        # pairs, so the two can part company and the sets would then differ by
        # one run at the boundary, silently, in whichever direction the
        # consumer did not expect.
        gated = entries[pair["gated_run_id"]]
        return gated.get("run_timestamp_utc") or pair.get("pair_id", "")

    pairs.sort(key=newest_first, reverse=True)

    ordered = []
    for pair in pairs[:PAIRS]:
        for run_id in (pair["gated_run_id"], pair["baseline_run_id"]):
            if run_id not in ordered:
                ordered.append(run_id)
    return ordered


def transcript(run_id: str) -> dict:
    """Run the verdict tool over one archive and keep what it printed."""
    directory = f"docs/runs/{run_id}"
    argv = [sys.executable, VERIFIER, directory]
    completed = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, check=False
    )
    code = completed.returncode
    if code not in VERDICTS:
        raise SystemExit(
            f"REFUSED: {VERIFIER} returned {code} for {run_id}, which is not one of "
            f"its documented exit codes {sorted(VERDICTS)}"
        )
    return {
        # Written as a person would type it, not as the subprocess was spawned:
        # sys.executable is this machine's interpreter path and would publish
        # a detail of the machine that happened to build it.
        "command": f"python3 {VERIFIER} {directory}",
        "exit_code": code,
        "verdict": VERDICTS[code],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def build() -> dict:
    scope = runs_in_scope()
    if not scope:
        raise SystemExit(
            "REFUSED: no valid-complete pair in the benchmark index has both halves "
            "in its entries, so there is nothing a consumer could render"
        )
    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verifier": VERIFIER,
        "exit_codes": {str(code): label for code, label in sorted(VERDICTS.items())},
        "pairs_covered": PAIRS,
        "transcripts": {run_id: transcript(run_id) for run_id in scope},
    }


def _without_timestamp(document: dict) -> dict:
    return {key: value for key, value in document.items() if key != "generated_at_utc"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="re-capture and compare against the committed file; the drift is the point",
    )
    args = parser.parse_args()

    fresh = build()
    if not args.check:
        # Only write when something other than the clock has moved. Both
        # publishing steps run this on every audit, and the first live one
        # committed a one-line diff to a published artefact for no reason but
        # a new timestamp. `generated_at_utc` therefore means when this
        # content was produced, not when the tool last ran; that the
        # transcripts were re-captured today is evidenced by the CI run that
        # did it, which is the right place for it.
        unchanged = (
            OUTPUT.is_file()
            and _without_timestamp(json.loads(OUTPUT.read_text(encoding="utf-8")))
            == _without_timestamp(fresh)
        )
        if unchanged:
            print(
                f"{OUTPUT.relative_to(ROOT)} already matches what {VERIFIER} prints "
                f"for all {len(fresh['transcripts'])} runs it covers; left untouched."
            )
            return 0
        OUTPUT.write_text(json.dumps(fresh, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"Captured {len(fresh['transcripts'])} transcripts from {VERIFIER} "
            f"into {OUTPUT.relative_to(ROOT)}"
        )
        for run_id, entry in fresh["transcripts"].items():
            print(f"  {entry['exit_code']}  {entry['verdict']:16} {run_id}")
        return 0

    if not OUTPUT.is_file():
        raise SystemExit(f"REFUSED: {OUTPUT.relative_to(ROOT)} has not been published")
    committed = json.loads(OUTPUT.read_text(encoding="utf-8"))
    if _without_timestamp(committed) != _without_timestamp(fresh):
        raise SystemExit(
            f"REFUSED: {OUTPUT.relative_to(ROOT)} no longer matches what "
            f"{VERIFIER} prints. Regenerate it rather than editing it."
        )
    print(
        f"{OUTPUT.relative_to(ROOT)} matches what {VERIFIER} prints for all "
        f"{len(fresh['transcripts'])} runs it covers."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
