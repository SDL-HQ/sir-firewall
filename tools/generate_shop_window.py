#!/usr/bin/env python3
"""Generate the evidence shop window from the published archive.

The shop window is a small, separate repository whose job is to get a stranger
from arriving to holding a verified fact in under two minutes. It is a build
artefact, not a sibling project: this tool selects the exhibits, copies them,
writes the documents and refuses to finish if any claim it is about to publish
does not hold.

Everything it writes is derived. The exit-code meanings come from
``docs/archive-figures.json``, the limits come verbatim from the evidence
perimeter, the counts come from the figures tables, and the exhibits come from
``tools/shop_window.py``. Nothing is retyped, because the whole value of the
shop window is that our claims survive checking, and a hand-maintained copy of
the vault drifts in the direction that flatters us.

The verification runs inside the generated directory, which has no
``docs/runs`` and no ``proofs/runs``. That is deliberate:
``verify_certificate.py`` falls back to the canonical archive path resolved
against the working directory, so a check run inside the main repository would
pass whatever the copy contained.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import publication_rules

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "docs" / "archive-figures.json"
PERIMETER = ROOT / "docs" / "evidence-perimeter.v6.md"
ERRATA = ROOT / "docs" / "archive-errata.md"
ARCHIVE = ROOT / "docs" / "runs"
VAULT = "https://github.com/SDL-HQ/sir-firewall"
WINDOW = "https://github.com/SDL-HQ/sir-evidence"

#: Nothing compiled travels. See the refusal at the end of generate().
_NO_BYTECODE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")


#: The window regenerates itself rather than being pushed to. A token issued to
#: Actions in the vault would need write access to a second public repository;
#: a token issued to Actions in the window needs write access only to itself.
#: The dependency arrow points the safe way.
REGENERATE_WORKFLOW = """\
name: Rebuild from the archive of record

# This file is written by tools/generate_shop_window.py in the archive of
# record. Do not edit it here. A token issued to Actions cannot update a
# workflow file, so when the generator changes it the job below fails and says
# how to push the new one by hand.

on:
  workflow_dispatch:
  schedule:
    - cron: "17 6 * * 1"

permissions:
  contents: write

jobs:
  rebuild:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          path: window

      - name: Check out the archive of record at its latest release tag
        run: |
          git clone --quiet {vault}.git vault
          cd vault
          git checkout --quiet "$(git tag --list --sort=-v:refname | head -n 1)"

      # The window is pinned at a release tag and rebuilt from that tag's tree,
      # so a tag older than the generator cannot rebuild it. That was true of
      # the release this window was first published from, and stops being true
      # at the next one. Skipping says so rather than failing every week for a
      # reason nobody can act on.
      - name: Stop here if the generator is not in that release
        id: pin
        run: |
          cd vault
          tag="$(git describe --tags --exact-match)"
          if [ -f tools/generate_shop_window.py ]; then
            echo "buildable=yes" >> "$GITHUB_OUTPUT"
          else
            echo "buildable=no" >> "$GITHUB_OUTPUT"
            echo "::notice::$tag predates the generator, so the window cannot be \
          rebuilt from it and nothing in the window can change until the next release."
          fi

      - name: Install the only dependency the verifiers have
        if: steps.pin.outputs.buildable == 'yes'
        run: python3 -m pip install --quiet cryptography

      - name: Build, which refuses if a documented exit code does not reproduce
        if: steps.pin.outputs.buildable == 'yes'
        run: python3 vault/tools/generate_shop_window.py --out built

      - name: Stop if the generator would change this workflow
        if: steps.pin.outputs.buildable == 'yes'
        run: |
          if ! diff -r built/.github window/.github; then
            echo "The generator writes a different workflow than this repository holds."
            echo "Actions cannot update a workflow file. Push it from a clone of the"
            echo "archive of record:"
            echo "  python3 tools/generate_shop_window.py --out w && cp -a w/.github ."
            exit 1
          fi

      - name: Replace the window with what was built
        if: steps.pin.outputs.buildable == 'yes'
        run: |
          cd window
          find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {{}} +
          cp -a ../built/. .
          git add -A

      - name: Commit, if anything moved
        if: steps.pin.outputs.buildable == 'yes'
        run: |
          cd window
          if git diff --cached --quiet; then
            echo "The window already matches the archive of record."
            exit 0
          fi
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git commit -qm "Rebuild from $(sed -n 's/^tag //p' GENERATED)"
          git push
"""

#: The three verifiers a visitor runs, and the modules they import from
#: tools/. Held by a test, so a new import fails there rather than in the
#: generated repository.
#: `verify_evidence.py` is the command the archive of record tells a reader to
#: prefer, and it was not shipped. The window showed six exit codes from three
#: single-property tools and called two of them clean, while the project's own
#: verdict tool said NOT ESTABLISHED about one of those two. It executes
#: `validate_certificate_contract.py`, so that ships too: without it the
#: verdict tool reports a missing helper as "the certificate violates its
#: applicable evidence contract", which is the worst wrong answer available.
VERIFIER_FILES = (
    "verify_certificate.py",
    "verify_baseline_record.py",
    "verify_archive_receipt.py",
    "verify_evidence.py",
    "validate_certificate_contract.py",
    "key_registry.py",
    "itgl.py",
    "document_signing.py",
)

#: Everything a shipped verifier may import without the visitor installing
#: anything: the standard library, and the other files the window ships.
SHIPPED_MODULES = {"key_registry", "itgl", "document_signing", "sir_firewall"}

#: Written out because the public claims write them out. A figure quoted in
#: words still has to be true.
WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight"}


def third_party_dependencies() -> set:
    """What a visitor has to install, read from the imports of what ships.

    Parsed with `ast` rather than matched against the file text. A first
    version of this, in the test that used to own it, matched line starts and
    reported a dependency named "the", from a docstring sentence beginning
    "from the". It would have gone red on prose and stayed green on an import
    inside a function, which is the wrong way round.
    """
    found = set()
    for name in VERIFIER_FILES:
        tree = ast.parse((ROOT / "tools" / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for imported in names:
                top = imported.split(".")[0]
                if not top or top == "__future__" or top in SHIPPED_MODULES:
                    continue
                if top in sys.stdlib_module_names:
                    continue
                found.add(top)
    return found


def verifier_commands() -> list:
    """The files a visitor runs, as against the files that get copied."""
    return [name for name in VERIFIER_FILES if name.startswith("verify_")]


def _shop_window():
    name = "shop_window"
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/shop_window.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _archive(run_id: str) -> Path:
    for base in (ROOT / "docs/runs", ROOT / "proofs/runs"):
        if (base / run_id).is_dir():
            return base / run_id
    raise LookupError(f"{run_id} is selected as an exhibit and is not in the archive")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digests(directory: Path) -> dict:
    return {
        str(p.relative_to(directory)): _digest(p)
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


# --- the documents ----------------------------------------------------------


def _model_invocation(exhibit) -> tuple:
    """Whether the named model ran, read from the field its own kind uses.

    The two document kinds record this differently and nothing made that
    explicit, so a note written for one was applied to the other and published
    a false sentence. A certificate carries `model_calls_made` at the top
    level. A baseline record carries no such field: its counters live under
    `counters`, as `provider_call_attempts` and `provider_call_successes`,
    because an ungated baseline forwards every prompt by definition. Reading
    the certificate's field on a baseline returned None, which read as zero,
    and the page said the model did not run on a record of fifty calls to it.

    Returns (model, provider, calls). Refuses rather than guessing: a document
    that names a model and records nothing about calling it is a claim this
    tool cannot derive, and the page must not carry a sentence about it.
    """
    document = json.loads(
        (ARCHIVE / exhibit.run_id / exhibit.document).read_text(encoding="utf-8")
    )
    model, provider = document.get("model"), document.get("provider")
    if not model:
        return (None, None, None)

    if "model_calls_made" in document:
        return (model, provider, document["model_calls_made"])
    counters = document.get("counters") or {}
    for field in ("provider_call_successes", "provider_call_attempts"):
        if field in counters:
            return (model, provider, counters[field])
    # Three-valued, like every other answer this project gives. A January
    # archive names a model and carries no call counters at all, because the
    # counters postdate it. That is not zero calls and it is not a reason to
    # refuse: it is unknown, and unknown has its own answer here as it does in
    # the verdict tool. Writing the refusal first is what surfaced it.
    return (model, provider, None)


def _model_note(exhibit) -> str:
    """One line per exhibit, because no verifier on the page reports this."""
    model, provider, calls = _model_invocation(exhibit)
    if not model:
        return ""
    if calls is None:
        return (
            f"Signed payload: `model` is `{model}` on `{provider}`, and the "
            "document records no call counters at all, because they postdate "
            "it. **Whether the named model ran cannot be told from this "
            "archive.** That is not the same as zero."
        )
    if calls:
        return (
            f"Signed payload: `model` is `{model}` on `{provider}`, with "
            f"{calls} recorded calls to it. **The named model did run.**"
        )
    return (
        f"Signed payload: `model` is `{model}` on `{provider}`, with zero "
        "recorded calls. **The named model did not run**, and no verifier on "
        "this page would tell you that."
    )


def _ran(exhibit) -> str:
    """The table cell, because a reader who stops at the table stops there.

    The note under the commands was not enough: an outside reader pointed out
    that the row still said an archive establishes every property with nothing
    beside it about the model it names never having been called.
    """
    model, _, calls = _model_invocation(exhibit)
    if not model:
        return "-"
    if calls is None:
        return "unknown"
    return f"yes, {calls}" if calls else "**no**"


def _errata_lists(run_id: str) -> bool:
    """Whether the errata names this archive, or only describes its class.

    Three of the exhibits are listed individually in an appendix. The fourth
    is covered by E4, which describes 223 archives whose ledger binding cannot
    be established and enumerates none of them. Saying all four are "written
    up" is true and leaves a reader who greps for the id finding it for three
    and not the fourth, so the page says which it is.
    """
    return run_id in ERRATA.read_text(encoding="utf-8")


def _documented_exits(tool: str) -> list:
    """Exit codes the verifier documents in its own epilog.

    The published figures only hold codes some archive actually produced, so
    exit 7 (a ledger that does not re-derive) and exit 12 (the wrong document
    kind) are absent from them: nothing published is tampered with, and no
    certificate is a baseline record. They are the two codes the window most
    needs to explain, so they come from the verifier's own text.
    """
    source = (ROOT / "tools" / tool).read_text(encoding="utf-8")
    # The epilog is written as adjacent string literals, so a sentence can run
    # across two of them. Joined first: a first version matched one literal at
    # a time and produced exit 12 as "the document is not a SIR audit
    # certificate, and nothing", which stops exactly before the part that
    # matters.
    joined = re.sub(r'\\n"\s*\n\s*"', " ", source)
    found = []
    # Non-greedy to the first full stop: joining the literals also joined the
    # sentences, so a greedy match returned all three codes as one meaning.
    for match in re.finditer(r"Exit code (\d+) means (.+?\.)", joined, re.S):
        found.append((int(match.group(1)), " ".join(match.group(2).split()).rstrip(".")))
    return found


def _exit_tables(figures: dict) -> dict:
    """Every published row, in order, plus the codes the tool documents itself.

    This was a dict keyed on the exit code. `certificate_rows` holds two exit-0
    rows, 80 "verified" and 39 "verified; no ledger in the archive, so no
    binding was checked", so the dict kept the second and the page told a
    reader that exit 0 means no binding was checked, directly beneath two
    exhibits that exit 0 with the binding checked and say so.
    """
    tables = {}
    for name, key in (("certificate", "certificate_rows"), ("receipt", "receipt_rows"),
                      ("baseline", "baseline_record_rows")):
        rows = [
            (row["exit"], row["meaning"], row["count"])
            for row in figures[key]
            if row["exit"] is not None
        ]
        tables[name] = rows
    observed = {code for code, _, _ in tables["certificate"]}
    tables["certificate_documented"] = [
        (code, meaning) for code, meaning in _documented_exits("verify_certificate.py")
        if code not in observed
    ]
    return tables


def _perimeter_section(heading: str) -> tuple:
    """The section's own lead-in and bullets, verbatim.

    The lead-in matters. "Explicit non-claims" opens with "Current evidence and
    implementation do not claim that SIR:", and its bullets continue that
    sentence. Lifting the bullets under a heading written here produced "SIR
    does not claim to / prevents all prompt injection", which is the kind of
    small wrongness that makes a reader stop trusting the page.
    """
    text = PERIMETER.read_text(encoding="utf-8")
    body = text.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0]
    lines = [line for line in body.splitlines() if line.strip()]
    lead = lines[0] if not lines[0].startswith("- ") else ""
    return lead, [line for line in lines if line.startswith("- ")]


def _readme(exhibits, figures, tag: str) -> str:
    rows = "\n".join(
        f"| {e.number} | {e.name} | `{e.tool}` | `{e.document_exit}` | "
        f"`{e.receipt_exit}` | **{e.verdict}** | {_ran(e)} | {e.errata or '-'} |"
        for e in exhibits
    )
    # Counted on the verdict, and counted over archives. An earlier version
    # counted rows whose exit codes were non-zero, over a list in which one
    # archive appeared twice, and asserted "seven real published archives"
    # above it. Both numbers were wrong and the page was confident.
    established = [e for e in exhibits if e.verdict == "ESTABLISHED"]
    unclean = [e for e in exhibits if e.verdict != "ESTABLISHED"]
    disclosed = [e for e in exhibits if e.errata]
    return f"""# SIR, in six commands and one you break yourself

SIR is a deterministic pre-inference gate. It reads a request before a model
does, decides `PASS` or `BLOCKED` by rules alone with no model in the decision
path, and writes a signed record of what it saw and what it decided. The record
is the point: it can be checked offline, by someone who does not have to take
our word for what it says.

That is not the same as independent of us. The verifiers here are ours and the
signing key is ours, so a signature that verifies establishes that we signed
that payload, not that the payload is true. [LIMITS.md](LIMITS.md) says what
follows from that, and it is the second thing to read.

This repository is generated from the archive of record, pinned at `{tag}`. It
holds {len(exhibits)} real published archives, each chosen because running our
verifiers against it produces a different answer.

**Our own verdict tool establishes {len(established)} of the {len(exhibits)}.**
`verify_evidence.py` prints one verdict over every property of an archive, and
exit 0 from a single-property verifier is not the same thing. {len(unclean)} of
these {len(exhibits)} come back NOT ESTABLISHED or FAILED, and
{len(disclosed)} of them are defects this project has already written up in its
own errata, named in the table.

| # | Exhibit | Document verifier | Its exit | Receipt exit | Verdict | Named model ran | Errata |
|---|---|---|---|---|---|---|---|
{rows}

[VERIFY.md](VERIFY.md) has the exact command for each, explains why each one
names its ledger, and ends with a recipe for changing one field in one ledger
row so you can watch the chain refuse to re-derive. That last one is the only
item here that is a detection rather than a disclosure, and it is the reason
the evidence plane exists.

The archive of record is at [{VAULT}]({VAULT}). It holds
{figures['total']} runs and {figures['certificates_total']} certificates.

Nothing here is a sample chosen for how it looks. Each exhibit is selected from
a category by a tool in the main repository, a test there refuses any category
with fewer than two eligible archives, and another refuses any exhibit drawn
from the 54 ungated baseline runs this project published as audit
certificates. The first version of this page failed that last check, which did
not exist: its lead exhibit was one of the 54.

## This repository is generated

Every file here except the workflow that rebuilds it is written by
`tools/generate_shop_window.py` in the archive of record, from the latest
release tag. Nothing is edited in place. An edit made here would be discarded
by the next rebuild rather than read, so issues and changes belong in the
archive of record. `GENERATED` records the tag, the commit it was built from,
and when.

The build is not a copy. It runs every command on this page inside the
directory it has just written, including the tampering recipe, and stops
without publishing if any exit code or verdict differs from the one the page
gives for it.
"""


def _limits() -> str:
    claims_lead, non_claims = _perimeter_section("Explicit non-claims")
    support_lead, unsupported = _perimeter_section("What current evidence does not support")
    # The perimeter gives "Explicit non-claims" a lead-in sentence and gives
    # the second section none: its bullets start immediately under the
    # heading. An earlier version of this file claimed "lead-in sentences
    # included" for both and rendered a two-line hole where the second one
    # would be, which is the same class of defect as the missing lead-in it
    # was written to prevent.
    def section(heading: str, lead: str, bullets: list) -> str:
        body = f"{lead}\n\n" if lead else ""
        if not lead:
            body = (
                "The perimeter gives this list no lead-in sentence, so there is none to\n"
                "lift. Its items are scoped by the perimeter itself, and the phrase\n"
                '"listed here" in the last of them means listed there, not here.\n\n'
            )
        return f"## {heading}\n\n{body}{chr(10).join(bullets)}"

    return f"""# What SIR does not do

Lifted verbatim from the evidence perimeter in the archive of record, with each
section's own lead-in sentence where the perimeter has one. Nothing here is
rewritten for this page, because a limit restated for a front door is a limit
softened for a front door.

{section("Explicit non-claims", claims_lead, non_claims)}

{section("What current evidence does not support", support_lead, unsupported)}

## And the one that applies to this repository

The exhibits show that our verifiers behave as we say they do on archives we
published. They do not show that the gate is adequate, that a passing
certificate means a safe run, or that the rule set covers any attack you care
about. `AUDIT PASSED` is a statement about one run's counters and its own
checks, and nothing more.
"""


def _verify_doc(exhibits, tables, tamper) -> str:
    blocks = []
    for e in exhibits:
        command = _shell(e.command(f"exhibits/{e.run_id}"))
        extra = ""
        if e.refusal_exit is not None:
            refusal = _shell(e.refusal_command(f"exhibits/{e.run_id}"))
            extra = f"""

And the part this exhibit exists for, the wrong verifier refusing it rather
than reporting something about it:

```
python3 {refusal}
```

Exits `{e.refusal_exit}`, naming the document kind it found."""
        model = _model_note(e)
        model = f"\n\n{model}" if model else ""
        if not e.errata:
            errata = ""
        elif _errata_lists(e.run_id):
            errata = (
                f"\n\nThis archive is listed individually under **{e.errata}** in the "
                "archive of record's errata."
            )
        else:
            errata = (
                f"\n\nThis archive's defect is **{e.errata}** in the archive of record's "
                "errata, which describes the class and does not enumerate its members, so "
                "searching that document for this run id finds nothing."
            )
        blocks.append(
            f"""### {e.number}. {e.name}

{e.teaches}

```
python3 {command}
python3 tools/verify_archive_receipt.py exhibits/{e.run_id}
python3 tools/verify_evidence.py exhibits/{e.run_id}
```

Document verifier exits `{e.document_exit}`, receipt verifier exits \
`{e.receipt_exit}`, and the verdict is **{e.verdict}**.{model}{errata}{extra}"""
        )

    def rows(entries):
        return "\n".join(f"| `{code}` | {meaning} | {count} |" for code, meaning, count in entries)

    # Observed and documented in one table, ordered by exit code, with the two
    # exit-0 rows kept in the order the figures publish them.
    certificate_rows = sorted(
        list(tables["certificate"])
        + [(c, m, "none published") for c, m in tables["certificate_documented"]],
        key=lambda row: row[0],
    )
    zero = [row for row in tables["certificate"] if row[0] == 0]
    shared = (
        f"Two rows share exit 0, because {zero[0][2]} archives verified with their "
        f"binding checked and {zero[1][2]} verified without a ledger to check it "
        "against, and those are different facts"
        if len(zero) == 2
        else "Each exit code appears once"
    )

    return f"""# Verifying the exhibits

Every command below runs offline against a file in this repository. Nothing
calls a model provider, and nothing needs a credential.

## Three commands per exhibit, and the third is the one that answers

The first two verify one property each: the signed document, and the archive's
own manifest. `verify_evidence.py` runs those and the rest, and prints one
verdict over all of them. It is the command the archive of record tells a
reader to prefer, and an exit code of 0 from the first two is not the same
thing as its verdict:

- **ESTABLISHED** every applicable property established, none unknown
- **NOT ESTABLISHED** nothing failed, but at least one property is unknown
- **FAILED** at least one property actively failed

Not established is not a failure and it is not a pass. A certificate no
evidence contract governs has not failed a contract; a ledger that predates the
fields needed to recompute the signed counters has not disagreed with them.
Both are unknown, and unknown has its own verdict.

## A certificate always names a model, even when none ran

Every evidence contract requires `model` and `provider` to be present and
non-empty, so a certificate has to name something, and the publishing workflow
supplies a default when no model was selected. A firewall-only audit therefore
names a commercial product and records `model_calls_made: 0` against it. The
archive of record discloses that as errata **E6**.

The verifiers have no property for it. They check the payload hash, the
signature, the ledger binding, the signed counters, archive custody and the
evidence contract, and a certificate naming a model that took no part in the
run establishes every one of them. So each exhibit below states what its
payload says about the model, because nothing you run here will.

An outside reader found this on the lead exhibit, where the window said an
archive establishes every property and did not mention that the model it names
never ran.

## Why each command names its ledger

A certificate is bound to the ledger of the run it signs, so verifying one
means checking it against that ledger. The verifier can usually find the
ledger by itself, from the run id inside the signed payload.

**Older certificates carry no run id.** They predate the field. For those the
verifier has nothing to key on, finds no ledger however complete the directory
is, and reports that the binding was not checked. That is a true answer and a
confusing one, so every command here names the ledger explicitly, and the
archive that ships no ledger at all passes `--no-ledger` instead.

We could have hidden this in a one-word wrapper. We have not, because the
point of this repository is that you can see exactly what is being checked.

## The commands

{(chr(10) + chr(10)).join(blocks)}

## Break one and watch it get caught

Every exhibit above is an archive we published and a defect we disclosed. None
of them is a detection, and detection is the whole proposition, so here is one
you perform yourself. Copy exhibit 1, change one field in one ledger row, and
re-run the command that passed:

```
{tamper['recipe']}
```

Exits `{tamper['exit']}`, and names the row and both hashes:

```
{tamper['message']}
```

One field in one row of {tamper['rows']}, and the chain does not re-derive.

## How to read the exit codes

Certificate verifier. {shared}:

| Exit | Meaning | Archives |
|---|---|---|
{rows(certificate_rows)}

Archive receipt verifier:

| Exit | Meaning | Archives |
|---|---|---|
{rows(tables["receipt"])}

Baseline record verifier:

| Exit | Meaning | Archives |
|---|---|---|
{rows(tables["baseline"])}

Every meaning and count above is generated from the archive of record's own
published figures, except the two exit codes no published archive produces,
which are generated from the verifier's own documentation.
"""


# --- generation and its assertions ------------------------------------------


def _shell(argv: list) -> str:
    """Wrap a command so a flag never loses its argument to a line break."""
    parts, i = [], 0
    while i < len(argv):
        if argv[i].startswith("--") and i + 1 < len(argv) and not argv[i + 1].startswith("--"):
            parts.append(f"{argv[i]} {argv[i + 1]}")
            i += 2
        else:
            parts.append(argv[i])
            i += 1
    return " \\\n    ".join(parts)


def _run(window: Path, argv: list):
    return subprocess.run(
        [sys.executable, "-B", *argv],
        cwd=window,
        capture_output=True,
        text=True,
        # Both, and they are not redundant. `-B` covers the process this
        # starts; the environment variable covers its children, which matters
        # because `verify_evidence.py` runs the other verifiers as
        # subprocesses of its own and `-B` does not reach them. An earlier
        # measurement found each sufficient alone and removed the variable as
        # untestable, which was true of the code at the time and stopped being
        # true the moment a tool that spawns children was shipped.
        # No PYTHONPATH: a visitor does not set one, and the window ships no
        # package for it to point at. Measuring with one made the generator
        # exercise an import path no reader reaches.
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
    )


def _tamper_recipe(run_id: str, row: int) -> str:
    """The exact text the page publishes, built once so it can be run verbatim.

    The generator used to reimplement something similar in Python and measure
    that. The published recipe then turned out to be neither idempotent nor
    one-way: `cp -r src /tmp/tampered` nests when the destination already
    exists, and flipping `expected` between two values restores the original on
    a second run. A visitor who ran it twice, which is what a sceptic does, got
    exit 0 and the reasonable conclusion that we cannot detect a changed byte.
    Measuring a paraphrase of a published command is not measuring it.
    """
    lines = [
        "rm -rf /tmp/sir-tampered",
        "cp -r exhibits/" + run_id + " /tmp/sir-tampered",
        "python3 - <<'EOF'",
        "import json, pathlib",
        'p = pathlib.Path("/tmp/sir-tampered/proofs/itgl_ledger.jsonl")',
        "rows = p.read_text().splitlines()",
        "row = json.loads(rows[" + str(row) + "])",
        'row["expected"] = "tampered"',
        "rows[" + str(row) + '] = json.dumps(row, separators=(",", ":"), sort_keys=True)',
        'p.write_text("\\n".join(rows) + "\\n")',
        "EOF",
        "python3 tools/verify_certificate.py /tmp/sir-tampered/audit.json "
        "--ledger /tmp/sir-tampered/proofs/itgl_ledger.jsonl",
    ]
    return "\n".join(lines)


def _verdict(window: Path, directory: str) -> str:
    """What `verify_evidence.py` says, run inside the generated window."""
    result = _run(window, ["tools/verify_evidence.py", directory])
    for line in reversed((result.stdout + result.stderr).splitlines()):
        if line.startswith("VERDICT:"):
            return line.split(":", 1)[1].strip()
    return f"<no verdict, exit {result.returncode}>"


def _tamper(window: Path, exhibit) -> dict:
    """Run the published recipe, verbatim and twice.

    Twice, because the first version of this recipe passed once and then
    quietly undid itself: it toggled a field between two values and copied into
    a directory that already existed. Once is not a measurement of something a
    stranger may run more than once.

    Three earlier attempts at measuring this failed in the rig rather than the
    product, twice looking like the chain not detecting a change: once because
    the copy had no `spec/` so no key loaded, and once because the edit was
    applied conditionally and the row was left untouched. Hence the method:
    change the bytes, check the file hash moved, then run the verifier.
    """
    ledger = window / "exhibits" / exhibit.run_id / "proofs" / "itgl_ledger.jsonl"
    rows = ledger.read_text(encoding="utf-8").splitlines()
    row = len(rows) // 2
    if "expected" not in json.loads(rows[row]):
        raise SystemExit("REFUSED: the tamper recipe's field is not in this ledger's rows")
    recipe = _tamper_recipe(exhibit.run_id, row)

    runs = []
    for _ in range(2):
        runs.append(
            subprocess.run(
                recipe,
                shell=True,
                executable="/bin/bash",
                cwd=window,
                capture_output=True,
                text=True,
                env=dict(
                    os.environ,
                    PYTHONDONTWRITEBYTECODE="1",
                ),
            )
        )
    message = next(
        (line.strip() for line in (runs[0].stdout + runs[0].stderr).splitlines()
         if "ERROR" in line),
        "",
    )
    return {
        "run_id": exhibit.run_id,
        "row": row,
        "rows": len(rows),
        "exit": runs[0].returncode,
        "exit_again": runs[1].returncode,
        "message": message,
        "recipe": recipe,
    }


def _about(exhibits) -> str:
    """The window's About line, from the same figures as the README.

    GitHub keeps a repository's About line in its settings rather than in the
    tree, so it is the one public claim about the window that no test can
    reach and no rebuild can correct. It went stale within a day of being
    written, saying seven archives and three verifiers after the corrections
    removed one of each, and it was a reviewer who noticed rather than us.

    Emitting it here does not fix that, because a person still has to paste
    it. It does mean the figures in it are derived rather than remembered,
    there is one place to copy from, and `_about_holds` refuses the build if
    the sentence stops being true of the exhibits it describes.
    """
    established = [e for e in exhibits if e.verdict == "ESTABLISHED"]
    unclean = [e for e in exhibits if e.verdict != "ESTABLISHED"]
    return (
        f"{WORDS[len(exhibits)].capitalize()} published SIR archives, "
        f"{WORDS[len(verifier_commands())]} verifiers, "
        f"{WORDS[len(third_party_dependencies())]} dependency. "
        f"Our own verdict tool establishes {WORDS[len(established)]} of the "
        f"{WORDS[len(exhibits)]}, and the {WORDS[len(unclean)]} it does not are "
        "defects we have written up."
    )


def _about_holds(exhibits) -> list:
    """Whether the About line's last clause is true, rather than coincidental.

    "the N it does not are defects we have written up" asserts that the
    exhibits the verdict tool fails to establish are the same exhibits that
    name an errata entry. Today those two sets happen to be equal, and equal
    counts are not the same as one set. Nothing stops a future exhibit being
    NOT ESTABLISHED with no errata entry, or established and disclosed, at
    which point the counts could still match while the sentence is false.
    """
    unclean = {e.run_id for e in exhibits if e.verdict != "ESTABLISHED"}
    disclosed = {e.run_id for e in exhibits if e.errata}
    if unclean == disclosed:
        return []
    return [
        "the About line says the archives the verdict tool does not establish are "
        f"the ones written up in the errata, and they are not: not established "
        f"{sorted(unclean)}, written up {sorted(disclosed)}"
    ]


def _not_for_publication(out: Path) -> dict:
    """Run the repository's publication rules over the tree about to be pushed.

    The window is a second public repository and most of what it carries is
    copied from files the vault's own guard already scans. Its prose is not:
    README.md, LIMITS.md, VERIFY.md and GENERATED are written here, exist in no
    file in the vault, and interpolate model names, paths, dates and an error
    message captured live from a subprocess. Nothing inspected them until this.

    Exhibits are treated exactly as the vault treats an archive, which is to
    say the secret rules apply and the writing rules do not. An archive is
    generated evidence, and the prompts inside an audited run may contain any
    words at all, including the ones the patent rule refuses.
    """
    offences = {}
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(out).as_posix()
        archive = relative.startswith("exhibits/")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            text = None
        found = publication_rules.offences(
            relative, text, working_documents=not archive, patent=not archive
        )
        if found:
            offences[relative] = found
    return offences


def generate(out: Path, tag: str) -> list:
    figures = json.loads(FIGURES.read_text(encoding="utf-8"))
    module = _shop_window()
    exhibits = module.select(figures)

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    # Only the verifiers and the modules they import. The main tools directory
    # is over a megabyte of scripts a visitor never runs, and "nothing else" is
    # the rule this repository is built on.
    (out / "tools").mkdir()
    for name in VERIFIER_FILES:
        shutil.copy2(ROOT / "tools" / name, out / "tools" / name)
    shutil.copytree(ROOT / "spec", out / "spec", ignore=_NO_BYTECODE)
    # No `src/`. One optional branch of the certificate verifier imports
    # `sir_firewall.evidence_paths` for the canonical-path fallback, inside a
    # try/except ImportError, and that fallback resolves `docs/runs/<id>/...`
    # against the working directory, which this window asserts it does not
    # have. So the branch was already dead here, and shipping it cost 416K
    # containing the gate itself: `core.py`, the deterministic rules and the
    # policy packs, in a repository whose limits say the exhibits do not show
    # the gate is adequate. `evidence_paths` is ten lines importing only
    # pathlib; the package came with it because `__init__.py` imports `.core`.
    #
    # A visitor never sets PYTHONPATH either, so they always took the
    # import-failure path. The generator used to set it and was measuring
    # something no reader does.
    (out / "exhibits").mkdir()

    problems = []
    for exhibit in exhibits:
        source = _archive(exhibit.run_id)
        destination = out / "exhibits" / exhibit.run_id
        if not destination.exists():
            shutil.copytree(source, destination, ignore=_NO_BYTECODE)
        if _tree_digests(source) != _tree_digests(destination):
            problems.append(f"exhibit {exhibit.number}: the copy differs from the archive")

    # Copied, not retyped. A licence that drifts from the one it was derived
    # from is worse than no licence at all.
    shutil.copy2(ROOT / "LICENSE", out / "LICENSE")
    workflows = out / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "rebuild.yml").write_text(
        REGENERATE_WORKFLOW.format(vault=VAULT), encoding="utf-8"
    )

    (out / "README.md").write_text(_readme(exhibits, figures, tag), encoding="utf-8")
    (out / "LIMITS.md").write_text(_limits(), encoding="utf-8")
    # Measured inside the window, because the page publishes the recipe and
    # the exit code it produces.
    tamper = _tamper(out, exhibits[0])
    if tamper["exit"] != module.TAMPER_EXIT:
        problems.append(
            f"the tamper recipe claims exit {module.TAMPER_EXIT} and produced {tamper['exit']}"
        )
    if tamper["exit_again"] != module.TAMPER_EXIT:
        problems.append(
            f"the tamper recipe produced {tamper['exit']} and then "
            f"{tamper['exit_again']} on a second run, so a reader who repeats it is "
            "told the change was not detected"
        )
    if not tamper["message"]:
        problems.append("the tamper recipe produced no error naming what failed")
    (out / "VERIFY.md").write_text(
        _verify_doc(exhibits, _exit_tables(figures), tamper), encoding="utf-8"
    )

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()
    (out / "GENERATED").write_text(
        f"source {VAULT}\ntag {tag}\ncommit {commit}\n"
        f"generated {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"archives {figures['total']}\ncertificates {figures['certificates_total']}\n"
        f"about {_about(exhibits)}\n",
        encoding="utf-8",
    )
    problems += _about_holds(exhibits)

    # No archive here, so nothing can answer for an exhibit but the exhibit.
    if (out / "docs" / "runs").exists() or (out / "proofs" / "runs").exists():
        problems.append("the generated window can reach an archive, so its checks prove nothing")

    for exhibit in exhibits:
        directory = f"exhibits/{exhibit.run_id}"
        document = _run(out, exhibit.command(directory)).returncode
        receipt = _run(out, ["tools/verify_archive_receipt.py", directory]).returncode
        if (document, receipt) != (exhibit.document_exit, exhibit.receipt_exit):
            problems.append(
                f"exhibit {exhibit.number}, {exhibit.name}: claims "
                f"{exhibit.document_exit}/{exhibit.receipt_exit}, produces {document}/{receipt}"
            )
        verdict = _verdict(out, directory)
        if verdict != exhibit.verdict:
            problems.append(
                f"exhibit {exhibit.number}, {exhibit.name}: the page says the verdict is "
                f"{exhibit.verdict} and verify_evidence.py says {verdict}"
            )
        if exhibit.refusal_exit is not None:
            refused = _run(out, exhibit.refusal_command(directory)).returncode
            if refused != exhibit.refusal_exit:
                problems.append(
                    f"exhibit {exhibit.number}: claims the wrong verifier refuses it with "
                    f"{exhibit.refusal_exit}, and it returned {refused}"
                )

    # The verifiers were just run inside the window, which compiles the modules
    # they import unless told not to, so this is checked after the runs rather
    # than only at the copy.
    compiled = sorted(
        str(path.relative_to(out))
        for path in out.rglob("*")
        if path.name == "__pycache__" or path.suffix in (".pyc", ".pyo")
    )
    if compiled:
        problems.append(f"the window would ship compiled bytecode: {', '.join(compiled[:4])}")

    for relative, reasons in _not_for_publication(out).items():
        problems.append(f"{relative} must not be published: {'; '.join(reasons)}")

    if problems:
        raise SystemExit(
            "REFUSED: the shop window would publish a claim that does not hold:\n  "
            + "\n  ".join(problems)
        )
    return exhibits


def _release_tag() -> str:
    tags = subprocess.run(
        ["git", "tag", "--list", "--sort=-v:refname"], cwd=ROOT, capture_output=True, text=True
    ).stdout.split()
    if not tags:
        raise SystemExit("REFUSED: the pin must be a release tag and this clone has none")
    return tags[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--check",
        action="store_true",
        help="build into a temporary directory and discard it; the refusal is the point",
    )
    parser.add_argument("--tag", default=None, help="defaults to the highest release tag")
    args = parser.parse_args()
    if (args.out is None) == (not args.check):
        parser.error("give --out or --check, and not both")

    tag = args.tag or _release_tag()
    if args.check:
        with tempfile.TemporaryDirectory() as scratch:
            generate(Path(scratch) / "window", tag)
        print(f"The shop window builds from {tag} and every documented exit code reproduces.")
        return 0
    exhibits = generate(args.out, tag)
    print(f"Generated the shop window at {args.out}, pinned at {tag}")
    for e in exhibits:
        print(f"  {e.number}. {e.name:38} {e.document_exit}/{e.receipt_exit}  {e.run_id}")
    # Printed because a person has to paste it: GitHub holds a repository's
    # About line in its settings, where no rebuild reaches it.
    print("\nSet the window's About line in GitHub's settings to exactly this:\n")
    print(f"  {_about(exhibits)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
