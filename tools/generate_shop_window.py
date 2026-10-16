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
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "docs" / "archive-figures.json"
PERIMETER = ROOT / "docs" / "evidence-perimeter.v6.md"
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
      - uses: actions/checkout@v4
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
VERIFIER_FILES = (
    "verify_certificate.py",
    "verify_baseline_record.py",
    "verify_archive_receipt.py",
    "key_registry.py",
    "itgl.py",
    "document_signing.py",
)


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


def _exit_meanings(figures: dict) -> dict:
    """What the verifier prints, taken from the published figures tables."""
    return {
        "certificate": {row["exit"]: row["meaning"] for row in figures["certificate_rows"]},
        "receipt": {row["exit"]: row["meaning"] for row in figures["receipt_rows"]},
    }


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
        f"| {e.number} | {e.name} | `{e.document_exit}` | `{e.receipt_exit}` | {e.teaches} |"
        for e in exhibits
    )
    # Counted, not asserted. An earlier draft said "four of these are about our
    # limits and three say we got something wrong", and neither number survived
    # being checked against the table above it.
    nonzero = sum(1 for e in exhibits if e.document_exit or e.receipt_exit)
    return f"""# SIR, in seven commands

SIR is a deterministic pre-inference gate. It reads a request before a model
does, decides `PASS` or `BLOCKED` by rules alone with no model in the decision
path, and writes a signed record of what it saw and what it decided. The record
is the point: it is designed to be checked by someone who does not trust us.

**Read [LIMITS.md](LIMITS.md) second.** It says what SIR does not do, in the
project's own words, and most of what is below is a limit made concrete.

This repository is generated from the archive of record, pinned at `{tag}`.
It holds seven real published archives, chosen because running our own
verifiers against them produces different answers.

**{nonzero} of the seven do not come back clean.** One has a signature that
genuinely does not verify. One is missing a file its own manifest lists. The
rest are boundaries and absences we have disclosed rather than tidied: an
archive too old for the current binding scheme, one that ships no ledger, and
one that predates the receipt format.

The seventh comes back clean twice over and is still worth running: it is a
baseline record, not a certificate, and pointing the certificate verifier at
it makes the verifier refuse the document rather than say something wrong
about it.

| # | Exhibit | Document exit | Receipt exit | What it shows |
|---|---|---|---|---|
{rows}

[VERIFY.md](VERIFY.md) has the exact command for each, and explains why each
one names its ledger on the command line.

The archive of record is at [{VAULT}]({VAULT}). It holds
{figures['total']} runs and {figures['certificates_total']} certificates.

Nothing here is a sample chosen for how it looks. Each exhibit is selected
from a category by a tool in the main repository, and a test there refuses any
category with only one member, so an exhibit is always an example of a class
rather than a fact about one run.

## This repository is generated

Every file here except the workflow that rebuilds it is written by
`tools/generate_shop_window.py` in the archive of record, from the latest
release tag. Nothing is edited in place. An edit made here would be discarded
by the next rebuild rather than read, so issues and changes belong in the
archive of record. `GENERATED` records the tag, the commit it was built from,
and when.

The build is not a copy. It runs every command on this page inside the
directory it has just written, and stops without publishing if any exit code
differs from the one the page gives for it.
"""


def _limits() -> str:
    claims_lead, non_claims = _perimeter_section("Explicit non-claims")
    support_lead, unsupported = _perimeter_section("What current evidence does not support")
    return f"""# What SIR does not do

Lifted verbatim from the evidence perimeter in the archive of record, lead-in
sentences included. It is not rewritten for this page, because a limit
restated for a front door is a limit softened for a front door.

## Explicit non-claims

{claims_lead}

{chr(10).join(non_claims)}

## What current evidence does not support

{support_lead}

{chr(10).join(unsupported)}

## And the one that applies to this repository

The exhibits show that our verifiers behave as we say they do on archives we
published. They do not show that the gate is adequate, that a passing
certificate means a safe run, or that the rule set covers any attack you care
about. `AUDIT PASSED` is a statement about one run's counters and its own
checks, and nothing more.
"""


def _verify_doc(exhibits, meanings) -> str:
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
        blocks.append(
            f"""### {e.number}. {e.name}

{e.teaches}

```
python3 {command}
python3 tools/verify_archive_receipt.py exhibits/{e.run_id}
```

Document verifier exits `{e.document_exit}`. Receipt verifier exits
`{e.receipt_exit}`.{extra}"""
        )

    certificate = "\n".join(
        f"| `{code}` | {meaning} |" for code, meaning in sorted(
            (c, m) for c, m in meanings["certificate"].items() if c is not None
        )
    )
    receipt = "\n".join(
        f"| `{code}` | {meaning} |" for code, meaning in sorted(meanings["receipt"].items())
    )

    return f"""# Verifying the exhibits

Every command below runs offline against a file in this repository. Nothing
calls a model provider, and nothing needs a credential.

## Why each command names its ledger

A certificate is bound to the ledger of the run it signs, so verifying one
means checking it against that ledger. The verifier can usually find the
ledger by itself, from the run id inside the signed payload.

**Older certificates carry no run id.** They predate the field. For those the
verifier has nothing to key on, finds no ledger however complete the directory
is, and reports that the binding was not checked. That is a true answer and a
confusing one, so every command here names the ledger explicitly, and the two
archives that ship no ledger at all pass `--no-ledger` instead.

We could have hidden this in a one-word wrapper. We have not, because the
point of this repository is that you can see exactly what is being checked.

## The commands

{chr(10).join(blocks)}

## How to read the exit codes

Certificate verifier:

| Exit | Meaning |
|---|---|
{certificate}

Archive receipt verifier:

| Exit | Meaning |
|---|---|
{receipt}

These meanings are generated from the archive of record's own published
figures, not written for this page.
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
        # -B above, so running the verifiers leaves no bytecode in the tree
        # they are run in. PYTHONDONTWRITEBYTECODE was set here too until
        # measuring showed each was sufficient alone, which made neither of
        # them detectable.
        env=dict(os.environ, PYTHONPATH=str(window / "src")),
    )


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
    # sir_firewall is imported by one optional branch of the certificate
    # verifier, for the canonical-path fallback. It is copied so that branch
    # behaves here as it does in the vault rather than failing to import.
    shutil.copytree(ROOT / "src", out / "src", ignore=_NO_BYTECODE)
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
    (out / "VERIFY.md").write_text(_verify_doc(exhibits, _exit_meanings(figures)), encoding="utf-8")

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()
    (out / "GENERATED").write_text(
        f"source {VAULT}\ntag {tag}\ncommit {commit}\n"
        f"generated {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"archives {figures['total']}\ncertificates {figures['certificates_total']}\n",
        encoding="utf-8",
    )

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
