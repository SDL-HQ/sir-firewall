#!/usr/bin/env python3
"""
Fail closed when a release checklist item is unmet or its evidence does not resolve.

A release is only finished when its acceptance conditions are met, and a
condition is only met when something other than a sentence says so. This project
has repeatedly answered a finding with a documentation change that was correct
as a mitigation and mistaken for the fix. The guard against that is mechanical:
an item cannot be ticked by a document.

Evidence therefore has exactly three permitted forms, and each one is resolved
rather than taken on trust:

  test      "tests/test_x.py::test_name" -- the file must exist and define it
  artefact  a repository path that must exist
  command   an executable and its arguments, run without a shell, which must
            reach its stated exit code (--run-commands)

There is deliberately no prose or document evidence type. A paragraph explaining
why something is acceptable is a scope statement, which belongs in the
documentation, not in this file.

This check runs on the merge path to main. Pushes to the release branch do not
run it, so the checklist can sit incomplete for the whole release and only has
to hold at the point the work is published.

Exit codes:
  0  every item is met and every piece of evidence resolves
  1  an item is open, or an item is met with no evidence
  2  evidence does not resolve: a test, artefact or command check failed
  3  the checklist could not be read, or is malformed
"""

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

PERMITTED_TYPES = ("test", "command", "artefact")
DEFAULT_CHECKLIST = "release-checklist.json"


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: checklist not found: {path}", file=sys.stderr)
        raise SystemExit(3)
    except json.JSONDecodeError as exc:
        print(f"ERROR: checklist is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(3)
    if not isinstance(data.get("items"), list) or not data["items"]:
        print("ERROR: checklist carries no items", file=sys.stderr)
        raise SystemExit(3)
    return data


def _resolve_test(ref: str, root: Path) -> str | None:
    if "::" not in ref:
        return "test reference must be path::test_name"
    rel, name = ref.split("::", 1)
    path = root / rel
    if not path.is_file():
        return f"test file not found: {rel}"
    if f"def {name}(" not in path.read_text(encoding="utf-8"):
        return f"test not defined in {rel}: {name}"
    return None


def _resolve_artefact(ref: str, root: Path) -> str | None:
    target = root / ref
    if not target.exists():
        return f"artefact not found: {ref}"
    return None


def _resolve_command(entry: dict, root: Path, run: bool) -> str | None:
    ref = entry.get("ref")
    if not ref:
        return "command evidence carries no ref"
    if "expect_exit" not in entry:
        return "command evidence must state expect_exit"
    if not run:
        return None
    # Split rather than hand the string to a shell. This file gates the merge, so
    # anyone able to open a pull request can edit it, and the gate runs command
    # evidence in CI. A command here is one executable and its arguments; a step
    # that needs a pipe or a conditional belongs in a script the repository owns.
    try:
        argv = shlex.split(ref)
    except ValueError as exc:
        return f"command could not be parsed: {ref} ({exc})"
    if not argv:
        return f"command is empty: {ref!r}"
    try:
        result = subprocess.run(argv, cwd=root, capture_output=True, text=True)
    except OSError as exc:
        return f"command could not be run: {ref} ({exc})"
    expected = int(entry["expect_exit"])
    if result.returncode != expected:
        return (
            f"command exited {result.returncode}, expected {expected}: {ref}\n"
            f"      {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ''}"
        )
    return None


def _check_item(item: dict, root: Path, run_commands: bool) -> tuple[int, list[str]]:
    """Return (worst_exit, problems) for one checklist item."""
    problems: list[str] = []
    ident = f"item {item.get('id')} ({item.get('name', 'unnamed')})"

    if item.get("status") != "met":
        return 1, [f"{ident}: status is {item.get('status')!r}, not 'met'"]

    evidence = item.get("evidence") or []
    if not evidence:
        return 1, [f"{ident}: marked met with no evidence"]

    worst = 0
    for entry in evidence:
        kind = entry.get("type")
        if kind not in PERMITTED_TYPES:
            problems.append(
                f"{ident}: evidence type {kind!r} is not permitted "
                f"(allowed: {', '.join(PERMITTED_TYPES)})"
            )
            worst = max(worst, 2)
            continue
        if kind == "test":
            failure = _resolve_test(entry.get("ref", ""), root)
        elif kind == "artefact":
            failure = _resolve_artefact(entry.get("ref", ""), root)
        else:
            failure = _resolve_command(entry, root, run_commands)
        if failure:
            problems.append(f"{ident}: {failure}")
            worst = max(worst, 2)
    return worst, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--checklist", default=DEFAULT_CHECKLIST)
    parser.add_argument("--root", default=".", help="repository root the evidence resolves against")
    parser.add_argument(
        "--run-commands",
        action="store_true",
        help="execute command evidence and require its stated exit code",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="report status without failing, for use on the release branch",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    data = _load(Path(args.checklist))
    items = data["items"]

    worst = 0
    problems: list[str] = []
    met = 0
    resolved: dict[Any, int] = {}
    for item in items:
        status, found = _check_item(item, root, args.run_commands)
        resolved[item.get("id")] = status
        if status == 0:
            met += 1
        worst = max(worst, status)
        problems.extend(found)

    target = data.get("target_version", "unknown")
    print(f"Release checklist for {target}: {met} of {len(items)} items met.")
    for item in items:
        # The mark reflects whether the evidence resolved, not only what the
        # status field claims. Reading the field alone printed [x] beside an
        # item whose evidence did not resolve, so the checkbox list and the
        # count above it disagreed and nothing said which item was at fault.
        # A tick that can be wrong is the thing this file exists to prevent.
        state = resolved.get(item.get("id"))
        if state == 0:
            mark = "x"
        elif item.get("status") == "met":
            mark = "!"
        else:
            mark = " "
        print(f"  [{mark}] {item.get('id')}  {item.get('name')}")
    if any(
        resolved.get(item.get("id")) != 0 and item.get("status") == "met"
        for item in items
    ):
        print("  [!] marked met, but its evidence does not resolve; see below.")

    if problems:
        print("", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)

    if args.summary_only:
        return 0
    if worst:
        print(
            f"\nERROR: the checklist for {target} does not hold, so this cannot merge.",
            file=sys.stderr,
        )
    return worst


if __name__ == "__main__":
    sys.exit(main())
