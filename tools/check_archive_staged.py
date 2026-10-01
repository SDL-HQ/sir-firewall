#!/usr/bin/env python3
"""
Fail closed when a signed run manifest names a file that will not reach the commit.

A run archive is only published evidence if git carries every file its manifest
names. `tools/publish_run.py` hashes whatever it finds in the run directory into
`manifest.json` and signs that manifest through `archive_receipt.json`. If a
.gitignore rule or a missing `git add` then drops one of those files, the
archive is published incomplete and `tools/verify_archive_receipt.py` fails for
every third party who tries to verify it, while CI stays green.

This check runs after `git add` and before `git commit`. By default it inspects
only the run archives this commit is publishing, found from the git index, so
archives published by earlier runs cannot block a later one.

Exit codes:
  0  every manifest file in every staged run archive is present and staged
  1  at least one manifest file is absent from disk or from the git index
  2  a manifest could not be read
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_TREES = ("proofs/runs", "docs/runs")
_RUN_PATH = re.compile(r"^(?:proofs|docs)/runs/([^/]+)/")


def _git(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def _staged(path: str) -> bool:
    return _git(["ls-files", "--cached", "--error-unmatch", "--", path]).returncode == 0


def _staged_run_ids() -> list[str]:
    result = _git(["diff", "--cached", "--name-only"])
    if result.returncode != 0:
        print(f"ERROR: unable to read the git index: {result.stderr.strip()}", file=sys.stderr)
        raise SystemExit(2)
    found: list[str] = []
    for line in result.stdout.splitlines():
        match = _RUN_PATH.match(line.strip())
        if match and match.group(1) not in found and match.group(1) != "pairs":
            found.append(match.group(1))
    return found


def _check(run_id: str, trees: tuple[str, ...]) -> int:
    manifest_path = Path(trees[0]) / run_id / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read run manifest at {manifest_path}: {exc}", file=sys.stderr)
        return 2

    named = [entry.get("path", "") for entry in manifest.get("files", [])]
    if not named:
        print(f"ERROR: run manifest at {manifest_path} names no files", file=sys.stderr)
        return 2

    absent_on_disk: list[str] = []
    not_staged: list[str] = []
    for tree in trees:
        if not Path(tree, run_id).is_dir():
            continue
        for relative in named:
            candidate = f"{tree}/{run_id}/{relative}"
            if not Path(candidate).is_file():
                absent_on_disk.append(candidate)
            elif not _staged(candidate):
                not_staged.append(candidate)

    if absent_on_disk or not_staged:
        print(
            f"ERROR: the signed manifest for {run_id} names files that will not be published.",
            file=sys.stderr,
        )
        for candidate in absent_on_disk:
            print(f"  absent from disk: {candidate}", file=sys.stderr)
        for candidate in not_staged:
            print(f"  not staged in git: {candidate}", file=sys.stderr)
        return 1

    print(f"OK: {run_id}: all {len(named)} manifest files present and staged.")
    return 0


def _verify_receipt(run_id: str, tree: str) -> int:
    archive = f"{tree}/{run_id}"
    result = subprocess.run(
        [
            sys.executable,
            "tools/verify_archive_receipt.py",
            archive,
            "--require-registry",
        ],
        capture_output=True,
        text=True,
    )
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        print(
            f"ERROR: the archive receipt for {run_id} does not verify.",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify that every file named by a run manifest is staged for commit."
    )
    parser.add_argument(
        "run_id",
        nargs="*",
        help="Run archive identifiers to check. Default: every run archive staged in the git index.",
    )
    parser.add_argument(
        "--tree",
        action="append",
        default=None,
        help=f"Published tree to check. Repeatable. Default: {', '.join(DEFAULT_TREES)}",
    )
    parser.add_argument(
        "--verify-receipt",
        action="store_true",
        help="Also run tools/verify_archive_receipt.py against each checked archive.",
    )
    args = parser.parse_args()

    trees = tuple(args.tree) if args.tree else DEFAULT_TREES
    run_ids = args.run_id or _staged_run_ids()

    if not run_ids:
        print("OK: no run archive is staged in this commit; nothing to check.")
        return 0

    worst = 0
    staging_failed = False
    for run_id in run_ids:
        staged_status = _check(run_id, trees)
        if staged_status:
            staging_failed = True
        worst = max(worst, staged_status)
        if args.verify_receipt:
            worst = max(worst, _verify_receipt(run_id, trees[0]))

    if staging_failed:
        print(
            "\nThe archive would be published incomplete and "
            "tools/verify_archive_receipt.py would fail for every third party.\n"
            "A .gitignore rule or a missing git add is dropping published evidence.",
            file=sys.stderr,
        )
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
