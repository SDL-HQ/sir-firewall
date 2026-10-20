#!/usr/bin/env python3
"""Refuse to carry what must never leave a repository.

A repository being private is not the same as it being controlled. Private
repositories get read by new collaborators, cloned onto laptops, made public
by accident and handed over during diligence. The rules that decide what must
not be committed already exist and are already tested, next to this file in
`publication_rules.py`.

This runner exists so that another repository can apply those rules without
copying them: it checks this one out at a pin, imports the module, and calls
it. `tests/test_no_working_documents_in_the_public_repository.py` applies them
to this repository and does not use this runner.

**This script does not reimplement them, and nothing here may.** A second copy
of an identity is the defect this project records as its recurring one, and a
second copy of *these* rules would be the half nobody watches.

Which rule families apply is the caller's decision, passed as flags, because
it differs by repository: a repository whose purpose is to hold working
documents should not be refused for holding them, while one that publishes
should be refused for everything. The policy therefore lives in each caller's
workflow, where it is visible, rather than inside this file.

Exit 0 clean, 1 offences found, 2 the check could not run. 2 is not 0: a check
that could not run is not a check that passed.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path


def load_rules(module_path: Path):
    """Load publication_rules from a pinned checkout, or fail closed."""
    if not module_path.is_file():
        print(f"ERROR: rules module not found at {module_path}", file=sys.stderr)
        print("The check cannot run. This is exit 2, not a pass.", file=sys.stderr)
        raise SystemExit(2)
    spec = importlib.util.spec_from_file_location("publication_rules", module_path)
    if spec is None or spec.loader is None:
        print(f"ERROR: {module_path} is not importable", file=sys.stderr)
        raise SystemExit(2)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for required in ("offences",):
        if not hasattr(module, required):
            print(f"ERROR: rules module has no {required}()", file=sys.stderr)
            raise SystemExit(2)
    return module


def tracked_files(root: Path) -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode("utf-8")
    # Untracked-but-not-ignored files too. Scanning only tracked files means a
    # new file is invisible until the commit that adds it has already happened,
    # which is the wrong ordering for a guard.
    out += subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root
    ).decode("utf-8")
    return sorted(filter(None, set(out.split("\0"))))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, required=True,
                        help="path to publication_rules.py from a pinned checkout")
    parser.add_argument("--root", type=Path, default=Path("."),
                        help="repository root to scan")
    parser.add_argument("--allow-working-documents", action="store_true",
                        help="this repository's purpose is to hold them")
    parser.add_argument("--allow-patent-analysis", action="store_true",
                        help="this repository is the designated home for it")
    parser.add_argument("--exhibit-prefix", action="append", default=[],
                        metavar="PREFIX",
                        help="path prefix holding exhibits: scanned for "
                             "secrets, not for writing. Repeatable.")
    parser.add_argument("--known", action="append", default=[], metavar="PATH=PHRASE",
                        help="one judged occurrence: this exact phrase, in this "
                             "exact file, has been read and is not what the rule "
                             "is for. Deliberately not a file exemption. The same "
                             "file carrying a different phrase still fails, and "
                             "the same phrase in another file still fails. "
                             "Repeatable; every entry needs a comment in the "
                             "workflow saying what was read.")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    known: dict[str, tuple[str, ...]] = {}
    for entry in args.known:
        if "=" not in entry:
            print(f"ERROR: --known needs PATH=PHRASE, got {entry!r}", file=sys.stderr)
            return 2
        path_part, phrase = entry.split("=", 1)
        known[path_part] = known.get(path_part, ()) + (phrase,)
    root = args.root.resolve()
    paths = tracked_files(root)

    # Absent input is never a pass.
    if not paths:
        print("ERROR: no files to scan. The check cannot have run.", file=sys.stderr)
        return 2

    findings: list[tuple[str, list[str]]] = []
    for relative in paths:
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # A binary or unreadable file still has a path, and a path is a
            # claim. publication_rules handles text=None by applying the path
            # rule alone.
            text = None
        # An exhibit is evidence, and evidence may contain any words at all.
        # Secrets are still refused in one: an account identifier is never
        # part of a captured prompt, it arrives in a provider error body.
        exhibit = relative.startswith(tuple(args.exhibit_prefix)) if args.exhibit_prefix else False
        found = rules.offences(
            relative, text,
            working_documents=not args.allow_working_documents and not exhibit,
            patent=not args.allow_patent_analysis and not exhibit,
        )
        if found and known:
            found = [reason for reason in found
                     if not any(phrase in reason for phrase in known.get(relative, ()))]
        if found:
            findings.append((relative, found))

    families = []
    if not args.allow_working_documents:
        families.append("working documents")
    if not args.allow_patent_analysis:
        families.append("patent analysis")
    families += ["private key material", "credentials", "account identifiers"]
    exhibits = sum(1 for p in paths
                   if args.exhibit_prefix and p.startswith(tuple(args.exhibit_prefix)))
    print(f"Scanned {len(paths)} files against: {', '.join(families)}.")
    if exhibits:
        print(f"  {exhibits} of them are exhibits, scanned for secrets only.")

    if known:
        print(f"  {sum(len(v) for v in known.values())} judged occurrence(s) "
              f"allowed by name, in {len(known)} file(s).")

    if not findings:
        print("Clean.")
        return 0

    print(f"\nREFUSED: {len(findings)} file(s) carry what must not be committed "
          f"to this repository.\n", file=sys.stderr)
    for relative, found in findings:
        print(f"  {relative}", file=sys.stderr)
        for reason in found:
            print(f"      {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
