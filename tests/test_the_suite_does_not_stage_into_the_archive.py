"""No test writes into the repository's published archive trees.

On 15 October 2026 two synthetic baseline archives were found sitting in
`proofs/runs`. `test_the_review_bundle_restates_a_record_as_a_record` copied a
fixture's archive into the real tree because `tools/export_review_bundle.py`
could only read `proofs/runs/<run_id>` from its own repository, and removed it
in a `finally`. The suite was interrupted, so the `finally` never ran.

Why that matters more than the mess: the audit workflow's `audit-and-sign` job
runs pytest and `git add proofs/runs/` in the same job, so a stray archive is
one interruption away from being committed into the published evidence. Nothing
published has ever carried one, confirmed by scanning all 2,562 tracked archive
JSON files for a pytest temp path, and the check that stopped it was incidental:
`tools/archive_verification_report.py` refuses to generate figures when
proofs/runs and docs/runs hold different runs, so publication fails at the
figures step. A test should not depend on an incidental guard to stay out of the
archive.

The exporter took a `--runs-root` flag and the test now exports from the tree
the fixture built. This holds the pattern closed.

Scope, stated because a test that implies more than it checks is worse than a
narrow one: this checks the destination argument of the shutil copy and move
helpers, and the target of `shutil.rmtree`. A test could still write into the
repository by other means. What it catches is the shape that happened, which is
a test staging a tree inside the repository and deleting it afterwards.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent

# Where a destination inside the repository would be published from.
ARCHIVE_TREES = ("proofs/runs", "docs/runs", "proofs", "docs")

# shutil helpers, and which positional argument is the one written to.
DESTINATION_ARG = {"copytree": 1, "copy": 1, "copy2": 1, "copyfile": 1, "move": 1}
REMOVAL_ARG = {"rmtree": 0}


def _root_derived_names(tree: ast.AST) -> set[str]:
    """Local names assigned from a path built on the repository root.

    The pattern that happened assigned `staged = ROOT / "proofs/runs" / run_id`
    and then passed the bare name to copytree and rmtree, so checking the call
    argument alone misses it: the argument is a Name. Assignments are resolved
    first, over the whole module and without regard to scope, which can only
    make this stricter.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not _mentions_repository_root(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _mentions_repository_root(node: ast.AST, *, derived: set[str] = frozenset()) -> bool:
    """Whether this path expression is built from the repository root.

    Every test file names it `ROOT`, so that is the signal, together with any
    local name assigned from it. A test that reached the repository some other
    way is not caught here, and the module docstring says so.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and (child.id == "ROOT" or child.id in derived):
            return True
    return False


def _shutil_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if not (isinstance(owner, ast.Name) and owner.id == "shutil"):
            continue
        yield node.func.attr, node


def _offences(source: str) -> list[str]:
    """Every shutil destination or removal target under the repository root."""
    tree = ast.parse(source)
    derived = _root_derived_names(tree)
    found: list[str] = []
    for name, call in _shutil_calls(tree):
        for table, label in ((DESTINATION_ARG, "destination"), (REMOVAL_ARG, "target")):
            index = table.get(name)
            if index is None or len(call.args) <= index:
                continue
            if _mentions_repository_root(call.args[index], derived=derived):
                found.append(f"line {call.lineno}: shutil.{name} {label} is under ROOT")
    return found


@pytest.mark.parametrize(
    "path", sorted(TESTS.glob("test_*.py")), ids=lambda p: p.name
)
def test_no_test_copies_or_removes_inside_the_repository(path):
    offences = _offences(path.read_text(encoding="utf-8"))

    assert not offences, (
        f"{path.name} writes into or removes inside the repository: {offences}. "
        "Build the tree under tmp_path and point the tool at it; "
        "tools/export_review_bundle.py takes --runs-root for exactly this."
    )


def test_this_guard_sees_the_shape_it_exists_for():
    """Guard the guard, on the source that actually caused this.

    A first version of this file compared the call argument against `ROOT` and
    would have passed on the real code, because the argument was the name
    `staged` rather than an expression mentioning ROOT.
    """
    offences = _offences(
        "import shutil\n"
        "staged = ROOT / 'proofs/runs' / run_id\n"
        "shutil.copytree(published / run_id, staged)\n"
        "shutil.rmtree(staged)\n"
    )

    assert len(offences) == 2, offences
    assert any("copytree destination" in line for line in offences), offences
    assert any("rmtree target" in line for line in offences), offences


def test_the_guard_does_not_flag_reading_out_of_the_repository():
    """A ROOT path may be a copy source. Several tests legitimately do that."""
    assert _offences(
        "import shutil\n"
        "shutil.copytree(ROOT / 'docs/runs' / run_id, destination)\n"
    ) == []
