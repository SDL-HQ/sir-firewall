"""Every third-party package the code or the tests import is declared, and
every name declared is imported by something.

``hypothesis`` was in ``requirements.txt`` and not in ``pyproject.toml``. The
README documents ``pip install -e .`` in four places and ``requirements.txt`` in
none, and only one of the five workflows installs that file. So CI was green on
a dependency a reader is never told to install, and a stranger following the
README got a collection error on ``tests/test_gate_outcome_invariance.py``
before a single test ran.

This derives the import set from the source rather than listing it, so the next
undeclared dependency fails here instead of failing for a stranger. Imports are
read statically, so an import inside a function or guarded by a try block is
found too, which is deliberate: an optional dependency should be declared as an
extra, not left out.

Two gaps in the original version, both found on 16 October 2026 and both fixed
here.

``tools/`` was not scanned. ``tools/export_run_archive.py`` imports ``boto3``
behind ``--s3-bucket``, guarded, raising a SystemExit when it is absent, and
``boto3`` was declared nowhere. A file that tells the reader to install
something the project never declares is the same defect this test was written
for, one directory over. ``tools/`` is scanned now and ``boto3`` is the ``s3``
extra.

Nothing checked the other direction. ``pydantic``, ``requests`` and ``pandas``
were declared and imported by none of the 143 tracked Python files; ``pandas``
appeared in the repository only in the forbidden-import list of
``tests/test_no_model_in_the_decision_path.py``, so it was declared as a
dependency and banned from the decision path in the same tree. ``openai`` was
declared under the ``live`` extra and imported nowhere; the openai provider
path reaches it through litellm, which declares it itself. An unused
declaration is not inert: it is a package a deployer installs, scans and
patches on our say-so, and it invites a reader to believe the code uses it.

Mutations measured on 16 October 2026, each run against the full file:

- re-add ``"pandas"`` to ``dependencies``:
  ``test_every_declared_dependency_is_imported`` fails (1 failed).
- drop ``"boto3"`` from the ``s3`` extra:
  ``test_every_imported_third_party_package_is_declared`` fails (1 failed).
- remove ``tools/`` from the scanned sources: ``boto3`` becomes declared and
  imported by nothing, so ``test_every_declared_dependency_is_imported`` and
  ``test_the_scan_covers_the_four_source_roots`` fail (2 failed). The forward
  test alone would not have caught this, which is why both directions are
  held.
- make ``_imported()`` return ``{}``:
  ``test_every_declared_dependency_is_imported`` and
  ``test_the_import_scan_finds_something`` fail (2 failed).
- empty ``IMPORT_TO_DISTRIBUTION``: the declared ``PyYAML`` no longer resolves
  to the imported module ``yaml``, so both directions and the planted-case
  test fail (3 failed).
- restore the loose name parser ``_declared`` used until 16 October 2026:
  ``test_every_declared_dependency_is_imported`` and
  ``test_the_parser_reads_names_and_not_the_text_between_them`` fail
  (2 failed).

A first draft carried a reverse of ``IMPORT_TO_DISTRIBUTION`` in the final
condition of ``_unimported``. Mutating it changed nothing: ``present`` already
holds both spellings of every imported module, so the reverse lookup could
never alter the result. It is deleted rather than recorded as an undetected
mutation, because the mutation was undetectable for the reason that the code
was dead.
"""

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Repository-local modules, importable by path or as the installed package
# rather than from an index.
LOCAL_MODULES = {
    "sir_firewall",
    "itgl",
    "key_registry",
    "conftest",
    "red_team_suite",
    "rule_coverage_report",
    "generate_certificate",
    "local_audit",
    "verify_certificate",
    "verify_baseline_record",
    "verify_policy",
    "pair_validation",
    "certificate_results",
    "document_signing",
    "publication_rules",
    "tools",
}

# Where a repository-local module can live. Used only by the test that holds
# the list above to files that exist.
LOCAL_MODULE_DIRECTORIES = ("tools", "src/sir_firewall", "tests", "")

# Import name to distribution name, where they differ.
IMPORT_TO_DISTRIBUTION = {"yaml": "PyYAML"}


def _requirement_names(block: str) -> set:
    """The distribution name of each quoted requirement in a TOML array.

    The original read every run of characters following a quote, so the text
    between two entries, and a comment inside the array, were returned as
    declared names. That only ever loosened the forward test, so it went
    unnoticed until the reverse test reported `,\\n  # Published indexes...`
    as an unimported dependency on 16 October 2026.
    """
    names = set()
    for quoted in re.findall(r'"([^"]*)"', block):
        matched = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", quoted)
        if matched:
            names.add(matched.group(1).lower())
    return names


def _declared() -> set:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    required = _requirement_names(text.split("dependencies = [", 1)[1].split("]", 1)[0])
    extras = text.split("[project.optional-dependencies]", 1)
    if len(extras) > 1:
        for value in re.findall(r"=\s*\[([^\]]*)\]", extras[1].split("\n[", 1)[0]):
            required |= _requirement_names(value)
    return required


def _sources() -> list:
    paths = sorted((ROOT / "tests").glob("*.py"))
    paths += sorted((ROOT / "src/sir_firewall").rglob("*.py"))
    paths += sorted((ROOT / "tools").glob("*.py"))
    paths += [ROOT / "red_team_suite.py"]
    return paths


def _imported() -> dict:
    found = {}
    for path in _sources():
        if not path.is_file():
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if not name or name in sys.stdlib_module_names:
                    continue
                if name in LOCAL_MODULES:
                    continue
                found.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    return found


def _undeclared(declared: set, imported: dict) -> dict:
    """Imported by the tree, named by neither the dependencies nor an extra."""
    return {
        name: sorted(files)
        for name, files in imported.items()
        if IMPORT_TO_DISTRIBUTION.get(name, name).lower() not in declared
    }


def _unimported(declared: set, imported: dict) -> set:
    """Named by the dependencies or an extra, imported by nothing in the tree."""
    present = set()
    for name in imported:
        present.add(name.lower())
        present.add(IMPORT_TO_DISTRIBUTION.get(name, name).lower())
    return {name for name in declared if name not in present}


def test_every_module_excused_as_local_is_really_in_this_repository():
    """Guard the excuse list. A stale name here silently declares nothing.

    `LOCAL_MODULES` removes a name from the comparison entirely, so an entry
    for a module that has been renamed or deleted goes on excusing anything
    imported under that name, including a real package from an index. Nothing
    held the list until `publication_rules` was added to it on 17 October 2026,
    which is when it became obvious that adding to it costs nothing and is
    never noticed.

    Mutation, 17 October 2026: add `requests` to `LOCAL_MODULES`, which is a
    real distribution and not a file here. This test fails (1 failed) and
    `test_every_declared_dependency_is_imported` does not, because that one
    reads the same excused list.
    """
    missing = []
    for name in sorted(LOCAL_MODULES):
        if any(
            (ROOT / directory / f"{name}.py").is_file()
            for directory in LOCAL_MODULE_DIRECTORIES
        ):
            continue
        if (ROOT / "src" / name).is_dir() or (ROOT / name).is_dir():
            continue
        missing.append(name)

    assert not missing, (
        "these are excused from the dependency comparison as repository-local "
        f"and are not in the repository: {missing}"
    )


def test_every_imported_third_party_package_is_declared():
    undeclared = _undeclared(_declared(), _imported())

    assert not undeclared, (
        "these packages are imported but not declared in pyproject.toml; add them "
        f"to dependencies, or to an extra if they are optional: {undeclared}"
    )


def test_every_declared_dependency_is_imported():
    unimported = sorted(_unimported(_declared(), _imported()))

    assert not unimported, (
        "these names are declared in pyproject.toml but imported by nothing under "
        "tests/, src/, tools/ or red_team_suite.py; remove them, or point the "
        f"scan at the file that needs them: {unimported}"
    )


def test_the_import_scan_finds_something():
    """Guard the guard. A refactor must not make this file vacuous."""
    imported = _imported()

    assert "cryptography" in imported
    assert "hypothesis" in imported
    assert len(imported) >= 4, sorted(imported)


def test_the_scan_covers_the_four_source_roots():
    """tools/ was missing for the life of this file. Hold all four."""
    scanned = {str(path.relative_to(ROOT)) for path in _sources() if path.is_file()}
    roots = {path.split("/")[0] for path in scanned}

    assert {"tests", "src", "tools"} <= roots, sorted(roots)
    assert "red_team_suite.py" in scanned


def test_both_directions_report_a_planted_discrepancy():
    """Exercise each helper against a case the real tree does not contain."""
    imported = {"cryptography": {"src/sir_firewall/core.py"}, "yaml": {"tests/a.py"}}

    assert _undeclared({"cryptography", "pyyaml"}, imported) == {}
    assert _unimported({"cryptography", "pyyaml"}, imported) == set()

    assert _undeclared({"cryptography"}, imported) == {"yaml": ["tests/a.py"]}
    assert _unimported({"cryptography", "pyyaml", "pandas"}, imported) == {"pandas"}


def test_the_parser_reads_names_and_not_the_text_between_them():
    """The defect the reverse test exposed: comments parsed as dependencies."""
    block = '\n  "cryptography",\n  # a comment, with a comma\n  "PyYAML>=6.0"\n'

    assert _requirement_names(block) == {"cryptography", "pyyaml"}
