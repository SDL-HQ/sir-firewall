"""Every third-party package the code or the tests import is declared.

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
    "tools",
}

# Import name to distribution name, where they differ.
IMPORT_TO_DISTRIBUTION = {"yaml": "PyYAML"}


def _declared() -> set:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    required = set(re.findall(r'"([^"<>=!\[\]]+)', block))
    extras = text.split("[project.optional-dependencies]", 1)
    if len(extras) > 1:
        for value in re.findall(r"=\s*\[([^\]]*)\]", extras[1].split("\n[", 1)[0]):
            required |= set(re.findall(r'"([^"<>=!\[\]]+)', value))
    return {name.strip().lower() for name in required}


def _imported() -> dict:
    found = {}
    sources = sorted((ROOT / "tests").glob("*.py"))
    sources += sorted((ROOT / "src/sir_firewall").rglob("*.py"))
    sources += [ROOT / "red_team_suite.py"]
    for path in sources:
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


def test_every_imported_third_party_package_is_declared():
    declared = _declared()
    undeclared = {
        name: sorted(files)
        for name, files in _imported().items()
        if IMPORT_TO_DISTRIBUTION.get(name, name).lower() not in declared
    }

    assert not undeclared, (
        "these packages are imported but not declared in pyproject.toml; add them "
        f"to dependencies, or to an extra if they are optional: {undeclared}"
    )


def test_the_import_scan_finds_something():
    """Guard the guard. A refactor must not make this file vacuous."""
    imported = _imported()

    assert "cryptography" in imported
    assert "hypothesis" in imported
    assert len(imported) >= 4, sorted(imported)
