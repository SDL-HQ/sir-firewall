"""Every tool in tools/ runs from a clone, with no install and no PYTHONPATH.

A stranger who clones the repository and runs a tool should get the tool's own
behaviour, not ``ModuleNotFoundError: No module named 'sir_firewall'``. Four
verifiers always did this. Seven other tools did not, and worked only because
the environment they happened to be run in made the package importable:
``latency_report``, ``prepare_run_archive_page``, ``publish_run``,
``quorum_firewall``, ``rule_coverage_report``, ``run_paired_benchmark``, and
``generate_certificate``, which inserted only its own directory and did so after
the package imports.

That is worse than an inconvenience, because it makes a test's outcome depend on
the ambient environment.
``test_rule_coverage_report.py::test_run_archive_publication_prepares_generated_coverage_region``
shells out to ``prepare_run_archive_page.py``, and the child process does not
inherit pytest's ``pythonpath = ["src"]``. It therefore passed for anyone with
an editable install or ``PYTHONPATH`` already set and failed for anyone else, on
the same commit. A test with two answers is not evidence.

Each tool below is run the way a person runs it, as a script, with the
environment emptied so nothing but the tool itself can make the import work.
``--help`` is sufficient: these imports are at module scope, so a tool that
cannot find the package fails before it parses arguments.
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
BARE_ENVIRONMENT = {"PATH": "/usr/bin:/bin"}


def _imports_the_package(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return "from sir_firewall" in text or "import sir_firewall" in text


ALL_TOOLS = sorted(path.name for path in TOOLS.glob("*.py"))
TOOLS_IMPORTING_THE_PACKAGE = sorted(
    path.name for path in TOOLS.glob("*.py") if _imports_the_package(path)
)


def _help(tool: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOLS / tool), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=dict(BARE_ENVIRONMENT),
    )


def test_the_set_of_tools_importing_the_package_is_not_empty():
    """Guard the guard. A rename or a move must not make this file vacuous."""
    assert len(TOOLS_IMPORTING_THE_PACKAGE) >= 9, TOOLS_IMPORTING_THE_PACKAGE


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_a_tool_imports_what_it_needs_without_help_from_the_environment(tool):
    result = _help(tool)
    combined = result.stdout + result.stderr

    assert "ModuleNotFoundError" not in combined, combined[-1500:]
    assert "ImportError" not in combined, combined[-1500:]


def test_the_page_preparer_runs_as_a_child_process_of_the_tests():
    """The specific case that had two answers, pinned on its own."""
    assert _help("prepare_run_archive_page.py").returncode == 0


def test_the_quorum_tool_imports_a_module_that_exists():
    """It imported ``sir_firewall.sir_firewall``, gone since the move to core.py.

    Nothing in the repository referenced this tool, so a broken import sat in a
    shipped directory from the commit that created it until 8 October 2026,
    raising in every environment rather than only in a bare one. The parametrised
    test above covers it; this names it, so that deleting the tool is a decision
    someone takes rather than a way to make a test pass.

    This tool takes no arguments and reads argv[1] as a path, so it is asserted
    to reach its own argument handling rather than to exit 0.
    """
    result = _help("quorum_firewall.py")
    combined = result.stdout + result.stderr

    assert "ModuleNotFoundError" not in combined, combined
    assert "Failed to load ISC payload" in combined, combined
