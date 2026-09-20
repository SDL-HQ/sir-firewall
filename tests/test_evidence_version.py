import importlib.util
import re
import subprocess
from collections import Counter
from pathlib import Path

import sir_firewall


ROOT = Path(__file__).resolve().parents[1]


def _load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_certificate_generator_uses_package_version():
    generator = _load_tool("generate_certificate")

    assert generator._sir_firewall_version() == sir_firewall.__version__


def test_local_audit_uses_package_version():
    local_audit = _load_tool("local_audit")

    assert local_audit._sir_version() == sir_firewall.__version__


def test_current_version_surfaces_match_runtime_authority():
    """Guard current surfaces without rewriting historical or independently versioned artifacts.

    Archive trees are excluded only by the explicit prefixes below. Historical release notes,
    current signed-proof pointers, and the past-run findings document are enumerated with exact
    expected values. Schema, document, and pack versions are excluded by matching only the runtime
    version plus the explicitly listed historical SIR application versions; the SVG exporter
    version is the sole unrelated semantic-version exception in that set. Every other tracked file
    containing a candidate token must be listed, so a new current surface fails until classified.
    """

    authority = sir_firewall.__version__
    v_102 = ".".join(("1", "0", "2"))
    v_200 = ".".join(("2", "0", "0"))
    v_210 = ".".join(("2", "1", "0"))
    v_220 = ".".join(("2", "2", "0"))
    v_221 = ".".join(("2", "2", "1"))
    archived_evidence_prefixes = ("proofs/runs/", "docs/runs/", "proofs/archive/")
    expected_by_path = {
        "README.md": Counter({authority: 3, v_221: 2, v_220: 1}),
        "docs/additional-phase-1-findings.md": Counter({v_221: 4, v_102: 1, v_200: 1}),
        "docs/assets/StructuralDesignLabs_Logo.svg": Counter({v_210: 1}),
        "docs/backlog.md": Counter({authority: 1}),
        "docs/evidence-perimeter.v5.md": Counter({authority: 1}),
        "docs/latest-audit.json": Counter({v_221: 1}),
        f"docs/release-notes-{v_221}.md": Counter({v_221: 2, v_220: 1}),
        "docs/release-notes-2.2.md": Counter({v_220: 1}),
        f"docs/release-notes-{authority}.md": Counter({authority: 2}),
        "docs/rule-coverage.md": Counter({authority: 1}),
        "proofs/latest-audit.json": Counter({v_221: 1}),
        "pyproject.toml": Counter({authority: 1}),
        "src/sir_firewall/__init__.py": Counter({authority: 1}),
    }
    version_pattern = re.compile(
        rf"(?<![\d.])(?:{'|'.join(re.escape(version) for version in (authority, v_102, v_200, v_210, v_220, v_221))})(?!\d)"
    )
    tracked_paths = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT
    ).decode("utf-8").split("\0")
    observed_by_path = {}

    # A new release-notes file or any other version-bearing file is expected to
    # fail this test until it is classified above. Do not make the archive
    # exclusions broader to get a new release green; classify the new surface.
    for relative_path in filter(None, tracked_paths):
        if relative_path.startswith(archived_evidence_prefixes):
            continue
        path = ROOT / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        versions = Counter(version_pattern.findall(text))
        if versions:
            observed_by_path[relative_path] = versions

    assert observed_by_path == expected_by_path
