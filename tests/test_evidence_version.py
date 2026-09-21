import importlib.util
import json
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
    the past-run findings document, and other genuinely static historical documents are enumerated
    with exact expected values. Mutable signed pointers instead prove that their single recognised
    SIR application version agrees with the certificate's own ``sir_firewall_version`` field.
    Schema, document, and pack versions are excluded by matching only the runtime version plus the
    explicitly listed historical SIR application versions; the SVG exporter version is the sole
    unrelated semantic-version exception in that set. Every other tracked file containing a
    candidate token must be listed, so a new current surface fails until classified.
    """

    authority = sir_firewall.__version__
    v_102 = ".".join(("1", "0", "2"))
    v_200 = ".".join(("2", "0", "0"))
    v_210 = ".".join(("2", "1", "0"))
    v_220 = ".".join(("2", "2", "0"))
    v_221 = ".".join(("2", "2", "1"))
    v_230 = ".".join(("2", "3", "0"))
    v_231 = ".".join(("2", "3", "1"))
    v_232 = ".".join(("2", "3", "2"))
    v_233 = ".".join(("2", "3", "3"))
    archived_evidence_prefixes = ("proofs/runs/", "docs/runs/", "proofs/archive/")
    mutable_certificate_pointers = {
        "proofs/latest-audit.json",
        "docs/latest-audit.json",
        # These are intentionally classified before the first eligible live run creates them.
        "proofs/latest-live-audit.json",
        "docs/latest-live-audit.json",
    }
    expected_by_path = {
        "README.md": Counter({authority: 8, v_233: 2, v_232: 2, v_230: 2, v_231: 2, v_221: 2, v_220: 2}),
        "examples/verifier-negatives/tampered-leak-count.json": Counter({v_230: 1}),
        "examples/verifier-negatives/tampered-leak-count-rehashed.json": Counter({v_230: 1}),
        "examples/verifier-negatives/tampered-required-field-removed.json": Counter({v_230: 1}),
        "examples/verifier-negatives/tampered-signature-swap.json": Counter({v_230: 1}),
        "examples/verifier-negatives/tampered-unregistered-key.json": Counter({v_230: 1}),
        "docs/additional-phase-1-findings.md": Counter({v_221: 4, v_102: 1, v_200: 1}),
        "docs/assets/StructuralDesignLabs_Logo.svg": Counter({v_210: 1}),
        "docs/backlog.md": Counter({v_230: 1}),
        "docs/evidence-perimeter.v5.md": Counter({authority: 1}),
        "docs/evidence-binding-correction.md": Counter(
            {authority: 5, v_220: 4, v_221: 1, v_230: 1, v_233: 1}
        ),
        f"docs/release-notes-{v_221}.md": Counter({v_221: 2, v_220: 1}),
        "docs/release-notes-2.2.md": Counter({v_220: 1}),
        f"docs/release-notes-{v_230}.md": Counter({v_230: 2}),
        f"docs/release-notes-{v_231}.md": Counter({v_231: 2, v_230: 1}),
        f"docs/release-notes-{v_232}.md": Counter({v_232: 2}),
        f"docs/release-notes-{v_233}.md": Counter({v_233: 2, v_230: 3, v_231: 1}),
        f"docs/release-notes-{authority}.md": Counter({authority: 2, v_220: 1}),
        "docs/failure-modes.md": Counter({v_230: 3, v_231: 3, authority: 2}),
        "docs/rule-coverage.md": Counter({authority: 1}),
        "pyproject.toml": Counter({authority: 1}),
        "spec/evidence_contract.v1.json": Counter({v_220: 2}),
        "src/sir_firewall/__init__.py": Counter({authority: 1}),
        "tests/test_evidence_contract_applicability.py": Counter({v_220: 3, v_233: 1}),
        "tests/test_standalone_verifiers.py": Counter({authority: 1}),
    }
    version_pattern = re.compile(
        rf"(?<![\d.])(?:{'|'.join(re.escape(version) for version in (authority, v_102, v_200, v_210, v_220, v_221, v_230, v_231, v_232, v_233))})(?!\d)"
    )
    tracked_paths = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT
    ).decode("utf-8").split("\0")
    tracked_paths = list(filter(None, tracked_paths))
    mutable_if_versioned = {
        relative_path
        for relative_path in tracked_paths
        if relative_path == "proofs/local-audit.json"
        or Path(relative_path).name == "latest-run.json"
    }
    recognised_versions = {authority, v_102, v_200, v_210, v_220, v_221, v_230, v_231, v_232, v_233}
    observed_by_path = {}

    for relative_path in sorted(mutable_certificate_pointers | mutable_if_versioned):
        if relative_path not in tracked_paths:
            continue
        payload = json.loads((ROOT / relative_path).read_text(encoding="utf-8"))
        certificate_version = payload.get("sir_firewall_version")
        if relative_path in mutable_if_versioned and certificate_version is None:
            continue
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        versions = Counter(version_pattern.findall(text))
        assert certificate_version in recognised_versions, relative_path
        assert versions == Counter({certificate_version: 1}), relative_path

    # A new release-notes file or any other version-bearing file is expected to
    # fail this test until it is classified above. Do not make the archive
    # exclusions broader to get a new release green; classify the new surface.
    for relative_path in tracked_paths:
        if relative_path.startswith(archived_evidence_prefixes):
            continue
        if relative_path in mutable_certificate_pointers | mutable_if_versioned:
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
