"""This repository is public. Working documents and secrets must not reach it.

SIR's working documents live outside this repository: handoffs, review prompts,
scope documents, and the patent coverage analysis the claims register's Coverage
column is derived from. That separation is deliberate and, until now, enforced
by nothing but habit. A single `git add .` from the wrong directory would have
published the lot, and the patent coverage analysis in particular is a
feature-by-feature map of what is and is not inside the filed application, which
is to say a list of what a competitor is free to copy.

An audit on 16 October 2026 found the separation had in fact held: no working
document has ever been committed, no private key material has ever been in any
blob in the history, and the only email addresses in the tree are the company
contact and `test@example.invalid`. Six `-----BEGIN PRIVATE KEY-----` markers do
appear in documentation, every one a placeholder with no key body, one of them
reading "YOUR REAL PRIVATE KEY HERE". This file turns that audit into a check
that runs on every commit, because an audit establishes a fact about one day.

The rules themselves live in `tools/publication_rules.py`, which says why each
is drawn as narrowly as it is. They moved there on 17 October 2026 because this
repository is no longer the only tree published from it: the evidence window is
generated and pushed to a second public repository, its prose exists in no file
here, and the generator now runs the same rules over the tree it is about to
publish. One definition, two surfaces.

Published archives are excluded from the working-document and patent rules and
included in the secret rules. An archive is generated evidence and cannot
contain a handoff, and its audited prompts may contain any words at all, but it
could in principle carry something a run picked up.

Mutations measured on 16 October 2026, each run against the full file, and all
four repeated on 17 October 2026 after the rules moved. Lifting logic out of a
check is how a check goes hollow while still reading correctly, so the move is
not finished until the mutations that caught something before catch it again:

- add `claude/handoff-2026-10-17.md` to the tree:
  `test_no_working_document_is_tracked` fails (1 failed, both dates).
- add a real generated RSA private key to `docs/`:
  `test_no_tracked_file_carries_private_key_material` fails (1 failed, both).
- add a file containing a provider-shaped API key:
  `test_no_tracked_file_carries_a_credential` fails (1 failed, both).
- empty the tracked-file list: `test_the_scan_sees_the_repository` fails. One
  failure on 16 October and two on 17, because
  `test_every_exempted_rule_file_is_real_and_needs_the_exemption` reads the
  same list and an empty one takes its exemptions with it.

The generator's own five mutations over the window are recorded in
`tests/test_generate_shop_window.py`, next to the tests that measure them.
"""

import subprocess
from pathlib import Path

import pytest

import publication_rules
from publication_rules import (
    ARCHIVE_PREFIXES,
    KEY_BODY,
    KEY_BODY_MINIMUM,
    KEY_HEADER,
    PATENT_ANALYSIS,
    PATENT_NOTICE,
    RULE_FILES,
    WORKING_DOCUMENT,
)

ROOT = Path(__file__).resolve().parents[1]


def _tracked() -> list:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


TRACKED = _tracked()


def _readable(paths):
    for relative in paths:
        path = ROOT / relative
        if not path.is_file():
            continue
        try:
            yield relative, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue


def test_the_scan_sees_the_repository():
    """Guard the guard. An empty file list would make everything below pass."""
    assert len(TRACKED) > 1000, len(TRACKED)
    assert any(p.endswith(".py") for p in TRACKED)
    assert "docs/claims-register.md" in TRACKED


def test_the_rules_this_file_enforces_are_the_ones_the_generator_enforces():
    """The point of moving them. A second copy is the defect, not the fix."""
    assert publication_rules.__file__.endswith("tools/publication_rules.py")
    assert RULE_FILES[0] == "tools/publication_rules.py"
    assert Path(__file__).relative_to(ROOT).as_posix() in RULE_FILES
    assert publication_rules.working_document("claude/handoff-2026-10-17.md")
    assert not publication_rules.working_document("docs/claims-register.md")


def test_no_working_document_is_tracked():
    offenders = {
        relative: pattern
        for relative in TRACKED
        if not publication_rules.is_archive(relative)
        for pattern in [publication_rules.working_document(relative)]
        if pattern
    }

    assert not offenders, (
        "these look like working documents, which live outside this public "
        f"repository: {offenders}"
    )


def test_no_tracked_file_carries_private_key_material():
    offenders = {
        relative: found
        for relative, text in _readable(TRACKED)
        for found in [publication_rules.private_key_material(text)]
        if found
    }

    assert not offenders, (
        "these carry a private key header followed by a key body. A header "
        "alone is documentation and is allowed; a body is a key and is not: "
        f"{offenders}"
    )


def test_no_tracked_file_carries_a_credential():
    offenders = {
        relative: found
        for relative, text in _readable(TRACKED)
        for found in [publication_rules.credentials(text)]
        if found
    }

    assert not offenders, f"these look like live credentials: {offenders}"


@pytest.mark.parametrize(
    "pattern,sample",
    [
        ("claude directory", "claude/handoff-2026-10-16.md"),
        ("handoff", "docs/handoff-notes.md"),
        ("review prompt", "docs/codex-prompt-review.md"),
        ("patent coverage", "docs/patent-coverage-boundary.md"),
        ("office document", "docs/SDL_RD_Plan.docx"),
    ],
)
def test_the_working_document_patterns_catch_what_they_are_for(pattern, sample):
    """Each rule is exercised against the shape it exists to refuse."""
    assert any(rule.search(sample) for rule in WORKING_DOCUMENT), (pattern, sample)


@pytest.mark.parametrize(
    "sample",
    [
        "docs/claims-register.md",
        "tools/verify_certificate.py",
        # A release-notes path would be the obvious sample here and is
        # deliberately not used: its version literal would make this file a
        # surface tests/test_evidence_version.py has to classify, for a
        # string that is only ever an example.
        "docs/threat-model.md",
        "proofs/runs/20261015-092557-107124-gh38712792514-670d9d4222c2/baseline.json",
    ],
)
def test_the_working_document_patterns_leave_real_files_alone(sample):
    """A guard that flags correct work is one people route around."""
    assert not any(rule.search(sample) for rule in WORKING_DOCUMENT), sample


def test_a_documented_key_header_without_a_body_is_allowed():
    """The documentation has to be able to name the thing it is about."""
    documented = (
        'export SDL_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY----- ... '
        '-----END PRIVATE KEY-----"'
    )
    real = "-----BEGIN PRIVATE KEY-----\n" + ("A" * 64 + "\n") * 20 + "-----END PRIVATE KEY-----"

    assert not publication_rules.private_key_material(documented)
    assert publication_rules.private_key_material(real)
    # The threshold is the rule, so name it rather than trusting the samples.
    assert KEY_BODY_MINIMUM == 200
    assert len("".join(KEY_BODY.findall(KEY_HEADER.search(real).group(2)))) > KEY_BODY_MINIMUM


def test_no_tracked_file_outside_the_notice_carries_patent_analysis():
    """One file may discuss the patent, and only to say one exists."""
    offenders = {}
    for relative, text in _readable(TRACKED):
        if relative == PATENT_NOTICE or publication_rules.is_archive(relative):
            continue
        # The rule files have to name what they refuse. Everything else is held.
        if relative in RULE_FILES:
            continue
        found = publication_rules.patent_analysis(text)
        if found:
            offenders[relative] = found

    assert not offenders, (
        "patent analysis belongs in SDL's private records. PATENTS.md carries "
        f"the notice and nothing else: {offenders}"
    )


def test_every_exempted_rule_file_is_real_and_needs_the_exemption():
    """An exemption nobody can lose track of. Each one earns its place."""
    for relative in RULE_FILES:
        path = ROOT / relative
        assert path.is_file(), relative
        assert relative in TRACKED, relative
        assert publication_rules.patent_analysis(
            path.read_text(encoding="utf-8")
        ), f"{relative} no longer needs the exemption, so remove it"


def test_the_patent_pattern_catches_the_column_that_was_removed():
    """Exercised against the real wording, so the rule is not notional."""
    removed = [
        "*Coverage: inside, claimed.* Claims 1 and 14 recite deterministic rule evaluation",
        "They are in the amendment reservoir rather than in the claims.",
        "The `trust_fingerprint` composition at [0232] is inside and unclaimed.",
        "whether the feature sits inside the filed specification (US 19/820,502)",
        "an NZ provisional to hold the date rather than a full filing",
    ]
    for sample in removed:
        assert PATENT_ANALYSIS.search(sample), sample

    kept = [
        "the gate returns PASS or BLOCKED and nothing else",
        "docs/evidence-perimeter.v6.md records both pairs",
        "a certificate signs commit_sha",
    ]
    for sample in kept:
        assert not PATENT_ANALYSIS.search(sample), sample
