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

What it refuses, and why each is drawn narrowly:

- Working-document shapes. Named by pattern rather than by listing files, so a
  new handoff is caught without anyone remembering to add it here.
- Private key material. The header alone is not enough to fail, because the
  documentation needs to name it; what fails is a header followed by a key body.
  Checking for the body rather than the marker is the difference between a
  check people keep and a check people route around.
- Credential shapes for the providers and services this project actually uses.
  A generic high-entropy-string rule would flag hashes, run ids and signatures,
  of which this repository has hundreds of thousands.

Published archives are excluded from the working-document rules and included in
the secret rules. An archive is generated evidence and cannot contain a handoff,
but it could in principle carry something a run picked up.

Mutations measured on 16 October 2026, each run against the full file:

- add `claude/handoff-2026-10-16.md` to the tree:
  `test_no_working_document_is_tracked` fails (1 failed).
- add a real generated RSA private key to `docs/`:
  `test_no_tracked_file_carries_private_key_material` fails (1 failed).
- add a file containing a provider-shaped API key:
  `test_no_tracked_file_carries_a_credential` fails (1 failed).
- empty the tracked-file list: `test_the_scan_sees_the_repository` fails
  (1 failed).
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Shapes that mean "this was written to work from, not to publish".
WORKING_DOCUMENT = (
    re.compile(r"(^|/)\.?claude/"),
    re.compile(r"(^|/)handoff[-_]"),
    re.compile(r"(^|/)(codex|fable|grok)[-_]prompt"),
    re.compile(r"[-_]prompt[-_]\d{4}-\d{2}-\d{2}"),
    re.compile(r"patent[-_]coverage"),
    re.compile(r"patent[-_]brief"),
    re.compile(r"website[-_]changes[-_]queued"),
    re.compile(r"\.(docx|xlsx|pptx|doc|xls|ppt)$", re.IGNORECASE),
)

# A header on its own is documentation. A header with a body is a key.
KEY_HEADER = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----(.*?)-----END", re.S)
KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")

CREDENTIALS = {
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "xAI key": re.compile(r"\bxai-[A-Za-z0-9_-]{20,}"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}

ARCHIVE_PREFIXES = ("proofs/runs/", "docs/runs/", "proofs/archive/")

# Decided 16 October 2026. PATENTS.md states that an application is pending and
# nothing else; everything beyond that notice is held in SDL's private records.
# The claims register carried a coverage column until that date, and read
# together its verdicts characterised more than half the claims, cited
# specification paragraphs, and named places where described material is
# unclaimed. The specification publishes if the application is granted. An
# analysis of where its gaps are does not, unless we publish it.
PATENT_ANALYSIS = re.compile(
    # The claim-number rule excludes a version. tools/verify_certificate.py
    # says "a certificate that claims <version> or later", which is not a
    # patent reference, and a literal version here would make this file a
    # surface tests/test_evidence_version.py has to classify.
    r"\bclaims? \d+\b(?!\.\d)|19/820,502|\[0\d{3}\]|amendment reservoir|"
    r"\brecite[sd]?\b|filed specification|\bprovisional\b",
    re.IGNORECASE,
)
PATENT_NOTICE = "PATENTS.md"


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


def test_no_working_document_is_tracked():
    offenders = {
        relative: pattern.pattern
        for relative in TRACKED
        if not relative.startswith(ARCHIVE_PREFIXES)
        for pattern in WORKING_DOCUMENT
        if pattern.search(relative)
    }

    assert not offenders, (
        "these look like working documents, which live outside this public "
        f"repository: {offenders}"
    )


def test_no_tracked_file_carries_private_key_material():
    offenders = {}
    for relative, text in _readable(TRACKED):
        for match in KEY_HEADER.finditer(text):
            body = "".join(KEY_BODY.findall(match.group(2)))
            if len(body) > 200:
                offenders[relative] = f"{match.group(1)}, {len(body)} base64 characters"

    assert not offenders, (
        "these carry a private key header followed by a key body. A header "
        "alone is documentation and is allowed; a body is a key and is not: "
        f"{offenders}"
    )


def test_no_tracked_file_carries_a_credential():
    offenders = {}
    for relative, text in _readable(TRACKED):
        for name, pattern in CREDENTIALS.items():
            if pattern.search(text):
                offenders.setdefault(relative, []).append(name)

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

    def carries_material(text):
        return any(
            len("".join(KEY_BODY.findall(m.group(2)))) > 200
            for m in KEY_HEADER.finditer(text)
        )

    assert not carries_material(documented)
    assert carries_material(real)


def test_no_tracked_file_outside_the_notice_carries_patent_analysis():
    """One file may discuss the patent, and only to say one exists."""
    offenders = {}
    for relative, text in _readable(TRACKED):
        if relative == PATENT_NOTICE or relative.startswith(ARCHIVE_PREFIXES):
            continue
        # These two files are the rules themselves and have to name what
        # they refuse. Everything else is held.
        if relative in (Path(__file__).relative_to(ROOT).as_posix(),
                        "tests/test_claims_register.py"):
            continue
        found = sorted({m.group(0).lower() for m in PATENT_ANALYSIS.finditer(text)})
        if found:
            offenders[relative] = found

    assert not offenders, (
        "patent analysis belongs in SDL's private records. PATENTS.md carries "
        f"the notice and nothing else: {offenders}"
    )


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
