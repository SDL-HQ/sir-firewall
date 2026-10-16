"""What must not reach a public surface, held in one place.

Two trees are published from this repository and they are published by
different means. This repository is published by being pushed, and every
commit runs tests/test_no_working_documents_in_the_public_repository.py over
its tracked files. The evidence window is published by being generated:
tools/generate_shop_window.py builds a tree, writes prose into it that exists
nowhere else, and that tree is pushed to a second public repository. Until
these rules moved here, nothing inspected the second one.

The rules are here rather than in the test that used to own them because the
alternative is a second copy, and a second copy of an identity is the defect
this project keeps finding. The quieter half of that failure is the one that
matters: the repository's guard runs where a person is watching the commit,
and the window's prose exists only for the length of a build.

Each rule is drawn narrowly, and the reasons are worth keeping:

- Working-document shapes are named by pattern rather than by listing files,
  so a new handoff is caught without anyone remembering to add it here.
- A private key header alone is not enough to fail, because the documentation
  has to be able to name it. What fails is a header followed by a key body.
  Checking for the body rather than the marker is the difference between a
  check people keep and a check people route around.
- Credential shapes cover the providers and services this project actually
  uses. A generic high-entropy rule would flag hashes, run identifiers and
  signatures, of which this repository has hundreds of thousands.
- Patent analysis is refused everywhere but the notice. PATENTS.md states that
  an application is pending and nothing else; everything past that notice is
  held in SDL's private records, because an analysis of where an application's
  gaps are is a list of what a competitor is free to copy.

Published archives are generated evidence. They cannot contain a handoff, and
their audited prompts can contain any words at all, so callers pass
`working_documents=False` and `patent=False` for an archive path and leave the
secret rules on. That is what both surfaces do.
"""

import re

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
KEY_BODY_MINIMUM = 200

CREDENTIALS = {
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "xAI key": re.compile(r"\bxai-[A-Za-z0-9_-]{20,}"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}

PATENT_ANALYSIS = re.compile(
    # The claim-number rule excludes a version. tools/verify_certificate.py
    # says "a certificate that claims <version> or later", which is not a
    # patent reference, and a literal version here would make this file a
    # surface tests/test_evidence_version.py has to classify.
    r"\bclaims? \d+\b(?!\.\d)|19/820,502|\[0\d{3}\]|amendment reservoir|"
    r"\brecite[sd]?\b|filed specification|\bprovisional\b",
    re.IGNORECASE,
)

#: The one file allowed to say an application exists.
PATENT_NOTICE = "PATENTS.md"

#: A phrase the patent rule refuses, in the wording it was removed in, exported
#: so that a test somewhere else can plant it without becoming a file this rule
#: then has to exempt. That is not hypothetical: the generator's tests were
#: written with the phrase inline on 17 October 2026 and the vault's own guard
#: caught its own test suite, which is the guard working. Exempting an
#: 870-line test file to keep one sample would have been the wrong trade.
PATENT_SAMPLE = "Claims 1 and 14 recite deterministic rule evaluation."

#: Files that hold these rules and so have to name what they refuse. A caller
#: scanning this repository exempts them. A caller scanning a generated tree
#: does not, because a generated tree has no business carrying them.
RULE_FILES = (
    "tools/publication_rules.py",
    "tests/test_no_working_documents_in_the_public_repository.py",
    "tests/test_claims_register.py",
)

#: Prefixes under which a path is generated evidence rather than writing.
ARCHIVE_PREFIXES = ("proofs/runs/", "docs/runs/", "proofs/archive/")


def working_document(relative: str) -> str:
    """The pattern that refuses this path, or an empty string."""
    for pattern in WORKING_DOCUMENT:
        if pattern.search(relative):
            return pattern.pattern
    return ""


def private_key_material(text: str) -> list:
    """Every private key header in `text` that is followed by a key body."""
    found = []
    for match in KEY_HEADER.finditer(text):
        body = "".join(KEY_BODY.findall(match.group(2)))
        if len(body) > KEY_BODY_MINIMUM:
            found.append(f"{match.group(1)}, {len(body)} base64 characters")
    return found


def credentials(text: str) -> list:
    """The names of every credential shape present in `text`."""
    return [name for name, pattern in CREDENTIALS.items() if pattern.search(text)]


def patent_analysis(text: str) -> list:
    """Every distinct phrase in `text` that discusses the application."""
    return sorted({match.group(0).lower() for match in PATENT_ANALYSIS.finditer(text)})


def offences(relative, text, *, working_documents=True, patent=True) -> list:
    """Every reason this file must not be published, in the caller's words.

    `text` is None for a file that could not be read as UTF-8, which leaves
    the path rule as the only one that can apply. Both surfaces pass binary
    files that way rather than skipping them, because a path is still a claim.
    """
    reasons = []
    if working_documents:
        pattern = working_document(relative)
        if pattern:
            reasons.append(f"working document, matching {pattern}")
    if text is None:
        return reasons
    reasons += [f"private key material: {found}" for found in private_key_material(text)]
    reasons += [f"credential shaped like a {name}" for name in credentials(text)]
    if patent:
        reasons += [f"patent analysis: {phrase!r}" for phrase in patent_analysis(text)]
    return reasons


def is_archive(relative: str) -> bool:
    """Whether this path is generated evidence under one of the archive roots."""
    return relative.startswith(ARCHIVE_PREFIXES)
