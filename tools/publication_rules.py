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
#
# The minimum is one base64 run, not a round number, and the distinction it
# draws is carried by KEY_BODY's own 40-character floor: a documented header
# followed by prose or an ellipsis contributes nothing, so a body exists or it
# does not. The five legitimate headers in this repository's own docs and tests
# measure 0.
#
# It was 200 until 26 October 2026, which is a figure an RSA key clears easily
# and no other algorithm does. Measured on the keys of a repository this guard
# is also pointed at: an Ed25519 PKCS#8 private key body is 64 characters, so
# five real private keys scanned clean and the guard printed "private key
# material" among the rules it had checked. RSA-2048 is about 1,600, which is
# why nothing here caught it. The threshold was calibrated against the only
# algorithm this repository signs with, and then used to clear a repository
# that signs with another.
#
# tests/test_the_guard_sees_every_key_algorithm.py generates a real key per
# algorithm and requires each to be found, so the bound is derived from the
# artefacts rather than chosen.
KEY_HEADER = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----(.*?)-----END", re.S)
KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
KEY_BODY_MINIMUM = 40

CREDENTIALS = {
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "xAI key": re.compile(r"\bxai-[A-Za-z0-9_-]{20,}"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}

# Account identifiers, which are not credentials and are still not ours to
# publish. Separate from CREDENTIALS because the severity and the remedy differ:
# a leaked key is revoked, a leaked account identifier is redacted.
#
# This exists because the archive published one. xAI returns two forms of
# content refusal, and the verbose one carries organisational identifiers in the
# error body:
#
#   {"code":"The caller does not have permission to execute the specified
#    operation","error":"Content violates usage guidelines. Team: <uuid>,
#    API key ID: <uuid>, Model: grok-4-1-fast-reasoning, Failed check": ...}
#
# `red_team_suite.py` writes provider error text verbatim into the attempts
# log, deliberately, because an error's class and code are evidence. Thirteen
# such refusals reached six tracked files across three run identifiers, three of
# them under `docs/`, and `offences()` returned nothing for all six: the rule
# that exists to stop this did not see it. A key *ID* cannot call the API, so
# this was disclosure hygiene rather than an incident, and the guard's silence
# was the defect.
#
# Measured when this was added: across 5,646 published run artefacts, 52 UUIDs
# in 6 files and zero matches for any CREDENTIALS pattern, so no key has ever
# been published. The UUID rule has no false positives in the archive because a
# run identifier ends in 12 hex characters with no dashes and a hash is 64 with
# none.
ACCOUNT_IDENTIFIERS = {
    # The negative lookahead is load-bearing. Without it the rule matches its
    # own placeholder, so a file this module had just redacted still read as an
    # offence and no redaction could ever satisfy the guard. Found by running
    # the redactor and re-detecting, which is the only way it shows up.
    "provider account identifier": re.compile(
        r"(?i)\b(?:API key ID|Team)\s*:\s*(?!\[redacted\])[^\s,\"}]+"
    ),
    "UUID": re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    ),
}

#: What a redacted identifier is replaced with. One token, so a reader of a
#: redacted log can tell the difference between a field that was empty and a
#: field whose value was removed.
REDACTED = "[redacted]"


def account_identifiers(text) -> list:
    """Every account-identifier shape this text carries, by rule name."""
    return sorted(
        name for name, pattern in ACCOUNT_IDENTIFIERS.items() if pattern.search(text)
    )


def redact_account_identifiers(text) -> str:
    """Remove account identifiers while keeping what the text is evidence of.

    Used by the producer before provider error text reaches a log, and by the
    redaction of the six files that were published before it existed. Shares its
    patterns with `account_identifiers()` above, so what is detected and what is
    removed cannot drift: a second copy of this identity is the defect this
    project keeps finding.

    What survives deliberately: the exception class, the provider's `code`, its
    `Failed check` name and the model. Those are why the error is recorded at
    all. What goes: the labelled identifier fields, then any bare UUID left
    over, in that order, because the labelled form contains one.
    """
    out = str(text)
    labelled = ACCOUNT_IDENTIFIERS["provider account identifier"]
    out = labelled.sub(lambda m: m.group(0).split(":")[0] + ": " + REDACTED, out)
    out = ACCOUNT_IDENTIFIERS["UUID"].sub(REDACTED, out)
    return out


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
    # Applied to every surface, archives included. An audited prompt may contain
    # any words at all, which is why the writing rules are skipped for an
    # archive, but an account identifier is never part of a prompt: it arrives
    # in a provider's error body and gets written to a log beside it.
    reasons += [f"account identifier: {name}" for name in account_identifiers(text)]
    if patent:
        reasons += [f"patent analysis: {phrase!r}" for phrase in patent_analysis(text)]
    return reasons


def is_archive(relative: str) -> bool:
    """Whether this path is generated evidence under one of the archive roots."""
    return relative.startswith(ARCHIVE_PREFIXES)
