"""The certificate results SIR recognises, declared once.

Every reader that turns a certificate's `result` into something else, a CI
status, a published marker, a pass/fail line, takes the set from here. Until 14
October 2026 the set was written out three times: as a tuple in
tools/read_certificate_result.py and as an if/elif chain in each of the two
marker steps in .github/workflows/audit-and-sign.yml. The test that was meant to
keep the markers in agreement checked that each named the three strings, so a
marker that accepted a fourth value while still naming the original three
passed it. Codex demonstrated that by adding the branch in memory.

With one declaration, a fourth value is authorised in one place, and the tests
in tests/test_certificate_result_set.py fail if any reader accepts a value this
module does not declare, or if this module declares a value the certificate
generator cannot produce.

Exact comparison. The markers used to normalise with strip().upper(), while the
result reader compared exactly and documented why: a malformed field is not
evidence of a run, and the gate deciding what a run said should not repair its
input. One reader normalising and another not was itself a divergence. Both now
compare exactly.
"""
from __future__ import annotations

from typing import NamedTuple


class ResultStatus(NamedTuple):
    status: str
    audit_pass: bool
    inconclusive: bool


# The complete set tools/generate_certificate.py._compute_audit_result returns,
# with what each one publishes as. Nothing outside this mapping is a verdict.
RESULT_STATUS: dict[str, ResultStatus] = {
    "AUDIT PASSED": ResultStatus(status="PASS", audit_pass=True, inconclusive=False),
    "AUDIT FAILED": ResultStatus(status="FAIL", audit_pass=False, inconclusive=False),
    "INCONCLUSIVE": ResultStatus(status="INCONCLUSIVE", audit_pass=False, inconclusive=True),
}

KNOWN_RESULTS: tuple[str, ...] = tuple(RESULT_STATUS)


class UnrecognisedResult(ValueError):
    """A result outside the declared set. Callers stop; they do not map it."""


def status_for(result: object) -> ResultStatus:
    """Map a recorded result to its published status, or refuse it."""
    if isinstance(result, str) and result in RESULT_STATUS:
        return RESULT_STATUS[result]
    raise UnrecognisedResult(f"unsupported certificate result: {result!r}")
