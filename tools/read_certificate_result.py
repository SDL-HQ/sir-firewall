#!/usr/bin/env python3
"""Print a certificate's `result`, or a specific reason it has no usable one.

Exists as a file rather than as an inline one-liner in
.github/workflows/audit-and-sign.yml for the reason tools/ci_audit_verdict.sh
does: a rule nobody can invoke cannot be exercised, and the first version of
this was a `python -c` that no test could reach.

The caller compares this script's single line of output against the one value
that may pass. Every other outcome must therefore be a value that cannot equal
it, and should say which outcome it was rather than printing an empty string
for all of them.

What this validates, and what it does not. It checks that `result` is exactly
one of the three strings tools/generate_certificate.py can produce. It checks
nothing else about the certificate: signature, contract, ledger binding and
counter agreement are established by earlier steps, and a certificate saying
AUDIT PASSED while failing those is their business, not this script's.

Exact comparison rather than normalisation. The first version returned
`result.strip()`, so a certificate whose result was " \\nAUDIT PASSED\\t" was
reported as a pass. A malformed field is not evidence of a passing run, and a
gate whose job is to accept exactly one string should not be the thing that
repairs its input. Found by an independent review on 13 October 2026.

Prints exactly one line, always. Anything unrecognised is reported through
repr(), which escapes newlines and surrogates, so no value of `result` can
produce a second line or a character that stdout cannot encode. The previous
version printed the raw string, and a result of "\\ud800" raised
UnicodeEncodeError inside print(), which exits non-zero under `set -e` before
the step can report what it found.

Output, one line:
  AUDIT PASSED / AUDIT FAILED / INCONCLUSIVE   the certificate's own result
  ABSENT                                        parses, carries no result
  UNEXPECTED (<repr>)                           a result that is not one of the three
  UNREADABLE (<reason>)                         not parseable as a JSON object
"""
from __future__ import annotations

import json
import sys

# The complete set tools/generate_certificate.py._compute_audit_result returns.
# A result outside this set is not a verdict, whatever it says.
KNOWN_RESULTS = ("AUDIT PASSED", "AUDIT FAILED", "INCONCLUSIVE")


def read_result(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as error:  # noqa: BLE001 - every failure is reportable, none is fatal
        return f"UNREADABLE ({type(error).__name__})"

    if not isinstance(payload, dict):
        return "UNREADABLE (certificate is not a JSON object)"

    if "result" not in payload:
        return "ABSENT"

    result = payload["result"]
    if result in KNOWN_RESULTS:
        return result
    if result is None or (isinstance(result, str) and not result.strip()):
        return "ABSENT"
    return f"UNEXPECTED ({result!r})"


def emit(line: str) -> None:
    """Write one line that cannot fail to encode.

    repr() already escapes surrogates on the UNEXPECTED path, so this is the
    second guard rather than the first. It covers a path added later that
    forgets to.
    """
    safe = line.encode("utf-8", "backslashreplace").decode("utf-8", "replace")
    sys.stdout.write(safe.replace("\n", "\\n") + "\n")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        emit("UNREADABLE (expected exactly one certificate path)")
        return 0
    emit(read_result(argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
