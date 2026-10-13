#!/usr/bin/env python3
"""Print a certificate's `result` field, or a specific reason it has none.

Exists as a file rather than as an inline one-liner in
.github/workflows/audit-and-sign.yml for the reason tools/ci_audit_verdict.sh
does: a rule nobody can invoke cannot be exercised, and the first version of
this was a `python -c` that no test could reach.

Never raises and always exits 0. The caller decides what to do with the value,
and the only value that may be treated as a pass is the certificate's own
`result` string. A certificate that cannot be read and a certificate with no
result are both failures, and each prints a distinguishable reason so the
failure says which one it was rather than printing an empty string for both.

Prints exactly one line:
  the certificate's `result`, when it is a non-empty string
  ABSENT, when the certificate parses but carries no usable `result`
  UNREADABLE (<reason>), when it cannot be parsed as a JSON object
"""
from __future__ import annotations

import json
import sys


def read_result(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as error:  # noqa: BLE001 - every failure is reportable, none is fatal
        return f"UNREADABLE ({type(error).__name__})"

    if not isinstance(payload, dict):
        return "UNREADABLE (certificate is not a JSON object)"

    result = payload.get("result")
    if isinstance(result, str) and result.strip():
        return result.strip()
    return "ABSENT"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("UNREADABLE (expected exactly one certificate path)")
        return 0
    print(read_result(argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
