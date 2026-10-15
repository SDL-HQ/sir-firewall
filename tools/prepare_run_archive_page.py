#!/usr/bin/env python3
"""Prepare the copied run archive page with verification and generated coverage."""

import argparse
from pathlib import Path

import sys
from pathlib import Path as _Path

# Run directly from a clone without an editable install. The four verifiers in
# this directory already do this; a tool that only works once the package is
# installed makes a test's outcome depend on the ambient environment, which is
# how test_rule_coverage_report came to pass or fail according to whether
# PYTHONPATH happened to be set. tests/test_tools_run_from_a_clone.py holds the
# property for every tool here that imports sir_firewall.
_REPO_ROOT = _Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_Path(__file__).resolve().parent))

from sir_firewall.evidence_paths import canonical_ledger_path
from rule_coverage_report import build_report, inject_javascript_lookup

NEEDLE = '      return `<div class="link-group">${primaryHtml}</div>${extraHtml}`;'
AUGMENTED_RETURN = (
    '      return `<div class="link-group">${primaryHtml}</div>${extraHtml}${verifyCommand}`;'
)
_LEDGER_TEMPLATE = canonical_ledger_path("__RUN_ID__", runs_dir=Path("docs/runs")).as_posix()
_LEDGER_JAVASCRIPT = _LEDGER_TEMPLATE.replace("__RUN_ID__", "${esc(entry.run_id)}")
REPLACEMENT = """      const ev = entry?.evidence || {};
      // The command names the verifier for the document the entry holds. A
      // baseline record is verified by tools/verify_baseline_record.py;
      // tools/verify_certificate.py refuses a document that is not a
      // certificate on every path, including --no-ledger.
      const documentPath = isBaselineRecord(entry) ? ev.baseline : ev.audit;
      const verifier = isBaselineRecord(entry) ? "verify_baseline_record.py" : "verify_certificate.py";
      const verifyCommand = documentPath && entry?.run_id
        ? `<div class="verify-command"><code>python3 tools/${verifier} docs/${esc(documentPath)} --ledger %s</code></div>`
        : "";
      return `<div class="link-group">${primaryHtml}</div>${extraHtml}${verifyCommand}`;""" % _LEDGER_JAVASCRIPT

COVERAGE_VARIABLE = "FULL_GATE_COVERAGE"
COVERAGE_INDENT = 4


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("page", nargs="?", default="docs/runs/index.html")
    args = parser.parse_args()
    path = Path(args.page)
    text = path.read_text(encoding="utf-8")
    if REPLACEMENT not in text:
        # Replace either an unaugmented source page or a previous augmentation.
        # Any augmentation is recognised by the return line it leaves behind,
        # rather than by the condition the old insertion happened to use: this
        # tool used to name that condition, so changing it made the tool refuse
        # a page it had augmented itself.
        if AUGMENTED_RETURN in text:
            start = text.index(
                '      const ev = entry?.evidence || {};',
                text.index("function renderEvidenceGroup"),
            )
            end = text.index(AUGMENTED_RETURN, start) + len(AUGMENTED_RETURN)
            text = text[:start] + REPLACEMENT + text[end:]
        elif NEEDLE in text:
            text = text.replace(NEEDLE, REPLACEMENT, 1)
        else:
            raise SystemExit(f"ERROR: archive-page verification insertion point not found: {path}")

    # Deliberately do not catch coverage errors: publication must fail rather
    # than write an archive page without current generated coverage.
    text = inject_javascript_lookup(
        text,
        build_report(),
        COVERAGE_VARIABLE,
        COVERAGE_INDENT,
    )
    path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
