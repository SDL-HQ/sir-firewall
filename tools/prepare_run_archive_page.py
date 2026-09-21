#!/usr/bin/env python3
"""Add per-run ledger-aware verification commands to the published archive page."""

import argparse
from pathlib import Path

from sir_firewall.evidence_paths import canonical_ledger_path

NEEDLE = '      return `<div class="link-group">${primaryHtml}</div>${extraHtml}`;'
_LEDGER_TEMPLATE = canonical_ledger_path("__RUN_ID__", runs_dir=Path("docs/runs")).as_posix()
_LEDGER_JAVASCRIPT = _LEDGER_TEMPLATE.replace("__RUN_ID__", "${esc(entry.run_id)}")
REPLACEMENT = """      const ev = entry?.evidence || {};
      const verifyCommand = ev.audit && entry?.run_id
        ? `<div class="verify-command"><code>python3 tools/verify_certificate.py docs/${esc(ev.audit)} --ledger %s</code></div>`
        : "";
      return `<div class="link-group">${primaryHtml}</div>${extraHtml}${verifyCommand}`;""" % _LEDGER_JAVASCRIPT


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("page", nargs="?", default="docs/runs/index.html")
    args = parser.parse_args()
    path = Path(args.page)
    text = path.read_text(encoding="utf-8")
    if REPLACEMENT in text:
        return 0
    # Replace either an unaugmented source page or the previous augmentation.
    previous_start = '      const ev = entry?.evidence || {};\n      const verifyCommand = ev.audit && ev.itgl_ledger'
    if previous_start in text:
        start = text.index('      const ev = entry?.evidence || {};', text.index('function renderEvidenceGroup'))
        end_line = '      return `<div class="link-group">${primaryHtml}</div>${extraHtml}${verifyCommand}`;'
        end = text.index(end_line, start) + len(end_line)
        text = text[:start] + REPLACEMENT + text[end:]
    elif NEEDLE in text:
        text = text.replace(NEEDLE, REPLACEMENT, 1)
    else:
        raise SystemExit(f"ERROR: archive-page verification insertion point not found: {path}")
    path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
