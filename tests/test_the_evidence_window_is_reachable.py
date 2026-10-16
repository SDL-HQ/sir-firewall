"""The front door is only a front door if something points at it.

The evidence window is a separate generated repository. Everything inside it
is derived and held by `tests/test_generate_shop_window.py`, so the part that
can rot without anyone noticing is on this side: the two places in this
repository that send a stranger there, and the three figures those two places
quote.

The audit page is the higher-value of the two. A reader of a served
certificate is, by definition, someone deciding whether to believe it, and
until now that page asked them to clone this entire repository. The line added
to `proofs/template.html` offers the small alternative in the one box where
they are already looking for it.

The figures are quoted rather than vague because "seven archives, three
verifiers, one dependency" is what makes the link worth a click, and a quoted
figure is a claim. Each is recomputed here from the thing it describes, so
adding an eighth exhibit or a second dependency turns these red rather than
turning the public pages wrong.

Mutations measured on 16 October 2026:

- point the README at `sir-firewall` instead of the window:
  `test_the_readme_sends_a_reader_to_the_window` fails (1 failed).
- remove the line from the audit page template:
  `test_the_audit_page_offers_the_small_alternative` fails (1 failed).
- say "eight real archives" in the README:
  `test_both_pages_quote_the_exhibit_count_the_tool_produces` fails (1 failed).
- add `jsonschema` to `verify_archive_receipt.py`'s imports:
  `test_one_dependency_is_still_one_dependency` fails (1 failed). This is the
  one worth having. The dependency count is the only figure of the three a
  routine change elsewhere can falsify, and a visitor who is told to install
  one package and then hits a missing import has been given a worse first
  minute than if we had told them nothing.
- drop the window's link back to the archive of record:
  `test_the_window_says_where_it_came_from` fails (1 failed).

The dependency check reads the imports with `ast` rather than a regular
expression. The first version matched line starts in the file text and
reported a dependency named "the", from a docstring sentence beginning "from
the". It would have gone red on prose and stayed green on an import inside a
function, which is the wrong way round.

That check, the verifier count and the number words moved into
`tools/generate_shop_window.py` on 17 October 2026, because the window's
About line needs the same three and a second copy of any of them is the
defect this project keeps finding. This file still owns the claim that the
two public pages quote them correctly; it no longer owns how they are
computed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = _load("generate_shop_window", "tools/generate_shop_window.py")
SHOP_WINDOW = _load("shop_window", "tools/shop_window.py")

#: Number words, and the rule for what a visitor must install, both read from
#: the generator. They were duplicated here until 17 October 2026, when the
#: About line needed the same two and a second copy would have been the
#: defect this project keeps finding.
WORDS = GENERATOR.WORDS
README = (ROOT / "README.md").read_text(encoding="utf-8")
TEMPLATE = (ROOT / "proofs" / "template.html").read_text(encoding="utf-8")


def test_the_readme_sends_a_reader_to_the_window():
    """Most arrivals start at the product repository, above the fold."""
    assert GENERATOR.WINDOW in README
    position = README.index(GENERATOR.WINDOW)
    assert position < len(README) // 4, "the link is below the part anyone reads"


def test_the_audit_page_offers_the_small_alternative():
    """The box that says "clone this repo" now also says "or clone a smaller one"."""
    assert GENERATOR.WINDOW in TEMPLATE
    box = TEMPLATE[TEMPLATE.index("Canonical verification path") :]
    box = box[: box.index("</div>\n\n")]
    assert GENERATOR.WINDOW in box, "the link is outside the verification box"


def test_both_pages_quote_the_exhibit_count_the_tool_produces():
    """`shop_window.py` decides how many exhibits there are. These pages repeat it."""
    expected = f"{WORDS[len(SHOP_WINDOW.SPECIFICATION)]} real"
    assert expected in README
    assert expected in TEMPLATE


def test_both_pages_quote_the_number_of_verifiers_the_window_ships():
    """A visitor counts the things they run, not the files that get copied."""
    expected = f"{WORDS[len(GENERATOR.verifier_commands())]} verifiers"
    assert expected in README
    assert expected in TEMPLATE


def test_both_pages_quote_how_many_archives_the_verdict_tool_establishes():
    """The figure that matters, and the one the window got wrong.

    The window called an archive clean on two exit codes while the project's
    own verdict tool said NOT ESTABLISHED about it. Both public surfaces now
    quote the number of exhibits the verdict tool establishes, so a reader is
    told the weaker number rather than discovering it.
    """
    figures = json.loads((ROOT / "docs" / "archive-figures.json").read_text(encoding="utf-8"))
    exhibits = SHOP_WINDOW.select(figures)
    established = [e for e in exhibits if e.verdict == "ESTABLISHED"]
    expected = f"establishes {WORDS[len(established)]} of the {WORDS[len(exhibits)]}"
    assert expected in README, expected
    assert expected in TEMPLATE, expected


def test_one_dependency_is_still_one_dependency():
    """Recomputed from the imports of every file the window actually ships.

    The promise is "one dependency to install". Anything a shipped verifier
    imports that is neither standard library nor shipped alongside it breaks
    that promise in a place no other test looks.
    """
    third_party = GENERATOR.third_party_dependencies()

    assert third_party == {"cryptography"}, sorted(third_party)
    expected = f"{WORDS[len(third_party)]} dependency"
    assert expected in README
    assert expected in TEMPLATE


def test_the_window_says_where_it_came_from():
    """A one-way link leaves a visitor unable to check the thing it is derived from."""
    figures = json.loads((ROOT / "docs" / "archive-figures.json").read_text(encoding="utf-8"))
    readme = GENERATOR._readme(SHOP_WINDOW.select(figures), figures, "v0.0.0-test")
    assert GENERATOR.VAULT in readme


def test_the_two_repositories_are_not_the_same_repository():
    """A window hosted inside the repository it is about checks nothing."""
    assert GENERATOR.WINDOW != GENERATOR.VAULT
    assert GENERATOR.WINDOW.rsplit("/", 1)[0] == GENERATOR.VAULT.rsplit("/", 1)[0]
