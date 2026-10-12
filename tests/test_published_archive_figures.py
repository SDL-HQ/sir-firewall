"""Every published figure about the archive is generated, not transcribed.

Until 12 October 2026 `tools/archive_verification_report.py` produced the figures
and a person retyped them into `docs/archive-errata.md`,
`docs/claims-register.md` and `README.md`. Both documents said the figures were
generated rather than transcribed, which was not true.
`tests/test_archive_errata_figures.py` compared one table against the report and
caught drift in it. Nothing compared the rest, and four statements were wrong in
kind rather than by a count: E4 named a cause this measurement cannot produce,
E3 sent a reader to E4 for records that are not there, E6 was two runs stale with
a product list short by one, and the register described an absent field as
reporting `false`.

The figures now live in delimited regions owned by the generator. This file holds
the properties that make that mean something:

1. every region the generator owns exists, exactly once, in its document,
2. no document carries a region the generator does not own,
3. each region's content equals fresh output from a real verifier run,
4. the generator refuses to publish a decomposition it cannot account for,
5. the set-membership claims E3 makes are checked at generation time,
6. regeneration is idempotent, so publication does not churn the documents,
7. a live figure does not appear in prose outside a region, except where the
   sentence is about a past measurement and is listed here as such.

Mutation table. Each mutation below was applied to the repository on 12 October
2026, the stated effect observed, and the mutation reverted:

| Mutation | Effect |
|---|---|
| a figure edited by hand inside a region | test_every_region_matches_fresh_output fails, naming the region |
| a region's opening marker deleted | test_every_region_the_generator_owns_is_present fails, naming the region |
| a region added to a document with no renderer | test_no_document_carries_an_unowned_region fails |
| a verifier discriminator constant changed | the module raises FigureError while importing, so the whole file errors at collection rather than failing one test. That is the intended behaviour: the generator refuses to publish a decomposition it cannot account for, and refusing early is the point |
| `if updated != document` made unconditional | test_regeneration_is_idempotent fails |
| the archive total retyped into prose outside a region | test_live_figures_do_not_appear_outside_a_region fails |

Two further mutations are applied by the tests themselves, to copies of the
records rather than to the repository, because the thing being checked is that
the generator raises: an exit 9 record given an unrecognised detail string, and a
receiptless archive moved into the exit 9 set. Those are
test_an_unaccountable_record_stops_the_generator and
test_e3_membership_claims_are_checked.

It measures once, at module scope, and the measurement is the real one: two
verifier subprocesses per archive, about twenty seconds for the published set.
A fixture would be faster and would prove nothing, because the figures are
published as a statement about what the shipped tools report.
"""

import copy
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools/archive_verification_report.py"


def _generator():
    spec = importlib.util.spec_from_file_location("archive_verification_report", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = _generator()
RECORDS = REPORT.measure(ROOT / "proofs/runs")
FIGURES = REPORT.build_figures(RECORDS, ROOT / "proofs/runs")
REGIONS = REPORT.rendered_regions(FIGURES)

# Sentences that name a figure and are about a measurement that has already
# happened. A past measurement must not be rewritten by a later one, so these
# are prose on purpose and are listed here so the guard below can tell them from
# a figure someone retyped.
HISTORICAL_SENTENCES = (
    "41 archives from exit 9 to exit 0",
    "39 of them at that measurement",
    "taking the total from 290 to 292",
    "ledgers of 152, 8 and 6 rows",
    "E6 was two runs stale",
)


def test_the_generator_owns_regions_in_every_published_surface():
    """Guard the guard. An empty region map satisfies everything below."""
    assert set(REGIONS) == {"docs/archive-errata.md", "docs/claims-register.md", "README.md"}
    assert sum(len(names) for names in REGIONS.values()) >= 14
    for document, names in REGIONS.items():
        assert names, document
        for name, body in names.items():
            assert body.strip(), f"{document}:{name} renders nothing"


@pytest.mark.parametrize(
    ("document", "name"),
    [(document, name) for document, names in REGIONS.items() for name in names],
)
def test_every_region_the_generator_owns_is_present(document, name):
    text = (ROOT / document).read_text(encoding="utf-8")
    begin = REPORT.REGION_BEGIN.format(name=name)
    end = REPORT.REGION_END.format(name=name)

    assert text.count(begin) == 1, f"{document} does not open the {name!r} region exactly once"
    assert text.count(end) == 1, f"{document} does not close the {name!r} region exactly once"
    assert text.index(begin) < text.index(end)


@pytest.mark.parametrize(
    ("document", "name"),
    [(document, name) for document, names in REGIONS.items() for name in names],
)
def test_every_region_matches_fresh_output(document, name):
    """The published figure is the figure this archive produces, right now."""
    published = REPORT.read_region((ROOT / document).read_text(encoding="utf-8"), name)

    assert published == REGIONS[document][name], (
        f"{document}:{name} differs from fresh generator output. Run\n"
        "  python3 tools/archive_verification_report.py --update-published-surfaces\n"
        "rather than editing the figure in the document, which the next "
        "publication would overwrite."
    )


@pytest.mark.parametrize("document", sorted(REGIONS))
def test_no_document_carries_an_unowned_region(document):
    """A region with no renderer is a figure nothing keeps current."""
    text = (ROOT / document).read_text(encoding="utf-8")
    found = set(re.findall(r"BEGIN GENERATED ARCHIVE FIGURES: ([^\s]+) -->", text))

    assert found == set(REGIONS[document]), (
        f"{document} carries regions the generator does not own: "
        f"{sorted(found - set(REGIONS[document]))}"
    )


def test_an_unaccountable_record_stops_the_generator():
    """A decomposition that silently drops a case publishes a smaller archive.

    The buckets are keyed off the verifiers' own messages. If one of those
    changes, the arithmetic still adds up to something, and the something is
    wrong. This asserts the generator refuses rather than publishing it.
    """
    mutated = copy.deepcopy(RECORDS)
    victim = next(r for r in mutated if r["certificate_exit"] == 9)
    victim["certificate_detail"] = "NOT CHECKED: for a reason this script has never seen"

    with pytest.raises(REPORT.FigureError) as raised:
        REPORT.build_figures(mutated, ROOT / "proofs/runs")

    assert "does not account for every record" in str(raised.value)
    assert victim["run_id"] in str(raised.value)


def test_a_receipt_failure_with_an_unknown_cause_stops_the_generator():
    mutated = copy.deepcopy(RECORDS)
    victim = next(r for r in mutated if r["receipt_exit"] == 2)
    victim["receipt_detail"] = "ERROR: something new"

    with pytest.raises(REPORT.FigureError):
        REPORT.build_figures(mutated, ROOT / "proofs/runs")


def test_e3_membership_claims_are_checked():
    """E3 asserts two things about sets. Both are verified when it is written.

    The published paragraph said these archives were among E4's and they were
    not. The replacement states where they actually are, so the claim is now
    checked at generation time rather than left to be read and believed.
    """
    mutated = copy.deepcopy(FIGURES)
    mutated["exit_9_no_row_count"] = sorted(
        set(mutated["exit_9_no_row_count"]) | {mutated["legacy_no_receipt"][0]}
    )

    with pytest.raises(REPORT.FigureError) as raised:
        REPORT.render_e3_effect(mutated)
    assert "not among E4's and some are" in str(raised.value)

    mutated = copy.deepcopy(FIGURES)
    mutated["ships_no_ledger"] = [
        run for run in mutated["ships_no_ledger"] if run != mutated["legacy_no_receipt"][0]
    ]

    with pytest.raises(REPORT.FigureError) as raised:
        REPORT.render_e3_effect(mutated)
    assert "ships no ledger" in str(raised.value)


def test_regeneration_is_idempotent():
    """Publication must not touch a document whose figures have not moved.

    A generator that rewrites unconditionally puts every document in every proof
    pull request, which buries a real figure change in noise.
    """
    assert REPORT.update_published_surfaces(FIGURES, dry_run=True) == [], (
        "the published surfaces do not match this archive. Run\n"
        "  python3 tools/archive_verification_report.py --update-published-surfaces"
    )


@pytest.mark.parametrize(
    ("document", "figure"),
    [
        (document, figure)
        for document in ("docs/archive-errata.md", "docs/claims-register.md")
        for figure in ("total", "incomplete", "legacy_no_receipt")
    ],
)
def test_live_figures_do_not_appear_outside_a_region(document, figure):
    """A figure retyped into prose is the defect this whole change removes."""
    text = (ROOT / document).read_text(encoding="utf-8")
    for name in REGIONS[document]:
        begin = REPORT.REGION_BEGIN.format(name=name)
        end = REPORT.REGION_END.format(name=name)
        head, _, rest = text.partition(begin)
        _, _, tail = rest.partition(end)
        text = head + tail
    for sentence in HISTORICAL_SENTENCES:
        text = text.replace(sentence, "")
    # Run identifiers are hex and routinely contain a figure's digits:
    # `20260405-040324-000000-2c99d5f16574` holds 99. Inline code is not prose,
    # so it is removed before the search rather than matched around.
    text = re.sub(r"`[^`]*`", "", text)

    value = FIGURES[figure] if figure == "total" else len(FIGURES[figure])
    stray = re.findall(rf"(?<![\d.]){value}(?![\d.%])", text)

    assert not stray, (
        f"{document} states {value} outside every generated region. Either put the "
        "sentence in a region, or, if it describes a measurement that has already "
        "happened, add it to HISTORICAL_SENTENCES in this file and say so in the "
        "document."
    )
