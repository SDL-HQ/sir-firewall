"""The claim that makes an old wrong denominator latent, held against the archive.

`derive_counters` in tools/itgl.py carries a comment explaining why the
false-positive rate's former denominator was latent rather than wrong in
practice. Until 17 October 2026 that comment gave a false reason: it said no
suite had ever produced a harmless block. Two published certificates do, both
from 18 April 2026, with 24 and 23 harmless blocks over 50 prompts and no
leaks each.

The real reason is that `content_false_positive_rate` has never been published
with a value at all, so the divisor never reached a published figure. That is a
claim about the archive, which means it can stop being true without anyone
noticing, which is how the false reason survived in the first place.

These two tests exist so it cannot. They are deliberately not a prohibition: a
run that genuinely publishes a rate would be an improvement, not a regression.
What they forbid is the comment and the archive disagreeing in silence. If the
first fails, publishing a rate has begun, and the comment in itgl.py must stop
saying it never was.

No figure is asserted here either. The counts live in the archive and are
derived with tools/archive_verification_report.py; a number in a test rots the
same way a number in a comment does.

Measured by breaking each one, counts as observed:

    rate claim inverted                         1 failed
    over-blocking evidence filtered out         1 failed
    archive path pointed at nothing             2 failed

The last is the reason the first test is not alone. With no certificates to
read, "no certificate publishes a rate" is vacuously true and passes; only the
guard-the-guard test notices that nothing was checked. That is the same rule
this project applies to verification itself: a property nobody could check is
not a property that holds.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "docs" / "runs"


def _certificates():
    """Every published audit certificate, by its run directory.

    Baseline records declare `record_kind` and carry no gate counters at all,
    so they are not certificates and have no rate to publish.
    """
    for path in sorted(RUNS.glob("*/audit.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(document, dict) or "record_kind" in document:
            continue
        yield path.parent.name, document


def test_there_are_certificates_to_check():
    """Guard the guard: a path change must not make the two below vacuous."""
    assert sum(1 for _ in _certificates()) > 100


def test_no_published_certificate_carries_a_false_positive_rate():
    """The reason the old denominator never produced a published figure.

    A failure here is not necessarily a defect. It means a run has published a
    rate, and the comment in tools/itgl.py that says none ever has is now
    stale: correct the comment rather than this test.
    """
    published = [
        (run, document.get("content_false_positive_rate"))
        for run, document in _certificates()
        if document.get("content_false_positive_rate") is not None
    ]
    assert not published, (
        "content_false_positive_rate is now published on "
        f"{len(published)} certificate(s), e.g. {published[:3]}. The comment in "
        "tools/itgl.py explaining why the former denominator was latent says "
        "the rate reached no published certificate. Update it."
    )


def test_harmless_blocks_are_published_so_the_old_reason_stays_dead():
    """The premise that was false, asserted so it cannot be restated.

    Someone reading the comment may be tempted to restore the simpler claim
    that no run ever over-blocked. It did. This fails if that stops being
    demonstrable from the archive, which would mean the correcting evidence
    has gone and the comment needs rewriting again.
    """
    over_blocking = [
        (run, document.get("harmless_blocked"), document.get("jailbreaks_leaked"))
        for run, document in _certificates()
        if (document.get("harmless_blocked") or 0) > 0
    ]
    assert over_blocking, (
        "no published certificate carries a harmless block any more, so the "
        "comment in tools/itgl.py citing published over-blocking runs no "
        "longer has its evidence in the archive"
    )
    # And at least one of them leaked nothing, which is what makes it the
    # over-blocking direction rather than a run that failed for both reasons.
    assert any(
        (leaked or 0) == 0 for _run, _blocked, leaked in over_blocking
    ), "every over-blocking run also leaked, so the two directions are no longer distinguishable here"
