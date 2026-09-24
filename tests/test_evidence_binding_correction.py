from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_published_historical_census_is_frozen():
    """Prevent accidental drift in the release's closed-set disclosure."""
    disclosure = (ROOT / "docs/evidence-binding-correction.md").read_text(encoding="utf-8")

    normalized = " ".join(disclosure.split())
    assert "closed set of 29 in-scope certificates" in normalized
    assert "closed set of 295 certificates predates the 2.2.0 applicability" in normalized
    assert "reported with the distinct not-applicable exit code" in normalized
    assert "these are not current-contract failures" in normalized
