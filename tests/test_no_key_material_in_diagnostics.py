"""No key material reaches a diagnostic, and the diagnostic still says why.

CodeQL raises py/clear-text-logging-sensitive-data on the revocation failure
messages. Its source, in all three alerts, is the identifier
`last_trusted_run_id`: the rule classifies sensitive data by name, and that
name matches its "secret" pattern. The value is a continuous integration run
identifier, published in plaintext in spec/pubkeys/key_registry.v1.json and in
the directory name of every archive under proofs/runs/.

That makes the alerts false positives, but "false positive" is an assertion.
These tests make it a resolved question, in both directions:

  - no field of a registry entry that could carry key material can appear in a
    reason string, on any failure path;
  - every failure path still produces a reason, so a later change that silences
    the diagnostic to appease the scanner fails here instead of shipping.

The second half matters because the suggested remediation on the alert was to
delete the reason from the message, which would remove the only thing that
tells a consumer why exit code 10 fired.
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "key_registry_under_test", ROOT / "tools/key_registry.py"
)
assert _spec is not None and _spec.loader is not None
KR = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(KR)

# Values a reason string must never contain. Distinctive so a substring match
# is meaningful.
SECRET_PEM = "-----BEGIN PUBLIC KEY-----SENTINELKEYMATERIAL-----END PUBLIC KEY-----"
SECRET_B64 = "U0VOVElORUxCQVNFNjRLRVlNQVRFUklBTA=="

ANCHOR = "20261002-030936-161538-gh36958888228-3c39599f5009"


def _entry(**overrides):
    entry = {
        "key_id": "test-key",
        "status": "revoked",
        "revoked_utc": "2026-10-06T00:00:00Z",
        "last_trusted_run_id": ANCHOR,
        "pubkey_pem": SECRET_PEM,
        "pubkey_base64": SECRET_B64,
    }
    entry.update(overrides)
    return entry


# Every failure path through revocation_allows_proof, named by what it rejects.
FAILURE_PATHS = {
    "missing revoked_utc": (
        _entry(revoked_utc=None), "2026-10-05T00:00:00Z", "x-gh1-y",
    ),
    "no anchor": (
        _entry(last_trusted_run_id=None), "2026-10-05T00:00:00Z", "x-gh1-y",
    ),
    "unparseable proof run id": (
        _entry(), "2026-10-05T00:00:00Z", "no-run-number-here",
    ),
    "run after the anchor": (
        _entry(), "2026-10-05T00:00:00Z", "x-gh99999999999-y",
    ),
    "timestamp at or after revocation": (
        _entry(), "2026-10-07T00:00:00Z", "x-gh1-y",
    ),
}


@pytest.mark.parametrize("name", sorted(FAILURE_PATHS))
def test_no_key_material_reaches_a_revocation_reason(name):
    entry, timestamp, run_id = FAILURE_PATHS[name]
    allowed, reason = KR.revocation_allows_proof(entry, timestamp, run_id)
    assert not allowed, f"{name} should have been refused"
    assert SECRET_PEM not in reason
    assert SECRET_B64 not in reason
    assert "BEGIN PUBLIC KEY" not in reason
    assert "BEGIN PRIVATE KEY" not in reason


@pytest.mark.parametrize("name", sorted(FAILURE_PATHS))
def test_every_refusal_still_explains_itself(name):
    """The counterweight. Exit code 10 exists so a consumer can tell revocation
    apart from a bad signature; the reason is what tells them which revocation
    rule fired. Silencing it is not an acceptable way to clear a scanner."""
    entry, timestamp, run_id = FAILURE_PATHS[name]
    allowed, reason = KR.revocation_allows_proof(entry, timestamp, run_id)
    assert not allowed
    assert isinstance(reason, str) and len(reason.strip()) >= 20, (
        f"the {name} path gives no usable reason"
    )


def test_an_allowed_proof_carries_no_reason_at_all():
    entry, timestamp, run_id = _entry(), "2026-10-05T00:00:00Z", "x-gh1-y"
    allowed, reason = KR.revocation_allows_proof(entry, timestamp, run_id)
    assert allowed
    assert reason is None


def test_the_flagged_value_is_published_in_the_repository():
    """The whole basis for dismissing the alerts: the value CodeQL calls a
    secret is committed in plaintext and served from the public site."""
    registry = (ROOT / "spec/pubkeys/key_registry.v1.json").read_text(encoding="utf-8")
    assert "last_trusted_run_id" in registry
    assert ANCHOR in registry, (
        "the anchor this test reasons about is no longer in the published "
        "registry; re-check whether the dismissal rationale still holds"
    )
