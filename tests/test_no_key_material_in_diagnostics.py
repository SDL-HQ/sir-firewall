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


# --- the refusal path a certificate with no signing_key_id reaches -----------
#
# Added 8 October 2026 with the implicit-key resolution in
# verify_certificate.py. 43 published certificates carry no signing_key_id and
# are resolved as IMPLICIT_KEY_ID, so they acquire a revocation path they did
# not have before: previously they fell through to a bare public key file, which
# enforces no revocation at all. That is the point of the change, and it means
# there is a new exit 10 with a new reason string, which nothing tested.
#
# CodeQL flagged the print at that call site as clear-text logging of a secret,
# the fourth instance of the alert traced and dismissed on 7 October. The basis
# is unchanged and is asserted above: the value it calls a secret is
# last_trusted_run_id, committed in plaintext in the registry. These tests cover
# the new path in both directions, so the dismissal rests on a test rather than
# on the argument alone.


def _revoked_registry(tmp_path, key_id="default"):
    """A registry whose implicit entry is revoked, with a real key in it."""
    import base64 as _base64
    import json as _json

    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        _serialization.Encoding.PEM, _serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    path = tmp_path / "registry.json"
    path.write_text(_json.dumps({
        "version": "v1",
        "keys": [{
            "key_id": key_id,
            "pubkey_pem": pem,
            "status": "revoked",
            "created_utc": "2026-01-01T00:00:00Z",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "revoked_utc": "2026-10-06T00:00:00Z",
            "last_trusted_run_id": ANCHOR,
        }],
    }), encoding="utf-8")
    return key, path, pem


def _keyless_certificate(tmp_path, key, run_id="20260405-040322-000000-aed41b22e195"):
    """A certificate naming no signing_key_id, as 43 published ones do."""
    import base64 as _base64
    import hashlib as _hashlib
    import json as _json

    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding

    cert = {
        "sir_firewall_version": ".".join(("1", "0", "2")),
        "run_id": run_id,
        "timestamp_utc": "2026-04-05T04:03:22Z",
        "detached_ledger": True,
        "prompts_tested": 1,
    }
    payload = _json.dumps(cert, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cert["payload_hash"] = "sha256:" + _hashlib.sha256(payload).hexdigest()
    cert["signature"] = _base64.b64encode(
        key.sign(payload, _padding.PKCS1v15(), _hashes.SHA256())
    ).decode("ascii")
    path = tmp_path / "audit.json"
    path.write_text(_json.dumps(cert), encoding="utf-8")
    return path


def _verify(cert_path, registry_path, pubkey_path):
    import subprocess
    import sys as _sys

    return subprocess.run(
        [_sys.executable, str(ROOT / "tools/verify_certificate.py"), str(cert_path),
         "--no-ledger", "--key-registry", str(registry_path), "--pubkey", str(pubkey_path)],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )


def test_a_keyless_certificate_is_refused_when_the_implicit_key_is_revoked(tmp_path):
    """The new rule's whole point.

    Before 8 October a certificate with no signing_key_id was checked against a
    bare public key file, so revoking the key it was signed with refused the 249
    certificates that name it and none of the 43 that do not. Resolving the
    absent field as IMPLICIT_KEY_ID brings those 43 under the same rule.
    """
    key, registry, pem = _revoked_registry(tmp_path)
    pubkey = tmp_path / "pub.pem"
    pubkey.write_text(pem, encoding="utf-8")
    cert = _keyless_certificate(tmp_path, key)

    result = _verify(cert, registry, pubkey)

    assert result.returncode == 10, result.stdout + result.stderr
    assert "revoked-key verification failure" in result.stderr


def test_that_refusal_explains_which_rule_fired(tmp_path):
    """The counterweight, as above. Exit 10 tells a consumer that revocation
    refused the archive; the reason tells them why. The suggested remediation
    for the CodeQL alert is to delete the reason, which would make the scanner
    green by removing the only thing that distinguishes one refusal from
    another."""
    key, registry, pem = _revoked_registry(tmp_path)
    pubkey = tmp_path / "pub.pem"
    pubkey.write_text(pem, encoding="utf-8")
    cert = _keyless_certificate(tmp_path, key)

    stderr = _verify(cert, registry, pubkey).stderr

    assert "carries no" in stderr and "signing_key_id" in stderr, (
        "the refusal must say that the key id was implied rather than named"
    )
    assert len(stderr.strip()) >= 80, stderr


def test_no_key_material_reaches_that_refusal(tmp_path):
    """The direction CodeQL is worried about, at the new call site."""
    key, registry, pem = _revoked_registry(tmp_path)
    pubkey = tmp_path / "pub.pem"
    pubkey.write_text(pem, encoding="utf-8")
    cert = _keyless_certificate(tmp_path, key)

    output = _verify(cert, registry, pubkey)
    combined = output.stdout + output.stderr

    assert "BEGIN PUBLIC KEY" not in combined
    assert "BEGIN PRIVATE KEY" not in combined
    for line in pem.splitlines():
        if line and "-----" not in line:
            assert line not in combined, "a line of key material reached the output"


def test_an_unrevoked_implicit_key_still_verifies(tmp_path):
    """The refusal must be the revocation, not the resolution.

    If this fails, resolving an absent field through the registry has broken the
    43 certificates it exists to fix.
    """
    import json as _json

    key, registry, pem = _revoked_registry(tmp_path)
    entry = _json.loads(registry.read_text(encoding="utf-8"))
    entry["keys"][0]["status"] = "retired"
    entry["keys"][0].pop("revoked_utc")
    registry.write_text(_json.dumps(entry), encoding="utf-8")
    pubkey = tmp_path / "pub.pem"
    pubkey.write_text(pem, encoding="utf-8")
    cert = _keyless_certificate(tmp_path, key)

    result = _verify(cert, registry, pubkey)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "carries no signing_key_id" in result.stdout
