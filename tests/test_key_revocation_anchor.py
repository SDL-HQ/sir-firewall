"""Revoking a leaked signing key must actually contain it.

Before the anchor, revocation compared the certificate's own ``timestamp_utc``
against ``revoked_utc``. That field sits inside the signed payload, so it cannot
be edited after signing -- but anyone holding the private key can mint a fresh
certificate carrying any timestamp they like, which is precisely the party
revocation exists to stop. These tests pin the anchored behaviour and keep the
original defect from returning.
"""

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from key_registry import revocation_allows_proof, run_number_from_run_id  # noqa: E402

VERIFIER = REPO / "tools" / "verify_certificate.py"
REVOCATION_FAILURE = 10

ANCHOR_RUN = "20261001-233607-533569-gh36941637986-2ac75a57d439"
LATER_RUN = "20261003-101500-100000-gh36999999999-aaaaaaaaaaaa"
REVOKED_UTC = "2026-10-06T00:00:00Z"


def _entry(**overrides):
    entry = {
        "key_id": "k",
        "status": "revoked",
        "revoked_utc": REVOKED_UTC,
        "last_trusted_run_id": ANCHOR_RUN,
    }
    entry.update(overrides)
    return entry


def test_run_number_comes_from_the_run_identifier():
    assert run_number_from_run_id(ANCHOR_RUN) == 36941637986
    assert run_number_from_run_id("no-run-number-here") is None
    assert run_number_from_run_id(None) is None


def test_active_key_is_unaffected():
    allowed, _ = revocation_allows_proof({"status": "active"}, None, None)
    assert allowed


def test_revoked_without_an_anchor_fails_closed():
    allowed, reason = revocation_allows_proof(
        _entry(last_trusted_run_id=None), "2026-09-30T00:00:00Z", ANCHOR_RUN
    )
    assert not allowed
    assert "anchor" in reason


def test_proof_without_a_run_id_fails_closed():
    allowed, reason = revocation_allows_proof(_entry(), "2026-09-30T00:00:00Z", None)
    assert not allowed
    assert "run_id" in reason


def test_run_after_the_anchor_is_refused():
    allowed, reason = revocation_allows_proof(_entry(), "2026-09-30T00:00:00Z", LATER_RUN)
    assert not allowed
    assert "after the last trusted run" in reason


def test_run_at_or_below_the_anchor_is_honoured():
    allowed, reason = revocation_allows_proof(_entry(), "2026-09-30T00:00:00Z", ANCHOR_RUN)
    assert allowed and reason is None


def test_timestamp_can_only_tighten_never_substitute():
    """A run within the anchor but stamped after revocation is still refused."""
    allowed, reason = revocation_allows_proof(_entry(), "2026-10-07T00:00:00Z", ANCHOR_RUN)
    assert not allowed
    assert "revoked_utc" in reason


def test_backdating_no_longer_defeats_revocation():
    """The original defect: a holder of the key chose an earlier timestamp.

    The timestamp is now powerless on its own, because the run identifier is
    assigned by the forge rather than by the signer.
    """
    allowed, reason = revocation_allows_proof(_entry(), "2020-01-01T00:00:00Z", LATER_RUN)
    assert not allowed
    assert "after the last trusted run" in reason


# --- end to end through the real verifier ----------------------------------


@pytest.fixture(scope="module")
def keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pem


def _template():
    path = REPO / "proofs" / "runs" / ANCHOR_RUN / "audit.json"
    if not path.is_file():
        pytest.skip(f"template archive not present: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _mint(priv, tmp_path, *, run_id, timestamp_utc, key_id="k"):
    """Sign a certificate exactly as a holder of the private key would."""
    cert = _template()
    cert["signing_key_id"] = key_id
    cert["run_id"] = run_id
    cert["timestamp_utc"] = timestamp_utc
    cert.pop("signature", None)
    cert.pop("payload_hash", None)
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    cert["signature"] = base64.b64encode(
        priv.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    out = tmp_path / f"cert-{run_number_from_run_id(run_id)}-{timestamp_utc[:10]}.json"
    out.write_text(json.dumps(cert, indent=2), encoding="utf-8")
    return out


def _registry(pem, tmp_path, name, **overrides):
    entry = {"key_id": "k", "pubkey_pem": pem, "created_utc": "2026-01-01T00:00:00Z",
             "valid_from_utc": "2026-01-01T00:00:00Z", "status": "active",
             "revocation_reason": ""}
    entry.update(overrides)
    path = tmp_path / f"registry-{name}.json"
    path.write_text(json.dumps({"version": "v1", "keys": [entry]}), encoding="utf-8")
    return path


def _verify(cert, registry):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(cert), "--no-ledger",
         "--require-registry", "--key-registry", str(registry)],
        capture_output=True, text=True, cwd=REPO,
    )


def test_end_to_end_active_key_verifies(keypair, tmp_path):
    priv, pem = keypair
    cert = _mint(priv, tmp_path, run_id=LATER_RUN, timestamp_utc="2026-10-06T09:00:00Z")
    assert _verify(cert, _registry(pem, tmp_path, "active")).returncode == 0


def test_end_to_end_backdated_certificate_from_a_revoked_key_is_refused(keypair, tmp_path):
    """The reproduction from 6 October, now failing as it should."""
    priv, pem = keypair
    revoked = _registry(
        pem, tmp_path, "revoked", status="revoked", revoked_utc=REVOKED_UTC,
        revocation_reason="private key disclosed", last_trusted_run_id=ANCHOR_RUN,
    )
    backdated = _mint(priv, tmp_path, run_id=LATER_RUN, timestamp_utc="2026-09-30T09:00:00Z")
    result = _verify(backdated, revoked)
    assert result.returncode == REVOCATION_FAILURE, result.stderr
    assert "after the last trusted run" in result.stderr


def test_end_to_end_genuine_pre_revocation_certificate_still_verifies(keypair, tmp_path):
    """Revocation must not retroactively destroy honestly signed history."""
    priv, pem = keypair
    revoked = _registry(
        pem, tmp_path, "revoked", status="revoked", revoked_utc=REVOKED_UTC,
        revocation_reason="private key disclosed", last_trusted_run_id=ANCHOR_RUN,
    )
    genuine = _mint(priv, tmp_path, run_id=ANCHOR_RUN, timestamp_utc="2026-10-01T23:36:07Z")
    assert _verify(genuine, revoked).returncode == 0


# --- the registry must not weaken over time --------------------------------


def test_no_rotation_may_weaken_the_signing_key():
    """A key ceremony is an improvement or it is not worth doing.

    The first signing key was 4096-bit. rotate_keys.py originally hardcoded 2048,
    so running it silently halved the strength of the thing the whole evidence
    claim rests on. This refuses that, and refuses any future active key weaker
    than one it replaced.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    registry = json.loads(
        (REPO / "spec" / "pubkeys" / "key_registry.v1.json").read_text(encoding="utf-8")
    )
    sizes = {
        entry["key_id"]: (
            entry.get("status"),
            load_pem_public_key(entry["pubkey_pem"].encode()).key_size,
        )
        for entry in registry["keys"]
    }
    assert sizes, "key registry carries no keys"

    strongest_retired = max(
        (size for status, size in sizes.values() if status != "active"), default=0
    )
    for key_id, (status, size) in sizes.items():
        if status != "active":
            continue
        assert size >= 4096, f"active key {key_id} is {size}-bit, below the 4096 minimum"
        assert size >= strongest_retired, (
            f"active key {key_id} is {size}-bit, weaker than a retired key "
            f"at {strongest_retired}-bit"
        )
