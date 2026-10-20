"""The id a signature claims must name the key that made it.

Every signer used to read SDL_SIGNING_KEY_ID and fall back to "default" when
it was unset, and nothing ever compared the id to the key. That is how the
archive acquired six certificates naming a key nobody published: 2048-bit
signatures from a key absent from the registry, stamped "default", which stay
published because removing them would destroy the evidence.

The id cannot be computed from key material, because a registry id is a label.
So it is still named by the environment and then checked: the registry entry
it names must hold the public key belonging to the private key in hand.

What each test catches, measured by breaking the code rather than asserted:

- restore the `or "default"` fallback in any signer: the no-fallback test fails.
- drop the registry lookup: the unknown-id test fails.
- drop the public-key comparison: the wrong-key test fails, and that is the
  one the six certificates needed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "key_registry_under_test", ROOT / "tools" / "key_registry.py"
)
key_registry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(key_registry)


def _pair():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public = k.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private, public


@pytest.fixture
def signing(tmp_path, monkeypatch):
    private, public = _pair()
    other_private, _ = _pair()
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps({"keys": [{"key_id": "k-1", "pubkey_pem": public, "status": "approved"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv(key_registry.SIGNING_REGISTRY_ENV, str(registry))
    return private, other_private


def test_an_unset_key_id_signs_nothing(signing, monkeypatch):
    private, _ = signing
    monkeypatch.delenv(key_registry.SIGNING_KEY_ID_ENV, raising=False)
    with pytest.raises(key_registry.SigningKeyError) as raised:
        key_registry.resolve_signing_key_id(private)
    assert "not set" in str(raised.value)


def test_an_id_the_registry_does_not_hold_signs_nothing(signing, monkeypatch):
    private, _ = signing
    monkeypatch.setenv(key_registry.SIGNING_KEY_ID_ENV, "k-absent")
    with pytest.raises(key_registry.SigningKeyError) as raised:
        key_registry.resolve_signing_key_id(private)
    assert "identifies no key" in str(raised.value)


def test_an_id_naming_a_different_key_signs_nothing(signing, monkeypatch):
    """The defect the six published certificates carry, in one assertion."""
    _, other_private = signing
    monkeypatch.setenv(key_registry.SIGNING_KEY_ID_ENV, "k-1")
    with pytest.raises(key_registry.SigningKeyError) as raised:
        key_registry.resolve_signing_key_id(other_private)
    assert "different public key" in str(raised.value)


def test_an_id_that_names_the_signing_key_resolves(signing, monkeypatch):
    private, _ = signing
    monkeypatch.setenv(key_registry.SIGNING_KEY_ID_ENV, "k-1")
    assert key_registry.resolve_signing_key_id(private) == "k-1"


def test_no_signer_keeps_its_own_fallback():
    """Read out of the sources, because the point is that none of the four
    has its own copy of the rule."""
    for relative in (
        "tools/generate_certificate.py",
        "tools/generate_baseline_record.py",
        "tools/sign_policy.py",
        "tools/sign_isc.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "resolve_signing_key_id" in source, relative
        assert '"SDL_SIGNING_KEY_ID") or "default"' not in source, relative


def test_the_real_policy_signer_refuses_a_mismatched_id(tmp_path, signing):
    """Not the function in isolation: the signer, run as a process, as CI runs
    it. A check that only holds when called directly is not the check."""
    private, other_private = signing
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy/isc_policy.json").write_text(
        json.dumps({"version": "1.0", "rules": []}), encoding="utf-8"
    )
    env = dict(os.environ)
    env["SDL_PRIVATE_KEY_PEM"] = other_private
    env["SDL_SIGNING_KEY_ID"] = "k-1"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/sign_policy.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "different public key" in (result.stderr + result.stdout)
    assert not (tmp_path / "policy/isc_policy.signed.json").exists(), (
        "the signer wrote a signed policy despite refusing the key id"
    )
