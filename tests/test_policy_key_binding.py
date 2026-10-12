"""The signed policy names its signing key, and that name is itself signed.

Before 7 October 2026 policy/isc_policy.signed.json carried only payload,
payload_hash and signature. There was no key identity, so verify_policy could
only check against whatever spec/sdl.pub happened to be: no registry lookup, no
status check, nothing to revoke. generate_certificate.py refuses to sign when
verify_policy fails, so this artefact gates every other signature the project
produces, and it was the least bound of all of them.
"""

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = _load("verify_policy_under_test", "tools/verify_policy.py")
SIGN = _load("sign_policy_under_test", "tools/sign_policy.py")

POLICY = {"version": "test-1", "rules": {"max_friction": 1200}}


@pytest.fixture
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pub_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _registry(tmp_path: Path, entries) -> Path:
    path = tmp_path / "key_registry.v1.json"
    path.write_text(json.dumps({"version": "v1", "keys": entries}), encoding="utf-8")
    return path


def _entry(key_id: str, private_key, status: str = "active") -> dict:
    return {
        "key_id": key_id,
        "pubkey_pem": _pub_pem(private_key),
        "status": status,
        "created_utc": "2026-01-01T00:00:00Z",
        "valid_from_utc": "2026-01-01T00:00:00Z",
    }


def _sign(tmp_path: Path, private_key, key_id: str, policy=None) -> tuple[Path, Path]:
    """Produce a signed policy in the documented format."""
    policy = POLICY if policy is None else policy
    payload = SIGN.canonical_payload(policy)
    payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    signature = private_key.sign(
        SIGN.signing_input(SIGN.SIGNATURE_SCHEMA, key_id, payload_hash),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signed_path = tmp_path / "signed.json"
    signed_path.write_text(json.dumps({
        "schema": SIGN.SIGNATURE_SCHEMA,
        "key_id": key_id,
        "payload": policy,
        "payload_hash": payload_hash,
        "signature": base64.b64encode(signature).decode("ascii"),
    }), encoding="utf-8")
    enforced_path = tmp_path / "enforced.json"
    enforced_path.write_text(json.dumps(policy), encoding="utf-8")
    return signed_path, enforced_path


def test_signer_and_verifier_agree_end_to_end(tmp_path, key):
    """The real signer, run as it runs in CI, produces something the real
    verifier accepts. This is the test that stops the two drifting apart."""
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy/isc_policy.json").write_text(json.dumps(POLICY), encoding="utf-8")

    env = dict(os.environ)
    env["SDL_PRIVATE_KEY_PEM"] = private_pem = private_key_pem(key)
    env["SDL_SIGNING_KEY_ID"] = "test-key-1"
    assert private_pem.startswith("-----BEGIN")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/sign_policy.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    signed = json.loads((tmp_path / "policy/isc_policy.signed.json").read_text())
    assert signed["key_id"] == "test-key-1"
    assert signed["schema"] == SIGN.SIGNATURE_SCHEMA

    registry = _registry(tmp_path, [_entry("test-key-1", key)])
    ok, detail = VERIFY.verify_policy(
        tmp_path / "policy/isc_policy.signed.json",
        tmp_path / "policy/isc_policy.json",
        registry,
    )
    assert ok, detail
    assert "test-key-1" in detail


def private_key_pem(private_key) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def test_a_legacy_unidentified_signature_is_refused(tmp_path, key):
    """The pre-7-October shape: no schema, no key_id. It must not pass, because
    nothing in it says which key signed it."""
    signed_path, enforced_path = _sign(tmp_path, key, "test-key-1")
    signed = json.loads(signed_path.read_text())
    del signed["schema"]
    del signed["key_id"]
    signed_path.write_text(json.dumps(signed), encoding="utf-8")

    ok, detail = VERIFY.verify_policy(
        signed_path, enforced_path, _registry(tmp_path, [_entry("test-key-1", key)])
    )
    assert not ok
    assert "no schema and no key identity" in detail


def test_a_key_absent_from_the_registry_is_refused(tmp_path, key):
    signed_path, enforced_path = _sign(tmp_path, key, "not-registered")
    ok, detail = VERIFY.verify_policy(
        signed_path, enforced_path, _registry(tmp_path, [_entry("test-key-1", key)])
    )
    assert not ok
    assert "not in the key registry" in detail


def test_a_retired_key_cannot_gate_certificate_generation(tmp_path, key):
    """This is the case that went red on 6 October: the committed policy was
    signed by a key the rotation had just retired."""
    signed_path, enforced_path = _sign(tmp_path, key, "old-key")
    ok, detail = VERIFY.verify_policy(
        signed_path,
        enforced_path,
        _registry(tmp_path, [_entry("old-key", key, status="retired")]),
    )
    assert not ok
    assert "not active" in detail


def test_the_key_id_is_inside_the_signature(tmp_path, key):
    """Repointing key_id at another active registry entry must fail. If the id
    were merely recorded beside the signature this would succeed whenever the
    two keys were the same, and the binding would be decorative."""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed_path, enforced_path = _sign(tmp_path, key, "test-key-1")
    signed = json.loads(signed_path.read_text())
    signed["key_id"] = "test-key-2"
    signed_path.write_text(json.dumps(signed), encoding="utf-8")

    registry = _registry(
        tmp_path, [_entry("test-key-1", key), _entry("test-key-2", other)]
    )
    ok, detail = VERIFY.verify_policy(signed_path, enforced_path, registry)
    assert not ok
    assert "signature verification failed" in detail


def test_the_key_id_is_bound_even_when_the_same_key_is_claimed_twice(tmp_path, key):
    """The sharper version: the same key registered under two ids. The
    signature must still refuse the wrong id, which it can only do if the id
    is inside the signed bytes."""
    signed_path, enforced_path = _sign(tmp_path, key, "test-key-1")
    signed = json.loads(signed_path.read_text())
    signed["key_id"] = "test-key-1-alias"
    signed_path.write_text(json.dumps(signed), encoding="utf-8")

    registry = _registry(
        tmp_path, [_entry("test-key-1", key), _entry("test-key-1-alias", key)]
    )
    ok, detail = VERIFY.verify_policy(signed_path, enforced_path, registry)
    assert not ok
    assert "signature verification failed" in detail


def test_a_swapped_payload_is_refused(tmp_path, key):
    signed_path, enforced_path = _sign(tmp_path, key, "test-key-1")
    signed = json.loads(signed_path.read_text())
    signed["payload"] = {"version": "swapped", "rules": {}}
    signed_path.write_text(json.dumps(signed), encoding="utf-8")
    enforced_path.write_text(json.dumps(signed["payload"]), encoding="utf-8")

    ok, detail = VERIFY.verify_policy(
        signed_path, enforced_path, _registry(tmp_path, [_entry("test-key-1", key)])
    )
    assert not ok
    assert "payload_hash mismatch" in detail


def test_runtime_drift_is_still_caught_before_any_key_work(tmp_path, key):
    signed_path, enforced_path = _sign(tmp_path, key, "test-key-1")
    enforced = json.loads(enforced_path.read_text())
    enforced["version"] = "drifted"
    enforced_path.write_text(json.dumps(enforced), encoding="utf-8")

    ok, detail = VERIFY.verify_policy(
        signed_path, enforced_path, _registry(tmp_path, [_entry("test-key-1", key)])
    )
    assert not ok
    assert "differs" in detail


def test_the_signer_defaults_to_the_same_key_id_as_the_certificate_generator():
    """Both read SDL_SIGNING_KEY_ID and both fall back to "default". A rotation
    that moved one and not the other would stamp mismatched identities."""
    generator = (ROOT / "tools/generate_certificate.py").read_text(encoding="utf-8")
    assert 'os.getenv("SDL_SIGNING_KEY_ID")' in generator
    assert 'os.getenv("SDL_SIGNING_KEY_ID")' in (
        ROOT / "tools/sign_policy.py"
    ).read_text(encoding="utf-8")
