"""A key that reaches a verifier from a public key file is held to the registry entry that holds it.

A key reaches a verifier two ways: the registry is asked for the entry a
document names, or a public key file is read. Until 19 November 2026 the
registry's rules were applied on the first way only. A document naming no key,
or a key the registry does not have, was verified against the file, and
neither a revocation nor the anchored set was asked anything. Measured with a
key a scratch registry marks revoked and a public key file that still holds it:
a certificate, a receipt and a baseline record signed after the revocation
each verified at exit 0.

The id a document states is the signer's to write. The key that verified the
signature is not, so after the signature verifies the registry is asked whether
it holds that key, by the key.

Breaking this: return None from `key_registry.key_file_refusal`, or drop the
call from a verifier.
"""

import base64
import copy
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

from document_signing import payload_hash, sign_document  # noqa: E402
from key_registry import (  # noqa: E402
    ANCHORED_FIELD,
    RegistryKeyUnreadable,
    entries_holding,
    key_file_refusal,
    load_registry,
)

REGISTRY = REPO / "spec" / "pubkeys" / "key_registry.v1.json"
CERTIFICATE = REPO / "docs" / "runs" / "20261026-114228-317580-gh40317017323-d8bd37b6606d" / "audit.json"
BASELINE = REPO / "docs" / "runs" / "20261015-092557-107124-gh38712792514-670d9d4222c2" / "baseline.json"
KEY_NOT_HONOURED = 10
CHECK_NOT_PERFORMED = 6
A_NAME_THE_REGISTRY_LACKS = "a-name-the-registry-does-not-have"
REVOKED = {"status": "revoked", "revoked_utc": "2026-10-06T00:00:00Z"}


@pytest.fixture(scope="module")
def key(tmp_path_factory):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    key_file = tmp_path_factory.mktemp("key") / "their.pub"
    key_file.write_text(public, encoding="utf-8")
    return private, pem, public, key_file


def _registry(tmp_path, name, public=None, **fields):
    """The committed registry, plus an entry holding the test's key when one is given."""
    registry = copy.deepcopy(load_registry(REGISTRY))
    if public is not None:
        registry["keys"].append({"key_id": "gone", "pubkey_pem": public, "created_utc": "2025-01-01T00:00:00Z",
                                 "valid_from_utc": "2025-01-01T00:00:00Z", "revocation_reason": "", **fields})
    path = tmp_path / f"registry-{name}.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    return path


def _resigned(published, private_pem, key_id=None, **changes):
    document = {k: v for k, v in published.items() if k not in ("signature", "payload_hash", "signing_key_id")}
    if key_id:
        document["signing_key_id"] = key_id
    document.update(changes)
    return sign_document(document, private_pem)


def _published(path):
    if not path.is_file():
        pytest.skip(f"published document not present: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _run(tool, *argv):
    return subprocess.run([sys.executable, str(REPO / "tools" / tool), *map(str, argv)], capture_output=True, text=True, cwd=REPO)


# --- the rule ------------------------------------------------------------------


def test_the_registry_is_asked_by_the_key_and_not_by_a_name(key, tmp_path):
    private, _, public, _ = key
    held = entries_holding(_registry(tmp_path, "held", public, **REVOKED), private.public_key())
    assert [entry["key_id"] for entry in held] == ["gone"]
    assert entries_holding(_registry(tmp_path, "not-held"), private.public_key()) == []


def test_the_committed_public_key_file_holds_the_active_key():
    # So nothing published is decided differently: the file's key is an entry, and the entry is active.
    public_key = serialization.load_pem_public_key((REPO / "spec" / "sdl.pub").read_bytes())
    held = entries_holding(REGISTRY, public_key)
    assert [entry["status"] for entry in held] == ["active"]
    assert key_file_refusal(REGISTRY, public_key, None, None, "sha256:" + "0" * 64) is None


def test_a_key_no_entry_holds_is_not_the_registrys_to_refuse(key, tmp_path):
    private, _, _, _ = key
    assert key_file_refusal(_registry(tmp_path, "not-held"), private.public_key(), None, None, "sha256:" + "0" * 64) is None


def test_with_no_registry_there_is_nothing_to_hold_the_key_to(key, tmp_path):
    # Not closed here. The verifiers say so in a warning.
    private, _, _, _ = key
    assert key_file_refusal(tmp_path / "absent.json", private.public_key(), None, None, "sha256:" + "0" * 64) is None


def test_an_entry_whose_key_cannot_be_read_is_not_read_as_an_entry_that_does_not_hold_it(key, tmp_path):
    private, _, _, _ = key
    registry = copy.deepcopy(load_registry(REGISTRY))
    registry["keys"].append({"key_id": "unreadable", "pubkey_pem": "not a key", "status": "revoked"})
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(RegistryKeyUnreadable):
        key_file_refusal(path, private.public_key(), None, None, "sha256:" + "0" * 64)


def test_a_key_held_twice_is_refused_if_either_entry_refuses(key, tmp_path):
    private, _, public, _ = key
    registry = copy.deepcopy(load_registry(REGISTRY))
    registry["keys"].append({"key_id": "in-use", "pubkey_pem": public, "status": "active"})
    registry["keys"].append({"key_id": "gone", "pubkey_pem": public, **REVOKED, ANCHORED_FIELD: []})
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    assert "revoked" in key_file_refusal(path, private.public_key(), None, None, "sha256:" + "0" * 64)


# --- end to end, through each verifier ------------------------------------------------


def _certificate(tmp_path, document, key_file, registry, *extra):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return _run("verify_certificate.py", path, "--pubkey", key_file, "--key-registry", registry, "--no-ledger", *extra)


def test_a_certificate_naming_no_key(key, tmp_path):
    _, private_pem, public, key_file = key
    published = _published(CERTIFICATE)
    old = _resigned(published, private_pem)
    new = _resigned(published, private_pem, timestamp_utc="2026-11-19T00:00:00Z")
    anchored = {ANCHORED_FIELD: [payload_hash(old)]}

    for name, fields in (("revoked", {**REVOKED, **anchored}), ("retired", {"status": "retired", **anchored})):
        registry = _registry(tmp_path, name, public, **fields)
        refused = _certificate(tmp_path, new, key_file, registry)
        assert refused.returncode == KEY_NOT_HONOURED, refused.stderr
        assert "key-file verification failure" in refused.stderr and f"is {name}" in refused.stderr
        assert _certificate(tmp_path, old, key_file, registry).returncode == 0

    # A revoked key the registry anchors nothing for is decided by the rule it always had, which it never reached.
    refused = _certificate(tmp_path, new, key_file, _registry(tmp_path, "no-set", public, **REVOKED))
    assert refused.returncode == KEY_NOT_HONOURED and "key_id='gone'" in refused.stderr

    # A key the registry holds as active, and a reader's own key beside the approved registry, verify as before.
    assert _certificate(tmp_path, new, key_file, _registry(tmp_path, "active", public, status="active")).returncode == 0
    own = _certificate(tmp_path, new, key_file, _registry(tmp_path, "not-held"))
    assert own.returncode == 0 and f"--pubkey {key_file}" in own.stdout


def test_a_certificate_and_a_registry_entry_that_cannot_be_read(key, tmp_path):
    _, private_pem, _, key_file = key
    registry = copy.deepcopy(load_registry(REGISTRY))
    registry["keys"].append({"key_id": "unreadable", "pubkey_pem": "not a key", "status": "revoked"})
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    result = _certificate(tmp_path, _resigned(_published(CERTIFICATE), private_pem), key_file, path)
    assert result.returncode == CHECK_NOT_PERFORMED and "could not be established" in result.stderr


def test_with_no_registry_a_certificate_naming_no_key_is_said_to_be_unchecked_or_is_refused(key, tmp_path):
    _, private_pem, _, key_file = key
    document = _resigned(_published(CERTIFICATE), private_pem)
    absent = tmp_path / "absent.json"
    fallback = _certificate(tmp_path, document, key_file, absent)
    assert fallback.returncode == 0
    assert "WARNING: certificate names no signing_key_id and key registry unavailable" in fallback.stderr
    # --require-registry is documented as the flag that fails closed and does not accept the fallback.
    required = _certificate(tmp_path, document, key_file, absent, "--require-registry")
    assert required.returncode == 1 and "key registry unavailable" in required.stderr

    unreadable = tmp_path / "unreadable.json"
    unreadable.write_text("{ not json", encoding="utf-8")
    assert "key registry unreadable" in _certificate(tmp_path, document, key_file, unreadable).stderr
    assert _certificate(tmp_path, document, key_file, unreadable, "--require-registry").returncode == 1


def _receipt_archive(tmp_path, name, private):
    canonical = lambda d: json.dumps(d, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")  # noqa: E731
    sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()  # noqa: E731
    archive = tmp_path / name
    archive.mkdir()
    body = f"a file of {name}\n".encode()
    (archive / "a.txt").write_bytes(body)
    manifest = {"files": [{"path": "a.txt", "sha256": sha(body), "size_bytes": len(body)}]}
    (archive / "manifest.json").write_text(json.dumps(manifest))
    receipt = {"run_id": "20260101-000000-000000-gh1-000000000000", "repository": "test", "commit_sha": "0" * 40, "ci_run_url": "none",
               "manifest_hash": sha(canonical(manifest)), "run_folder_hash": sha(f"a.txt:{sha(body)}".encode()),
               "timestamp_utc": "2026-01-01T00:00:00Z", "signing_key_id": A_NAME_THE_REGISTRY_LACKS}
    payload = canonical(receipt)
    receipt["payload_hash"] = sha(payload)
    receipt["signature"] = base64.b64encode(private.sign(payload, padding.PKCS1v15(), hashes.SHA256())).decode()
    (archive / "archive_receipt.json").write_text(json.dumps(receipt))
    return archive, receipt["payload_hash"]


def test_a_receipt_naming_a_key_the_registry_lacks(key, tmp_path):
    private, _, public, key_file = key
    published, published_hash = _receipt_archive(tmp_path, "published", private)
    later, _ = _receipt_archive(tmp_path, "later", private)
    registry = _registry(tmp_path, "revoked", public, **REVOKED, **{ANCHORED_FIELD: [published_hash]})
    assert _run("verify_archive_receipt.py", published, "--pubkey", key_file, "--key-registry", registry).returncode == 0
    refused = _run("verify_archive_receipt.py", later, "--pubkey", key_file, "--key-registry", registry)
    assert refused.returncode == 2 and "key-file verification failure" in refused.stderr
    own = _run("verify_archive_receipt.py", later, "--pubkey", key_file, "--key-registry", _registry(tmp_path, "not-held"))
    assert own.returncode == 0


def test_a_baseline_record_naming_a_key_the_registry_lacks(key, tmp_path):
    _, private_pem, public, key_file = key
    published = _published(BASELINE)
    old = _resigned(published, private_pem, A_NAME_THE_REGISTRY_LACKS)
    new = _resigned(published, private_pem, A_NAME_THE_REGISTRY_LACKS, timestamp_utc="2026-11-19T00:00:00Z")

    def verify(document, registry):
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return _run("verify_baseline_record.py", path, "--pubkey", key_file, "--key-registry", registry, "--no-ledger")

    registry = _registry(tmp_path, "revoked", public, **REVOKED, **{ANCHORED_FIELD: [payload_hash(old)]})
    assert verify(old, registry).returncode == 0
    refused = verify(new, registry)
    assert refused.returncode == KEY_NOT_HONOURED and "key-file verification failure" in refused.stderr
    assert verify(new, _registry(tmp_path, "not-held")).returncode == 0

    # With no registry the record is verified against the file, and that is now said.
    fallback = verify(new, tmp_path / "absent.json")
    assert fallback.returncode == 0 and "WARNING: signing_key_id present but key registry unavailable" in fallback.stderr
