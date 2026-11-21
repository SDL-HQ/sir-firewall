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

Since 21 November 2026 one of those two cases is gone. A document naming a
key the registry does not have is refused before any key is tried, by all
three verifiers, as a check that could not be performed; and so is any
document where no registry can be read. What a public key file is still a
candidate for is a certificate naming no key, and that is the case held here.

Breaking this: return None from `key_registry.key_file_refusal`, or drop the
call from `key_registry.refusal_after_signature`.
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


def test_with_no_registry_the_question_cannot_be_asked(key, tmp_path):
    # Until 21 November 2026 both of these were answered None, "not refused".
    private, _, _, _ = key
    unreadable = tmp_path / "unreadable.json"
    unreadable.write_text("{ not json", encoding="utf-8")
    for registry in (tmp_path / "absent.json", unreadable):
        with pytest.raises(RegistryKeyUnreadable, match="key registry could not be read"):
            key_file_refusal(registry, private.public_key(), None, None, "sha256:" + "0" * 64)


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


def test_with_no_registry_a_certificate_naming_no_key_is_refused(key, tmp_path):
    # On 19 November this was a pass with a warning, and exit 1 under
    # --require-registry. It is one answer now, with or without the flag, and
    # there is no flag that turns it back into a pass.
    _, private_pem, _, key_file = key
    document = _resigned(_published(CERTIFICATE), private_pem)
    absent = tmp_path / "absent.json"
    unreadable = tmp_path / "unreadable.json"
    unreadable.write_text("{ not json", encoding="utf-8")

    for registry, state in ((absent, "unavailable"), (unreadable, "unreadable")):
        for flags in ((), ("--require-registry",)):
            refused = _certificate(tmp_path, document, key_file, registry, *flags)
            assert refused.returncode == CHECK_NOT_PERFORMED, refused.stderr
            assert f"key registry {state}" in refused.stderr and "nothing about this document was verified" in refused.stderr
            assert "OK" not in refused.stdout


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


def test_a_receipt_naming_a_key_the_registry_lacks_is_not_verified_against_a_file(key, tmp_path):
    # Until 21 November 2026 typing --pubkey verified such a receipt against
    # the file, with a warning, and this test held that route to the registry.
    # The route is gone. Whatever the registry says about the key in the file,
    # and whether or not the file is typed, the receipt names a key the
    # registry does not have and nothing is checked against anything.
    private, _, public, key_file = key
    archive, receipt_hash = _receipt_archive(tmp_path, "published", private)
    registries = (
        _registry(tmp_path, "not-held"),
        _registry(tmp_path, "active", public, status="active"),
        _registry(tmp_path, "revoked", public, **REVOKED, **{ANCHORED_FIELD: [receipt_hash]}),
    )
    for registry in registries:
        for argv in (("--pubkey", key_file), ()):
            refused = _run("verify_archive_receipt.py", archive, *argv, "--key-registry", registry)
            assert refused.returncode == CHECK_NOT_PERFORMED, refused.stderr
            assert f"signing_key_id not found in key registry: {A_NAME_THE_REGISTRY_LACKS}" in refused.stderr
            assert "OK" not in refused.stdout


def test_a_baseline_record_naming_a_key_the_registry_lacks_is_not_verified_against_a_file(key, tmp_path):
    # Until 21 November 2026 such a record was verified against the public key
    # file, typed or default, and until 19 November without a word.
    _, private_pem, public, key_file = key
    record = _resigned(_published(BASELINE), private_pem, A_NAME_THE_REGISTRY_LACKS)
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    registries = (
        _registry(tmp_path, "not-held"),
        _registry(tmp_path, "active", public, status="active"),
        _registry(tmp_path, "revoked", public, **REVOKED, **{ANCHORED_FIELD: [payload_hash(record)]}),
    )
    for registry in registries:
        for argv in (("--pubkey", key_file), (), ("--require-registry",)):
            refused = _run("verify_baseline_record.py", path, *argv, "--key-registry", registry, "--no-ledger")
            assert refused.returncode == CHECK_NOT_PERFORMED, refused.stderr
            assert f"signing_key_id not found in key registry: {A_NAME_THE_REGISTRY_LACKS}" in refused.stderr
            assert "OK" not in refused.stdout
