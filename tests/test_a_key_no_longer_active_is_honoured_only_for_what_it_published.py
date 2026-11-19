"""A key that is retired or revoked is honoured for the documents it published, and for nothing it signs afterwards.

Until 19 November 2026 a retired key was honoured exactly as an active one.
The registry recorded an end date and a last trusted run for it and nothing
read either: `revocation_allows_proof` returned "allowed" for every status but
`revoked`. Measured on the committed registry's own `default` entry: a document
dated that day, with a run number above the recorded last trusted run, was
allowed. Revoking instead was not free, because the revoked rule reads the run
number a document states and 268 published certificates state none.

Both of those limits are values the signer writes. The anchored set is not: the
registry lists the payload hash of every published document the key signed,
derived from the archive, and a key that is no longer active is honoured for
those and no others. The hash looked up is the one the verifier computes after
the signature has verified, never the one the document states.

Breaking this: return None from `key_registry.anchored_set_refusal`, or drop
the call from a verifier.
"""

import base64
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

import anchor_published_set  # noqa: E402
from document_signing import payload_hash, sign_document  # noqa: E402
from key_registry import (  # noqa: E402
    ANCHORED_FIELD,
    anchored_set_refusal,
    load_registry,
    revocation_allows_proof,
)

REGISTRY = REPO / "spec" / "pubkeys" / "key_registry.v1.json"
CERTIFICATE_RUN = "20261026-114228-317580-gh40317017323-d8bd37b6606d"
BASELINE_RUN = "20261015-092557-107124-gh38712792514-670d9d4222c2"
KEY_NOT_HONOURED = 10


# --- the rule ------------------------------------------------------------------


def _entry(**fields):
    return {"key_id": "k", "status": "retired", ANCHORED_FIELD: ["sha256:" + "a" * 64], **fields}


def test_a_listed_hash_is_honoured_and_any_other_is_not():
    assert anchored_set_refusal(_entry(), "sha256:" + "a" * 64) is None
    reason = anchored_set_refusal(_entry(), "sha256:" + "b" * 64)
    assert reason and "retired" in reason and "1 document(s)" in reason


def test_the_set_decides_for_a_revoked_key_too():
    revoked = _entry(status="revoked", revoked_utc="2026-10-06T00:00:00Z")
    assert anchored_set_refusal(revoked, "sha256:" + "a" * 64) is None
    assert "revoked" in anchored_set_refusal(revoked, "sha256:" + "b" * 64)


def test_an_active_key_is_not_held_to_a_set():
    assert anchored_set_refusal(_entry(status="active"), "sha256:" + "b" * 64) is None


def test_a_key_with_no_set_is_not_decided_here():
    assert anchored_set_refusal({"key_id": "k", "status": "retired"}, "sha256:" + "b" * 64) is None


@pytest.mark.parametrize("malformed", [None, "sha256:" + "a" * 64, {"sha256:" + "a" * 64: True}, [1, 2]])
def test_a_set_that_is_not_a_list_of_hashes_fails_closed(malformed):
    assert "fail closed" in anchored_set_refusal(_entry(**{ANCHORED_FIELD: malformed}), "sha256:" + "a" * 64)


def test_an_empty_set_honours_nothing():
    assert anchored_set_refusal(_entry(**{ANCHORED_FIELD: []}), "sha256:" + "a" * 64)


def test_a_verifier_that_does_not_apply_the_set_cannot_honour_the_key():
    # The earlier rule defers to the set only for a caller that says the later check follows.
    allowed, reason = revocation_allows_proof(_entry(), "2026-01-01T00:00:00Z", None)
    assert not allowed and "does not apply" in reason
    assert revocation_allows_proof(_entry(), "2026-01-01T00:00:00Z", None, anchored_check_follows=True) == (True, None)


# --- the committed registry ------------------------------------------------------


def test_every_key_that_is_not_active_is_anchored_to_exactly_what_it_published():
    """Recorded == derived, for every retired or revoked key, over the published archive.

    One more anchored than published would be a hash honoured for a document
    nobody can read. One fewer would refuse a document SDL published.
    """
    assert anchor_published_set.check(load_registry(REGISTRY), [REPO / "docs", REPO / "proofs"]) == []


def test_the_rule_on_the_committed_default_key():
    default = next(k for k in load_registry(REGISTRY)["keys"] if k["key_id"] == "default")
    assert default["status"] != "active"
    published = json.loads((REPO / "docs" / "runs" / "20261002-030936-161538-gh36958888228-3c39599f5009" / "audit.json").read_text())
    assert anchored_set_refusal(default, payload_hash(published)) is None
    signed_today = dict(published, timestamp_utc="2026-11-19T00:00:00Z")
    assert anchored_set_refusal(default, payload_hash(signed_today))


# --- end to end, through each verifier, with a key of the test's own ----------------


@pytest.fixture(scope="module")
def key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private, pem, public


def _registry(tmp_path, name, public, **fields):
    registry = copy.deepcopy(load_registry(REGISTRY))
    registry["keys"].append({"key_id": "retired-test-key", "pubkey_pem": public, "created_utc": "2025-01-01T00:00:00Z",
                             "valid_from_utc": "2025-01-01T00:00:00Z", "revocation_reason": "", "status": "retired", **fields})
    path = tmp_path / f"registry-{name}.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    return path


def _resigned(published, private_pem, **changes):
    document = {k: v for k, v in published.items() if k not in ("signature", "payload_hash")}
    document["signing_key_id"] = "retired-test-key"
    document.update(changes)
    return sign_document(document, private_pem)


def _archive(tmp_path, run):
    source = REPO / "docs" / "runs" / run
    if not source.is_dir():
        pytest.skip(f"published archive not present: {source}")
    archive = tmp_path / "archive"
    if not archive.exists():
        shutil.copytree(source, archive)
        for descriptor in ("manifest.json", "archive_receipt.json"):
            (archive / descriptor).unlink()
    return archive


def _run(tool, *argv):
    return subprocess.run([sys.executable, str(REPO / "tools" / tool), *map(str, argv)], capture_output=True, text=True, cwd=REPO)


def _certificate(archive, document, registry):
    (archive / "audit.json").write_text(json.dumps(document), encoding="utf-8")
    return _run("verify_certificate.py", archive / "audit.json", "--key-registry", registry, "--require-registry",
                "--ledger", archive / "proofs" / "itgl_ledger.jsonl")


def test_a_certificate_signed_after_retirement_is_refused_and_the_published_one_is_not(key, tmp_path):
    _, private_pem, public = key
    archive = _archive(tmp_path, CERTIFICATE_RUN)
    published = json.loads((archive / "audit.json").read_text())
    old = _resigned(published, private_pem)
    new = _resigned(published, private_pem, timestamp_utc="2026-11-19T00:00:00Z")

    no_set = _registry(tmp_path, "no-set", public)
    anchored = _registry(tmp_path, "anchored", public, **{ANCHORED_FIELD: [payload_hash(old)]})
    revoked = _registry(tmp_path, "revoked", public, status="revoked", revoked_utc="2026-10-06T00:00:00Z",
                        **{ANCHORED_FIELD: [payload_hash(old)]})

    # A key with no set is honoured as before. `anchor_published_set.py --check` is what reports that state.
    assert _certificate(archive, new, no_set).returncode == 0

    assert _certificate(archive, old, anchored).returncode == 0
    refused = _certificate(archive, new, anchored)
    assert refused.returncode == KEY_NOT_HONOURED, refused.stderr
    assert "retired-key verification failure" in refused.stderr and "is not among them" in refused.stderr

    # The hash looked up is the computed one. Stating the anchored document's hash gets a hash mismatch, not trust.
    stating = dict(new, payload_hash=old["payload_hash"])
    assert _certificate(archive, stating, anchored).returncode == 3

    # Revoked with a set: the published document is still honoured, with no run-number rule consulted,
    # and the new one is still refused.
    assert _certificate(archive, old, revoked).returncode == 0
    refused = _certificate(archive, new, revoked)
    assert refused.returncode == KEY_NOT_HONOURED and "revoked-key verification failure" in refused.stderr


def test_a_tampered_certificate_keeps_its_own_answer(key, tmp_path):
    # The set is consulted after the signature, so a document nobody signed is still reported as that.
    _, private_pem, public = key
    archive = _archive(tmp_path, CERTIFICATE_RUN)
    old = _resigned(json.loads((archive / "audit.json").read_text()), private_pem)
    anchored = _registry(tmp_path, "anchored", public, **{ANCHORED_FIELD: [payload_hash(old)]})
    altered = dict(old, model="another")
    assert _certificate(archive, altered, anchored).returncode == 3
    rehashed = dict(altered, payload_hash=payload_hash(altered))
    assert _certificate(archive, rehashed, anchored).returncode == 5


def test_the_one_command_reports_the_refusal_as_signing_trust(key, tmp_path):
    _, private_pem, public = key
    archive = _archive(tmp_path, CERTIFICATE_RUN)
    published = json.loads((archive / "audit.json").read_text())
    old = _resigned(published, private_pem)
    anchored = _registry(tmp_path, "anchored", public, **{ANCHORED_FIELD: [payload_hash(old)]})
    (archive / "audit.json").write_text(json.dumps(_resigned(published, private_pem, timestamp_utc="2026-11-19T00:00:00Z")))
    result = _run("verify_evidence.py", archive, "--key-registry", anchored, "--json")
    properties = {p["property"]: p for p in json.loads(result.stdout)["properties"]}
    assert result.returncode == 2
    assert properties["signing trust"]["state"] == "failed"
    assert properties["certificate"]["state"] == "failed"


def test_a_baseline_record_signed_after_retirement_is_refused(key, tmp_path):
    _, private_pem, public = key
    archive = _archive(tmp_path, BASELINE_RUN)
    published = json.loads((archive / "baseline.json").read_text())
    old = _resigned(published, private_pem)
    new = _resigned(published, private_pem, timestamp_utc="2026-11-19T00:00:00Z")
    anchored = _registry(tmp_path, "anchored", public, **{ANCHORED_FIELD: [payload_hash(old)]})

    def verify(document):
        (archive / "baseline.json").write_text(json.dumps(document), encoding="utf-8")
        return _run("verify_baseline_record.py", archive / "baseline.json", "--key-registry", anchored, "--require-registry", "--no-ledger")

    assert verify(old).returncode == 0, verify(old).stderr
    refused = verify(new)
    assert refused.returncode == KEY_NOT_HONOURED and "retired-key verification failure" in refused.stderr


def _receipt_archive(tmp_path, name, private, run_id):
    canonical = lambda d: json.dumps(d, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")  # noqa: E731
    sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()  # noqa: E731
    archive = tmp_path / name
    archive.mkdir()
    body = f"a file of {name}\n".encode()
    (archive / "a.txt").write_bytes(body)
    manifest = {"files": [{"path": "a.txt", "sha256": sha(body), "size_bytes": len(body)}]}
    (archive / "manifest.json").write_text(json.dumps(manifest))
    receipt = {"run_id": run_id, "repository": "test", "commit_sha": "0" * 40, "ci_run_url": "none", "manifest_hash": sha(canonical(manifest)),
               "run_folder_hash": sha(f"a.txt:{sha(body)}".encode()), "timestamp_utc": "2026-01-01T00:00:00Z", "signing_key_id": "retired-test-key"}
    payload = canonical(receipt)
    receipt["payload_hash"] = sha(payload)
    receipt["signature"] = base64.b64encode(private.sign(payload, padding.PKCS1v15(), hashes.SHA256())).decode()
    (archive / "archive_receipt.json").write_text(json.dumps(receipt))
    return archive, receipt["payload_hash"]


def test_a_receipt_signed_after_retirement_is_refused_whatever_run_it_states(key, tmp_path):
    private, _, public = key
    published, published_hash = _receipt_archive(tmp_path, "published", private, "20260101-000000-000000-gh1-000000000000")
    # States a run number below any anchor and a January date: the two things a signer can write.
    later, _ = _receipt_archive(tmp_path, "later", private, "20260101-000000-000000-gh1-000000000000")
    anchored = _registry(tmp_path, "anchored", public, last_trusted_run_id="20261002-030936-161538-gh36958888228-3c39599f5009",
                         **{ANCHORED_FIELD: [published_hash]})
    assert _run("verify_archive_receipt.py", published, "--key-registry", anchored, "--require-registry").returncode == 0
    refused = _run("verify_archive_receipt.py", later, "--key-registry", anchored, "--require-registry")
    assert refused.returncode == 2 and "retired-key verification failure" in refused.stderr


# --- the set is derived when the key is retired ---------------------------------------


def test_rotation_anchors_the_key_it_retires(key, tmp_path, monkeypatch):
    private, private_pem, public = key
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"version": "v1", "keys": [
        {"key_id": "in-use", "pubkey_pem": public, "created_utc": "2026-01-01T00:00:00Z", "valid_from_utc": "2026-01-01T00:00:00Z",
         "status": "active", "revocation_reason": ""}]}))
    published = tmp_path / "published" / "runs" / "20260101-000000-000000-gh1-000000000000"
    published.mkdir(parents=True)
    document = sign_document({"run_id": published.name, "signing_key_id": "in-use", "timestamp_utc": "2026-01-01T00:00:00Z"}, private_pem)
    (published / "audit.json").write_text(json.dumps(document))
    someone_elses = sign_document({"run_id": "x", "signing_key_id": "another", "timestamp_utc": "2026-01-01T00:00:00Z"}, private_pem)
    (published / "other.json").write_text(json.dumps(someone_elses))

    spec = importlib.util.spec_from_file_location("rotate_keys", REPO / "tools" / "rotate_keys.py")
    rotate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rotate)
    monkeypatch.setattr(sys, "argv", ["rotate_keys.py", "--registry", str(registry), "--current-pub", str(tmp_path / "current.pub"),
                                      "--pubkey-dir", str(tmp_path / "pubkeys"), "--private-out", str(tmp_path / "private.pem"),
                                      "--archive-root", str(tmp_path / "published" / "runs"), "--published-root", str(tmp_path / "published"),
                                      "--key-id", "next"])
    assert rotate.main() == 0
    retired = next(k for k in json.loads(registry.read_text())["keys"] if k["key_id"] == "in-use")
    assert retired["status"] == "retired" and retired[ANCHORED_FIELD] == [payload_hash(document)]
