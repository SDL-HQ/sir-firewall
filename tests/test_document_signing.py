"""One signing scheme, and the published archive is what pins it.

Two kinds of signed document exist from SIR 2.5: the audit certificate and the
ungated baseline record. They are signed the same way, and the scheme was
written out twice before tools/document_signing.py existed.

The property that matters is not that the module is tidy. It is that the scheme
it implements is the scheme 305 published certificates were signed under. The
payload is the document's fields in their own order, not sorted, and a reader
rebuilds it from the parsed file. Normalising that order would be the obvious
tidy-up and would invalidate every published signature, so the archive is the
test: every archived certificate's payload hash is recomputed through this
module and must match what was published.

Checked on 15 October 2026 against three mutations of a scratch copy, never the
repository. Each count is what pytest reported:

    1. payload sorted by key                               2 failed
    2. ensure_ascii left at its default                     2 failed
    3. the two unsigned fields folded into the payload      4 failed

and the restored copy passed 7 of 7.

Mutation 1 is the one worth recording. It is invisible to
tests/test_baseline_record.py, which passed 24 of 24 under it: a record signed
and verified through the same sorted payload round-trips perfectly, because
both sides changed together. The archive is what refuses it. That is the same
shape as the digest mapping in tests/test_baseline_rows_are_not_gate_verdicts.py,
and the same lesson: a scheme checked only against itself is not checked.
"""

import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import document_signing  # noqa: E402

ARCHIVED = sorted((ROOT / "proofs/runs").glob("*/audit.json"))


def test_there_are_archived_certificates_to_check_against():
    """Guard the guard: an empty archive makes the test below vacuous."""
    assert len(ARCHIVED) > 300, len(ARCHIVED)


def test_every_archived_certificate_payload_hash_is_reproduced():
    """The scheme, held against what was published rather than against itself."""
    mismatched = []
    for path in ARCHIVED:
        certificate = json.loads(path.read_text(encoding="utf-8"))
        if "payload_hash" not in certificate:
            continue
        if document_signing.payload_hash(certificate) != certificate["payload_hash"]:
            mismatched.append(path.parent.name)

    assert not mismatched, mismatched[:5]


def test_the_payload_excludes_exactly_the_two_unsigned_fields():
    document = {"a": 1, "payload_hash": "x", "signature": "y", "b": 2}
    assert json.loads(document_signing.signing_payload(document)) == {"a": 1, "b": 2}
    assert document_signing.UNSIGNED_FIELDS == ("signature", "payload_hash")


def test_the_payload_keeps_the_document_order():
    """Not sorted. A verifier rebuilds this from the parsed file, which carries
    the order the file was written in."""
    assert document_signing.signing_payload({"b": 1, "a": 2}) == b'{"b":1,"a":2}'


def test_non_ascii_is_not_escaped():
    """ensure_ascii=False is part of the scheme, and a document with a non-ASCII
    field would sign differently under the default."""
    assert document_signing.signing_payload({"note": "café"}) == '{"note":"café"}'.encode("utf-8")


def test_a_signed_document_verifies_under_its_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    signed = document_signing.sign_document({"kind": "test", "n": 1}, pem)

    assert signed["payload_hash"] == document_signing.payload_hash(signed)
    key.public_key().verify(
        base64.b64decode(signed["signature"]),
        document_signing.signing_payload(signed),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert list(signed)[-2:] == ["payload_hash", "signature"], (
        "the two fields are appended last, which is the order every published "
        "certificate carries"
    )


def test_resigning_a_signed_document_is_stable():
    """Signing a document that already carries the two fields must not fold them
    into the payload."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    once = document_signing.sign_document({"kind": "test"}, pem)
    twice = document_signing.sign_document(once, pem)

    assert document_signing.signing_payload(once) == document_signing.signing_payload(twice)
    assert once["payload_hash"] == twice["payload_hash"]
