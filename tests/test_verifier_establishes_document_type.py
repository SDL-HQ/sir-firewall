"""The certificate verifier says what a document is before it says it verified.

Until 15 October 2026 tools/verify_certificate.py checked a signature and a
payload hash and reported on whatever it was handed. A published
archive_receipt.json therefore passed it at exit 0 under
`--no-ledger --require-registry`: a real signature over a real document,
reported as a verified certificate. The receipt records which files an archive
contains. It says nothing about a gate run, so nothing in that verdict was true
beyond the signature.

A signature establishes who wrote a document. It never establishes what the
document is, and this tool's exit 0 is read as a statement about an audit. That
gap is the one the 2.5 baseline record would widen: a second signed document
type, signed by the same key, in the same archive.

Found by an independent review on 14 October 2026 and reproduced against the
published archive used below.

Where the two checks sit is itself a decision. A foreign declaration
(`record_kind`) is refused before the signature is looked at. The identifying
fields are checked after the signature verifies, because the published negative
example `tampered-required-field-removed.json` is a real certificate with
`prompts_tested` stripped and the signature untouched: calling that "not a
certificate" would be the wrong account of a document that was signed as one,
and the payload hash gives the sharper one. Both checks sit above every success
path, which is the property that matters.

Checked on 15 October 2026 against four mutations of a scratch copy, never the
repository. Each count is what pytest reported:

    1. remove the identity check                           6 failed
    2. remove the record_kind check                         1 failed
    3. identity check first, before the signature           1 failed
    4. identity check after ledger binding                  2 failed

and the restored copy passed 11 of 11. Mutation 3 is the one worth noting: it
passes every assertion about the receipt and about real certificates, and is
caught only by the published tampered fixture, whose documented exit code it
changes.
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

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "verify_certificate.py"

# The published archive whose receipt this verifier used to accept. Chosen
# because it is real: a signature this tool verifies, over a document that is
# not a certificate.
RECEIPT = (
    ROOT
    / "proofs/runs/20260403-042349-000000-gh23933677730-ef03803fc756/archive_receipt.json"
)
CERTIFICATE = ROOT / "proofs/latest-audit.json"

NOT_A_CERTIFICATE = 12


def _verify(path, *extra):
    completed = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *extra],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def _streams(path, *extra):
    completed = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *extra],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _write(tmp_path, payload):
    path = tmp_path / "document.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _signed(tmp_path, payload, name="document.json"):
    """A document signed the way a certificate is, under an ephemeral key.

    The identity check runs after signature verification, so a document with an
    invalid signature never reaches it. These fixtures therefore have to be
    properly signed, which also makes them the case that matters: a real
    signature over a document that is not a certificate.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = {k: v for k, v in payload.items() if k not in ("signature", "payload_hash")}
    blob = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    body["payload_hash"] = "sha256:" + hashlib.sha256(blob).hexdigest()
    body["signature"] = base64.b64encode(
        key.sign(blob, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")

    document = tmp_path / name
    document.write_text(json.dumps(body), encoding="utf-8")
    pubkey = tmp_path / "key.pub"
    pubkey.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return document, pubkey


def test_the_published_receipt_is_still_a_valid_signed_document():
    """Guard the guard: the case is only interesting while the signature verifies.

    If this archive's receipt stopped verifying, the test below would pass
    because the document was broken rather than because the verifier refused
    its type.
    """
    code, output = _verify(RECEIPT, "--no-ledger", "--require-registry")
    assert code == NOT_A_CERTIFICATE, output

    receipt_verifier = ROOT / "tools" / "verify_archive_receipt.py"
    completed = subprocess.run(
        [sys.executable, str(receipt_verifier), str(RECEIPT.parent), "--require-registry"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("ledger_flag", [("--no-ledger",), ()])
def test_an_archive_receipt_is_not_a_certificate(ledger_flag):
    """Refused on every path, not only where a ledger was supplied.

    --no-ledger is the path that returned 0. A check placed after ledger
    resolution would leave it exactly as it was.
    """
    code, output = _verify(RECEIPT, *ledger_flag, "--require-registry")

    assert code == NOT_A_CERTIFICATE, output
    assert "not a SIR audit certificate" in output
    assert "No audit is described here" in output, (
        "the receipt's signature does verify, so the message has to say what "
        "that does and does not establish rather than leave a reader with a "
        "verified signature and no statement about the document"
    )


def test_nothing_is_reported_as_verified():
    """The refusal goes to stderr, and stdout carries no success line.

    This verifier's success output is an `OK:` line on stdout, which is what a
    caller greps and what the workflow prints. A document of the wrong type
    must produce none of it.
    """
    code, stdout, stderr = _streams(RECEIPT, "--no-ledger", "--require-registry")

    assert code == NOT_A_CERTIFICATE
    assert "OK" not in stdout, stdout
    assert stdout.strip() == "", stdout
    assert "not a SIR audit certificate" in stderr, stderr


def test_a_baseline_record_is_refused_by_its_declaration(tmp_path):
    """The 2.5 record type, refused before it exists, and before its signature.

    The fields are a certificate's on purpose. A record that declares itself is
    refused on the declaration alone, so this does not depend on the identity
    set, and the document is deliberately left unsigned to show the refusal
    happens first.
    """
    path = _write(
        tmp_path,
        {
            "record_kind": "sir_ungated_baseline",
            "result": "AUDIT PASSED",
            "prompts_tested": 150,
            "payload_hash": "sha256:" + "0" * 64,
            "signature": "",
        },
    )

    code, output = _verify(path, "--no-ledger")
    assert code == NOT_A_CERTIFICATE, output
    assert "record_kind" in output
    assert "signature verification" not in output, output


@pytest.mark.parametrize("field", ["result", "prompts_tested"])
def test_each_identifying_field_is_required(field, tmp_path):
    """Each field in the identity set is load-bearing on its own.

    Signed under an ephemeral key, so the document reaches the identity check
    rather than stopping at the signature.
    """
    # No sir_firewall_version: the field decides the chain-version floor, which
    # --no-ledger does not reach, and naming a release here would make this file
    # a version surface that tests/test_evidence_version.py has to classify.
    payload = {
        "run_id": "20261015-000000-000000-gh1-abc",
        "result": "AUDIT PASSED",
        "prompts_tested": 150,
    }
    payload.pop(field)
    document, pubkey = _signed(tmp_path, payload)

    code, output = _verify(document, "--no-ledger", "--pubkey", str(pubkey))
    assert code == NOT_A_CERTIFICATE, output
    assert field in output
    assert "Its signature verified" in output, (
        "the message must not suggest the signature was the problem"
    )


def test_a_signed_document_carrying_both_fields_is_treated_as_a_certificate(tmp_path):
    """Guard the guard: the refusals above are about the missing field.

    The same construction with both fields present must get past the type
    check. Without this, a fixture that could never verify for an unrelated
    reason would make the two tests above pass for the wrong reason.
    """
    document, pubkey = _signed(
        tmp_path,
        {
            "run_id": "20261015-000000-000000-gh1-abc",
            "result": "AUDIT PASSED",
            "prompts_tested": 150,
        },
    )

    code, output = _verify(document, "--no-ledger", "--pubkey", str(pubkey))
    assert code == 0, output


def test_a_tampered_certificate_is_still_reported_as_tampered():
    """The published negative example keeps its documented exit code.

    `tampered-required-field-removed.json` removes prompts_tested, which is in
    the identity set, without re-signing. examples/verifier-negatives/README.md
    documents exit 3, payload_hash mismatch. An identity check placed before
    the signature would report this as not a certificate, which is a worse
    account of a document that was signed as one.
    """
    fixture = ROOT / "examples/verifier-negatives/tampered-required-field-removed.json"
    code, output = _verify(fixture)

    assert code == 3, output
    assert "payload_hash mismatch" in output


def test_a_real_certificate_still_verifies():
    """The type check must cost nothing on the document it exists to protect."""
    code, output = _verify(CERTIFICATE, "--no-ledger", "--require-registry")
    assert code == 0, output


def test_every_published_certificate_still_passes_the_type_check():
    """No published outcome moves.

    The identity set was chosen from the intersection of the fields every
    published certificate carries. This holds that property against the archive
    rather than against the note that records it.
    """
    certificates = sorted((ROOT / "proofs" / "runs").glob("*/audit.json"))
    assert len(certificates) > 300, len(certificates)

    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import verify_certificate
    finally:
        sys.path.pop(0)

    missing = {}
    for path in certificates:
        payload = json.loads(path.read_text(encoding="utf-8"))
        absent = [
            field
            for field in verify_certificate.CERTIFICATE_IDENTIFYING_FIELDS
            if field not in payload
        ]
        foreign = [
            key for key in verify_certificate.FOREIGN_RECORD_KEYS if key in payload
        ]
        if absent or foreign:
            missing[path.parent.name] = {"absent": absent, "foreign": foreign}

    assert not missing, missing
