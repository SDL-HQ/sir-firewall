#!/usr/bin/env python3
"""How SIR signs a document, in one place.

Two kinds of signed document now exist: the audit certificate, which says what
the gate did, and the ungated baseline record, which says what was forwarded
with the gate out of the path. They are signed the same way, by the same key,
and the scheme was written out twice before this module existed.

The scheme, unchanged from the certificate's:

    payload       every field except signature and payload_hash, serialised as
                  compact JSON in the document's own field order, not sorted
    payload_hash  sha256 of those bytes, prefixed "sha256:"
    signature     PKCS1v15 over the same bytes, base64

Field order is load-bearing and deliberately not normalised. A verifier
rebuilds the payload from the parsed document, which preserves the order the
file was written in, so re-serialising with sorted keys would break every
published certificate. tests/test_document_signing.py reproduces the published
payload_hash of every archived certificate through this module, which is what
holds that.

The archive receipt in tools/publish_run.py is signed over a sorted payload and
is deliberately left alone: it is a different scheme, published that way across
160 verifying archives, and unifying it would invalidate them.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

UNSIGNED_FIELDS = ("signature", "payload_hash")


def signing_payload(document: Dict[str, Any]) -> bytes:
    """The exact bytes a signature covers."""
    body = {key: value for key, value in document.items() if key not in UNSIGNED_FIELDS}
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def payload_hash(document: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(signing_payload(document)).hexdigest()


def sign_document(document: Dict[str, Any], private_key_pem: str) -> Dict[str, Any]:
    """Return the document with payload_hash and signature attached.

    The two fields are appended in this order, after every signed field, which
    is the order the certificate generator used and therefore the order every
    published certificate carries.
    """
    payload = signing_payload(document)
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    signed = {key: value for key, value in document.items() if key not in UNSIGNED_FIELDS}
    signed["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    signed["signature"] = base64.b64encode(signature).decode("ascii")

    # The payload must not move while it is being signed. The certificate
    # generator checked this for the receipt and not for itself.
    if signing_payload(signed) != payload:
        raise RuntimeError(
            "refusing to sign: the payload changed while the signature was being attached"
        )
    return signed
