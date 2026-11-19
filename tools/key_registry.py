#!/usr/bin/env python3
"""Shared key-registry helpers for offline certificate/receipt verification."""

from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

TS_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RUN_NUMBER_RE = re.compile(r"-gh(\d+)-")


def parse_utc_z(ts: str) -> datetime:
    if not isinstance(ts, str) or TS_Z_RE.match(ts) is None:
        raise ValueError("timestamp must be UTC ISO-8601 with Z suffix")
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_registry(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"failed to parse key registry JSON {path}: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object in {path}, got {type(obj).__name__}")
    return obj


# The key id a certificate with no signing_key_id was signed by.
#
# 43 of the 292 certificates published before SIR 2.4.0 carry no
# signing_key_id, because the field did not exist yet. All 43 verify against
# the registry entry "default" and none verify against spec/sdl.pub, which has
# held the rotated key since 6 October 2026. Until 8 October a verifier with
# nothing to resolve fell through to that file, so those 43 archives reported
# "signature verification failed" under the documented procedure: not invalid
# evidence, a verifier with no rule for them.
#
# Treating an absent field as "default" records what the field's absence
# already meant. It is strictly stronger than the fallback it replaces, because
# the entry's status and revocation rules then apply where a bare public key
# file enforces neither. It is not a new trust path: "default" is in the
# approved registry, retired, and a revoked "default" refuses these archives
# exactly as it refuses the 249 that name it.
IMPLICIT_KEY_ID = "default"


# The environment variable every signer reads, and the registry they check it
# against.
SIGNING_KEY_ID_ENV = "SDL_SIGNING_KEY_ID"
# The verifiers all take a registry path; the signers had nowhere to say one,
# so a deployment or a test signing against its own keys had no way to be
# checked at all. Named rather than passed because the four signers are
# invoked as scripts with no shared argument surface.
SIGNING_REGISTRY_ENV = "SDL_KEY_REGISTRY"
DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "spec" / "pubkeys" / "key_registry.v1.json"


class SigningKeyError(RuntimeError):
    """The signing key id could not be established, so nothing may be signed."""


def _public_pem_of(private_key_pem: str) -> bytes:
    """The DER of the public key belonging to this private key."""
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_der_of_pem(public_key_pem: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def resolve_signing_key_id(
    private_key_pem: str, registry_path: Optional[Path] = None
) -> str:
    """The signing key id, derived against the key that will actually sign.

    Every signer used to read SDL_SIGNING_KEY_ID and fall back to "default"
    when it was unset. That fallback is how the archive acquired six
    certificates signed by a key nobody published: the id said "default", the
    signature was made by something else, and nothing compared the two. A key
    id read from an environment variable is a second copy of the key's
    identity, and this project's recurring defect is a value taken from the
    second copy rather than computed from the thing it names.

    So the id is still named by the environment, because a registry id is a
    label and cannot be computed from key material, but it is refused unless
    the registry entry it names holds the public key belonging to the private
    key in hand. Three ways to fail, all closed:

      unset            nothing to check, so nothing is signed
      not in registry  an id that resolves to no key identifies no key
      wrong key        the id names a key that is not the one signing

    The third is the one that matters. The other two were reachable before and
    produced a signed document anyway.
    """
    key_id = (os.getenv(SIGNING_KEY_ID_ENV) or "").strip()
    if not key_id:
        raise SigningKeyError(
            f"refusing to sign: {SIGNING_KEY_ID_ENV} is not set. It used to "
            'default to "default", which is how six published certificates '
            "came to name a key that was never published."
        )

    named = os.getenv(SIGNING_REGISTRY_ENV)
    path = registry_path or (Path(named) if named else DEFAULT_REGISTRY_PATH)
    entry = find_registry_key(path, key_id)
    if entry is None:
        raise SigningKeyError(
            f"refusing to sign: {SIGNING_KEY_ID_ENV} is {key_id!r}, which is "
            f"not in {path}. An id that resolves to no key identifies no key."
        )

    try:
        registry_der = _public_der_of_pem(public_key_pem_from_entry(entry))
        actual_der = _public_pem_of(private_key_pem)
    except SigningKeyError:
        raise
    except Exception as exc:  # noqa: BLE001 - any failure here must fail closed
        raise SigningKeyError(
            f"refusing to sign: could not compare {key_id!r} against the "
            f"signing key: {exc}"
        ) from exc

    if registry_der != actual_der:
        raise SigningKeyError(
            f"refusing to sign: {SIGNING_KEY_ID_ENV} is {key_id!r}, but the "
            "registry entry for that id holds a different public key from the "
            "one belonging to the signing key. The certificate would name a "
            "key that did not sign it."
        )
    return key_id


def find_registry_key(path: Path, key_id: str) -> Optional[Dict[str, Any]]:
    reg = load_registry(path)
    keys = reg.get("keys")
    if not isinstance(keys, list):
        raise ValueError("key registry keys must be a list")
    for item in keys:
        if isinstance(item, dict) and item.get("key_id") == key_id:
            return item
    return None


def public_key_pem_from_entry(entry: Dict[str, Any]) -> str:
    pem = entry.get("pubkey_pem")
    if isinstance(pem, str) and pem.strip():
        return pem

    b64 = entry.get("pubkey_base64")
    if isinstance(b64, str) and b64.strip():
        return base64.b64decode(b64.encode("ascii")).decode("utf-8")

    raise ValueError("registry key entry missing pubkey_pem/pubkey_base64")


def run_number_from_run_id(run_id: Optional[str]) -> Optional[int]:
    """CI run number embedded in a run identifier, or None.

    Run identifiers carry the publishing CI run as ``-gh<number>-``. The number
    increases monotonically per repository and is assigned by the forge, not by
    whoever holds a signing key.
    """
    if not isinstance(run_id, str):
        return None
    match = RUN_NUMBER_RE.search(run_id)
    return int(match.group(1)) if match else None


#: The registry field that anchors what a key signed, by payload hash.
ANCHORED_FIELD = "anchored_payload_hashes"


def has_anchored_set(entry: Dict[str, Any]) -> bool:
    """Whether this key is decided by an anchored set.

    It is when the key is no longer active and the entry carries the field,
    whatever the field holds: a field that is present and malformed is a set
    that honours nothing, not an absent one. An active key signs new documents
    every day, so a list of what it has signed is never complete and is not
    consulted.
    """
    return entry.get("status") != "active" and ANCHORED_FIELD in entry


def anchored_set_refusal(entry: Dict[str, Any], computed_payload_hash: str) -> Optional[str]:
    """Why a verified document is not honoured under this key, or None if it is.

    Call this after the signature has verified, with the payload hash the
    verifier computed from the document. Never pass the hash the document
    states: a signature does not cover that field, so whoever holds the key
    can write any value there, including one from this list.

    A key that is retired or revoked is, from that day, a key someone may hold
    who should not be signing. What the registry recorded for a retired key was
    an end date and a last trusted run, and nothing read either: a document
    signed the next year verified exactly as one signed the year before. Both
    limits are also values the signer writes. The anchored set is not. It is
    the payload hash of every document the key signed that was published while
    the key was in use, derived from the published archive when the key was
    retired (tools/anchor_published_set.py). A key that is not active is
    honoured for those documents and no others, whatever a new document says
    about its own date or run.
    """
    if not has_anchored_set(entry):
        return None
    anchored = entry.get(ANCHORED_FIELD)
    key_id = entry.get("key_id")
    status = entry.get("status")
    if not isinstance(anchored, list) or not all(isinstance(h, str) for h in anchored):
        return (
            f"key_id={key_id!r} is {status} and its {ANCHORED_FIELD} is not a list of "
            "payload hashes (fail closed)"
        )
    if computed_payload_hash in anchored:
        return None
    return (
        f"key_id={key_id!r} is {status} and is honoured only for the {len(anchored)} "
        f"document(s) the registry anchors by payload hash; this document's payload "
        f"hash, {computed_payload_hash}, is not among them"
    )


def revocation_allows_proof(
    entry: Dict[str, Any],
    proof_timestamp_utc: Optional[str],
    proof_run_id: Optional[str] = None,
    *,
    anchored_check_follows: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Decide whether a revoked key's signature may still be honoured.

    An entry that carries an anchored set is decided by that set instead, after
    the signature has verified (anchored_set_refusal). The run-number rule
    below reads values the document states about itself, and the set does not,
    so where both exist the set decides alone: it honours an anchored document
    that states no run number, which the rule below would refuse, and refuses
    an unanchored one that states an old run number, which the rule below
    would honour. A caller says it will make that later check by passing
    anchored_check_follows; one that does not is refused here, so a verifier
    that has not been taught the set cannot honour such a key for anything.

    A revoked key is, by assumption, held by someone who can sign anything they
    like, including a certificate carrying a timestamp from before the
    revocation. The signer's own timestamp therefore cannot decide this: it is
    chosen by the party the revocation exists to stop.

    The anchor decides instead. ``last_trusted_run_id`` names the last run
    published before the key was revoked, and a proof counts as
    pre-revocation only if its own run identifier is at or below that one. Run
    numbers come from the forge, so a key holder cannot raise theirs. The
    timestamp is still checked, but it can only tighten the result.

    Fails closed when the entry carries no anchor, or the proof carries no
    parseable run identifier.
    """
    if has_anchored_set(entry):
        if anchored_check_follows:
            return True, None
        return False, (
            f"key_id={entry.get('key_id')!r} is {entry.get('status')} and carries "
            f"{ANCHORED_FIELD}, which this verifier does not apply (fail closed)"
        )

    if entry.get("status") != "revoked":
        return True, None

    revoked_utc = entry.get("revoked_utc")
    if not isinstance(revoked_utc, str):
        return False, "revoked key missing revoked_utc"

    anchor_run_id = entry.get("last_trusted_run_id")
    anchor = run_number_from_run_id(anchor_run_id)
    if anchor is None:
        return False, (
            "revoked key has no usable last_trusted_run_id anchor, and revocation "
            "cannot be established from a signer-supplied timestamp alone"
        )

    proof_number = run_number_from_run_id(proof_run_id)
    if proof_number is None:
        return False, "proof carries no parseable run_id (fail closed for revocation checks)"

    if proof_number > anchor:
        return False, (
            f"proof run_id {proof_run_id} is after the last trusted run "
            f"{anchor_run_id} for this revoked key"
        )

    if isinstance(proof_timestamp_utc, str) and proof_timestamp_utc:
        if parse_utc_z(proof_timestamp_utc) >= parse_utc_z(revoked_utc):
            return False, (
                f"proof timestamp_utc {proof_timestamp_utc} is at/after "
                f"revoked_utc {revoked_utc}"
            )

    return True, None
