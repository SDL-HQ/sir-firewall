#!/usr/bin/env python3
"""Shared key-registry helpers for offline certificate/receipt verification."""

from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

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


class RegistryKeyUnreadable(ValueError):
    """The registry, or the key of one of its entries, could not be read, so no key can be compared with it."""


def entries_holding(registry_path: Path, public_key: Any) -> List[Dict[str, Any]]:
    """Every entry of this registry whose public key is the key in hand.

    The comparison is of key material. It reads nothing a document says about
    which key signed it and nothing a file is called.
    """
    from cryptography.hazmat.primitives import serialization

    keys = load_registry(registry_path).get("keys")
    if not isinstance(keys, list):
        raise ValueError("key registry keys must be a list")
    in_hand = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    holding = []
    for item in keys:
        if not isinstance(item, dict):
            continue
        try:
            der = _public_der_of_pem(public_key_pem_from_entry(item))
        except Exception as exc:  # noqa: BLE001 - an entry that cannot be read may be the one that matters
            raise RegistryKeyUnreadable(
                f"registry entry key_id={item.get('key_id')!r} holds no readable public key ({exc})"
            ) from exc
        if der == in_hand:
            holding.append(item)
    return holding


def key_file_refusal(
    registry_path: Path,
    public_key: Any,
    proof_timestamp_utc: Optional[str],
    proof_run_id: Optional[str],
    computed_payload_hash: str,
) -> Optional[str]:
    """Why a document verified by a key from a public key file is not honoured, or None.

    Call this after the signature has verified under a key that did not come
    from the registry, with the payload hash the verifier computed.

    A key reaches a verifier two ways: the registry is asked for the entry a
    document names, or a public key file is read. The registry's rules were
    applied on the first way only. So the holder of a revoked key had a second
    way in wherever a reader's public key file still held that key: a document
    naming no key, or naming one the registry does not have, was verified
    against the file, and neither the revocation nor the anchored set was
    asked anything. The id a document states is the signer's to write. The key
    that verified the signature is not, so the registry is asked about that.

    A key no entry holds is not the registry's to refuse: someone verifying
    their own documents with their own key beside this registry is unaffected.

    Raises RegistryKeyUnreadable when the registry, or an entry's key, cannot
    be read: the check could not be performed, which is not a statement about
    the document. Until 21 November 2026 a registry that was missing or could
    not be parsed was answered None here, "not refused", which is how a
    missing file became a pass. `resolve_keys` refuses that case before the
    signature now, so a verifier does not arrive here without a registry; if
    one ever does, the answer is that the question could not be asked.
    """
    try:
        holding = entries_holding(registry_path, public_key)
    except RegistryKeyUnreadable:
        raise
    except (OSError, ValueError) as exc:
        raise RegistryKeyUnreadable(f"key registry could not be read: {registry_path} ({exc})") from exc
    for entry in holding:
        if entry.get("status") == "active":
            continue
        allowed, reason = revocation_allows_proof(
            entry, proof_timestamp_utc, proof_run_id, anchored_check_follows=True
        )
        if not allowed:
            return f"the key in the public key file is registry entry key_id={entry.get('key_id')!r}: {reason}"
        refusal = anchored_set_refusal(entry, computed_payload_hash)
        if refusal is not None:
            return f"the key in the public key file is a registry key: {refusal}"
    return None


# --- one resolution, for every verifier ----------------------------------------
#
# The five functions above were already shared. The sequence that calls them
# was not: is there a registry, find the entry, ask the revocation rule, fall
# back or refuse, and after the signature the anchored set or the key file.
# Until 21 November 2026 each of the three verifiers wrote that sequence
# itself, in 118, 37 and 23 lines. They had the same inputs and nothing
# compared them, so one condition, a registry that was required and could not
# be read, returned 1 from one, 3 from the second and 5 from the third; a
# document naming a key the registry does not have was refused by one, verified
# against a public key file by the second only when the file was typed, and
# verified against it silently by the third; the key-file check of
# 19 November had to be added in three places; and the receipt verifier asked
# the wrong object for a day because its copy had its own variable.
#
# One thing is deliberately still different between the verifiers, and it is
# passed in by name and not written again in each:
#
#   implicit_key_id  only a certificate may name no key, because the field
#                    postdates 43 published certificates; such a certificate is
#                    resolved as that id, with the public key file as a second
#                    candidate.
#
# Each verifier maps a refusal's kind to its own published exit code.

#: The reader's bundle: no registry could be read, and one is required.
REGISTRY_UNAVAILABLE = "registry-unavailable"
#: The reader's bundle: a public key file was needed and could not be read.
KEY_FILE_UNREADABLE = "key-file-unreadable"
#: The reader's bundle: the registry was read and does not have the key the document names.
KEY_NOT_IN_REGISTRY = "key-not-in-registry"
#: The registry holds the key and does not honour it for this document.
KEY_NOT_HONOURED = "key-not-honoured"
#: The document's signing_key_id is present and is not a non-empty string.
KEY_ID_MALFORMED = "key-id-malformed"


class KeyRefused(Exception):
    """No key is offered for this document. `kind` says whose fact that is."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class KeyCandidate(NamedTuple):
    """A key to try, how the verifier names it, and the registry entry that governs it.

    `entry` is None for a key read from a public key file. After the signature
    verifies, `refusal_after_signature` asks the entry, or asks the registry
    whether it holds the key.

    NamedTuple and not a dataclass: several tests and the shop window load
    this module by path without registering it, and a dataclass under
    postponed annotations looks its own module up by name.
    """

    public_key: Any
    source: str
    entry: Optional[Dict[str, Any]]


def _key_from_file(pubkey_path: Path) -> KeyCandidate:
    from cryptography.hazmat.primitives import serialization

    try:
        public_key = serialization.load_pem_public_key(pubkey_path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - a file we could not read is our fact, whatever raised
        raise KeyRefused(KEY_FILE_UNREADABLE, f"failed to load public key: {pubkey_path} ({exc})") from exc
    return KeyCandidate(public_key, f"--pubkey {pubkey_path}", None)


def resolve_keys(
    document: Dict[str, Any],
    *,
    registry_path: Path,
    require_registry: bool = False,
    implicit_key_id: Optional[str] = None,
    pubkey_path: Optional[Path] = None,
) -> Tuple[KeyCandidate, ...]:
    """The keys to try for this document, in order, or a refusal.

    A document that names a key is verified against the registry's entry for
    that key and against nothing else. There is no flag that changes that.
    Before 21 November 2026 a registry that was missing or unreadable meant a
    warning and the public key file, and two of the three verifiers also fell
    back to the file for a key the registry did not have; a file a reader was
    handed says someone signed the document, and the registry is the only
    thing here that says who, so both are refusals now and neither verifies
    anything.

    They are refusals about the reader's bundle and not about the document.
    A registry that cannot be read, and a registry that was read and lacks the
    key, leave the same thing unestablished: nobody checked the signature.
    Which of them it was is in the message, and each verifier exits 6 for
    both.

    A public key file is a candidate in one case, the one `implicit_key_id`
    and `pubkey_path` exist for: a certificate that names no key. Someone
    assembling a minimal bundle signs with their own key, writes it to
    spec/sdl.pub and copies the approved registry in beside it; their
    certificate names no key either, and was not signed by SDL. The registry's
    implicit entry is tried first and the file second, the result names
    whichever verified, and `refusal_after_signature` holds a key from the
    file to the registry entry that holds it. `require_registry` withdraws
    the file: registry keys only.

    The revocation rule is asked here, before the signature, and it is told
    the anchored check follows. `refusal_after_signature` is that check. A
    verifier that calls one calls the other.
    """
    from cryptography.hazmat.primitives import serialization

    named = document.get("signing_key_id")
    names_a_key = isinstance(named, str) and bool(named)
    if ("signing_key_id" in document or implicit_key_id is None) and not names_a_key:
        raise KeyRefused(KEY_ID_MALFORMED, "signing_key_id must be a non-empty string when present")
    subject = f"signing_key_id={named}" if names_a_key else "a certificate naming no signing_key_id"

    def unavailable(state: str, detail: str) -> KeyRefused:
        return KeyRefused(
            REGISTRY_UNAVAILABLE,
            f"key registry {state}: {registry_path}{detail}. It is required to resolve {subject}, "
            "so nothing about this document was verified.",
        )

    if not registry_path.exists():
        raise unavailable("unavailable", "")
    lookup = named if names_a_key else implicit_key_id
    try:
        entry = find_registry_key(registry_path, lookup)
    except Exception as exc:  # noqa: BLE001 - whatever stopped the registry being read, it was not read
        raise unavailable("unreadable", f" ({exc})") from exc

    if entry is None:
        if names_a_key:
            # The sentence the certificate verifier has always printed for
            # this, which a negative example publishes.
            raise KeyRefused(KEY_NOT_IN_REGISTRY, f"signing_key_id not found in key registry: {named}")
        # A certificate naming no key, and a registry with no implicit entry:
        # someone else's registry. Their key file is all there is.
        if require_registry or pubkey_path is None:
            raise KeyRefused(
                KEY_NOT_IN_REGISTRY,
                f"this certificate names no signing_key_id and the key registry {registry_path} has no entry "
                f"{implicit_key_id!r} to resolve it as, so nothing about this document was verified.",
            )
        return (_key_from_file(pubkey_path),)

    implicit = not names_a_key
    allowed, reason = revocation_allows_proof(
        entry, document.get("timestamp_utc"), document.get("run_id"), anchored_check_follows=True
    )
    if not allowed:
        resolved_as = (
            f"this certificate carries no signing_key_id, so it is resolved as key_id={implicit_key_id!r}: "
            if implicit
            else ""
        )
        raise KeyRefused(KEY_NOT_HONOURED, f"revoked-key verification failure: {resolved_as}{reason}")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem_from_entry(entry).encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - a malformed entry in our own registry
        raise unavailable("unreadable", f" (entry key_id={lookup!r}: {exc})") from exc
    source = (
        f"key registry {registry_path} entry key_id={lookup} "
        "(the certificate carries no signing_key_id; the field postdates it)"
        if implicit
        else f"key registry {registry_path} entry signing_key_id={lookup}"
    )
    candidates = [KeyCandidate(public_key, source, entry)]
    if implicit and not require_registry and pubkey_path is not None:
        # A candidate and not a replacement: both are offered and the one
        # that verifies is named in the result.
        candidates.append(_key_from_file(pubkey_path))
    return tuple(candidates)


def refusal_after_signature(
    candidate: KeyCandidate,
    *,
    registry_path: Path,
    document: Dict[str, Any],
    computed_payload_hash: str,
) -> Optional[str]:
    """Why a document whose signature verified under this candidate is not honoured, or None.

    Call it after the signature verifies and not before, with the payload hash
    computed from the document: before the signature a refusal would be about
    a document nobody has shown the key signed, and it would displace the more
    exact answer for a tampered one.

    Raises RegistryKeyUnreadable when the question could not be asked.
    """
    if candidate.entry is not None:
        refusal = anchored_set_refusal(candidate.entry, computed_payload_hash)
        return None if refusal is None else f"{candidate.entry.get('status')}-key verification failure: {refusal}"
    refusal = key_file_refusal(
        registry_path, candidate.public_key, document.get("timestamp_utc"), document.get("run_id"), computed_payload_hash
    )
    return None if refusal is None else f"key-file verification failure: {refusal}"
