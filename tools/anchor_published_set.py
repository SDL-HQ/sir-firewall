#!/usr/bin/env python3
"""Derive, write or check the set of documents a key that is no longer active is honoured for.

A key that has been retired or revoked may be held by someone who should not
be signing. Whatever such a document says about its own date or run number is
written by whoever signs it. What the signer cannot write is the published
archive as it stood when the key went out of use.

So the registry anchors that: `anchored_payload_hashes` on a key's entry is
the payload hash of every published document the key signed, and the
verifiers honour a key that is not active for those documents and no others
(`key_registry.anchored_set_refusal`).

The set is derived, never typed. A document is in it when it is published
under one of the roots, resolves to the key (it names the key, or names no key
and the key is the implicit one), and its signature verifies under the key's
public key in the registry. The hash is computed from the document's payload,
in whichever of the two signing schemes verified.

    python3 tools/anchor_published_set.py --key-id default            # print what would be anchored
    python3 tools/anchor_published_set.py --key-id default --write    # record it in the registry
    python3 tools/anchor_published_set.py --check                     # every anchored key: recorded == derived

Exit codes: 0 done, or the check holds. 1 the check does not hold. 2 the
request cannot be carried out (unknown key, active key, unreadable registry).

Derive it when the key is retired, which `rotate_keys.py` does, and not when
it is revoked: after an incident the archive may already hold what the
incident produced, and the answer stops being derivable the moment anyone
else can sign.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parent))

from document_signing import UNSIGNED_FIELDS, signing_payload  # noqa: E402
from key_registry import (  # noqa: E402
    ANCHORED_FIELD,
    DEFAULT_REGISTRY_PATH,
    IMPLICIT_KEY_ID,
    public_key_pem_from_entry,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
#: Where signed documents are published from this repository.
DEFAULT_ROOTS = ("docs", "proofs")


def _receipt_payload(document: Dict[str, Any]) -> bytes:
    """The archive receipt's scheme: the same fields, serialised with sorted keys."""
    body = {key: value for key, value in document.items() if key not in UNSIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


#: Every way this project has signed a document. A document belongs to a key
#: when one of them verifies; nothing else about the document is consulted.
SCHEMES = (signing_payload, _receipt_payload)


def signed_documents(roots: Iterable[Path]) -> Iterator[Tuple[Path, Dict[str, Any]]]:
    """Every JSON object under the roots that carries a signature and a payload hash."""
    for root in roots:
        for path in sorted(root.rglob("*.json")):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(document, dict) and all(field in document for field in UNSIGNED_FIELDS):
                yield path, document


def _resolves_to(document: Dict[str, Any], key_id: str) -> bool:
    named = document.get("signing_key_id")
    if isinstance(named, str) and named:
        return named == key_id
    return key_id == IMPLICIT_KEY_ID


def verified_payload_hash(document: Dict[str, Any], public_key: Any) -> Optional[str]:
    """The payload hash of the bytes this key signed, or None if it signed neither form."""
    try:
        signature = base64.b64decode(str(document.get("signature")), validate=True)
    except Exception:
        return None
    for scheme in SCHEMES:
        payload = scheme(document)
        try:
            public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            continue
        return "sha256:" + hashlib.sha256(payload).hexdigest()
    return None


def derive(entry: Dict[str, Any], roots: Iterable[Path]) -> Tuple[List[str], Dict[str, int]]:
    """(sorted payload hashes, counts) for the documents this key signed under the roots."""
    key_id = str(entry.get("key_id"))
    public_key = serialization.load_pem_public_key(public_key_pem_from_entry(entry).encode("utf-8"))
    hashes_found: Dict[str, int] = {}
    counts = {"resolve to the key": 0, "verify under it": 0}
    for _path, document in signed_documents(roots):
        if not _resolves_to(document, key_id):
            continue
        counts["resolve to the key"] += 1
        digest = verified_payload_hash(document, public_key)
        if digest is None:
            continue
        counts["verify under it"] += 1
        hashes_found[digest] = hashes_found.get(digest, 0) + 1
    counts["distinct documents"] = len(hashes_found)
    return sorted(hashes_found), counts


def _load(registry_path: Path) -> Dict[str, Any]:
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(registry, dict) or not isinstance(registry.get("keys"), list):
        raise ValueError(f"{registry_path} is not a key registry")
    return registry


def _entry(registry: Dict[str, Any], key_id: str) -> Optional[Dict[str, Any]]:
    for entry in registry["keys"]:
        if isinstance(entry, dict) and entry.get("key_id") == key_id:
            return entry
    return None


def check(registry: Dict[str, Any], roots: Iterable[Path]) -> List[str]:
    """What is wrong with the registry's anchored sets, as sentences. Empty when nothing is."""
    roots = list(roots)
    problems = []
    for entry in registry["keys"]:
        if not isinstance(entry, dict):
            continue
        key_id, status = entry.get("key_id"), entry.get("status")
        if status == "active":
            if ANCHORED_FIELD in entry:
                problems.append(f"{key_id!r} is active and carries {ANCHORED_FIELD}; an active key's set is never complete")
            continue
        if ANCHORED_FIELD not in entry:
            problems.append(f"{key_id!r} is {status} and carries no {ANCHORED_FIELD}: it is honoured for anything it signs, on any date")
            continue
        derived, _ = derive(entry, roots)
        recorded = entry.get(ANCHORED_FIELD)
        if recorded != derived:
            recorded_set = set(recorded) if isinstance(recorded, list) else set()
            problems.append(
                f"{key_id!r}: the registry anchors {len(recorded_set)} document(s) and the published archive holds "
                f"{len(derived)} it signed; {len(set(derived) - recorded_set)} published and not anchored, "
                f"{len(recorded_set - set(derived))} anchored and not published"
                + ("" if isinstance(recorded, list) and recorded == sorted(recorded_set) else "; the list is not sorted and distinct")
            )
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--registry", default=str(DEFAULT_REGISTRY_PATH))
    ap.add_argument("--root", action="append", help="a published root to read; repeatable (default: docs and proofs)")
    ap.add_argument("--key-id", help="the key to derive the set for")
    ap.add_argument("--write", action="store_true", help="record the derived set on the key's registry entry")
    ap.add_argument("--check", action="store_true", help="every key that is not active: the recorded set is the derived one")
    args = ap.parse_args(argv)

    registry_path = Path(args.registry)
    roots = [Path(r) for r in args.root] if args.root else [REPO_ROOT / r for r in DEFAULT_ROOTS]
    try:
        registry = _load(registry_path)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.check:
        problems = check(registry, roots)
        for problem in problems:
            print(f"NOT ANCHORED: {problem}", file=sys.stderr)
        if not problems:
            print("OK: every key that is not active is anchored to exactly the documents it signed in the published archive")
        return 1 if problems else 0

    if not args.key_id:
        print("ERROR: --key-id is required unless --check is given", file=sys.stderr)
        return 2
    entry = _entry(registry, args.key_id)
    if entry is None:
        print(f"ERROR: key_id {args.key_id!r} is not in {registry_path}", file=sys.stderr)
        return 2
    if entry.get("status") == "active":
        print(f"ERROR: {args.key_id!r} is active. An active key signs new documents, so its set is never complete.", file=sys.stderr)
        return 2

    derived, counts = derive(entry, roots)
    summary = ", ".join(f"{value} {name}" for name, value in counts.items())
    if args.write:
        entry[ANCHORED_FIELD] = derived
        registry_path.write_text(json.dumps(registry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"anchored {len(derived)} document(s) for {args.key_id!r} in {registry_path} ({summary})")
    else:
        print(f"{args.key_id!r}: {summary}")
        for digest in derived:
            print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
