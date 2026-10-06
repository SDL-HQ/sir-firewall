"""The registry is the only way to resolve a signing key.

A public key file sitting outside spec/pubkeys/ is an unregistered
verification surface: anyone who finds it and verifies against it gets an
answer with no status check, no revocation check and no run-id anchor. On
6 October 2026 policy/sdl_public_key.pem held the retired `default` key for
exactly that reason, referenced by nothing.
"""

import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

ROOT = Path(__file__).resolve().parents[1]

PEM_PUBLIC_MARKER = "-----BEGIN PUBLIC KEY-----"

# Published evidence and test fixtures legitimately embed key material.
SKIPPED_PREFIXES = ("proofs/", "docs/", "tests/", "examples/")

# The registry and the single active key file are the sanctioned surface.
SANCTIONED = {"spec/sdl.pub"}
SANCTIONED_PREFIXES = ("spec/pubkeys/",)

# Paths allowed to carry key material for a stated reason. Add here rather
# than widening SKIPPED_PREFIXES, so each exception stays visible.
ALLOWLIST: set[str] = {
    # A commented-out example inside the empty PUBLIC_KEYS dict, holding an
    # ellipsis rather than key material. The dict being empty is why incoming
    # signature enforcement cannot currently pass (item 8).
    "src/sir_firewall/core.py",
}


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line]


def _spki(pem: bytes) -> bytes:
    return load_pem_public_key(pem).public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def test_no_public_key_material_outside_the_registry() -> None:
    offenders = []
    for rel in _tracked_files():
        if rel.startswith(SKIPPED_PREFIXES):
            continue
        if rel in SANCTIONED or rel.startswith(SANCTIONED_PREFIXES):
            continue
        if rel in ALLOWLIST:
            continue
        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, IsADirectoryError):
            continue
        if PEM_PUBLIC_MARKER in text:
            offenders.append(rel)

    assert not offenders, (
        "public key material outside spec/sdl.pub and spec/pubkeys/: "
        + ", ".join(sorted(offenders))
        + ". The registry must be the only way to resolve a key; delete the "
        "file or add it to ALLOWLIST with a reason."
    )


def test_spec_sdl_pub_matches_the_active_registry_entry() -> None:
    registry = json.loads(
        (ROOT / "spec/pubkeys/key_registry.v1.json").read_text(encoding="utf-8")
    )
    active = [e for e in registry["keys"] if e.get("status") == "active"]
    assert len(active) == 1, f"expected exactly one active key, found {len(active)}"

    expected = _spki(active[0]["pubkey_pem"].encode("utf-8"))
    actual = _spki((ROOT / "spec/sdl.pub").read_bytes())

    assert actual == expected, (
        "spec/sdl.pub is not the active registry key "
        f"({active[0]['key_id']}). It is the default public key for the "
        "certificate, receipt and export-bundle verifiers, so a mismatch "
        "makes every published archive unverifiable with the documented "
        "command."
    )
