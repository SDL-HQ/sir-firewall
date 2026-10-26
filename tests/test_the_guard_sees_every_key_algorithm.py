"""The private-key rule is bounded by real keys, not by a chosen number.

`KEY_BODY_MINIMUM` separates a documented header from an actual key. It was 200,
which is a figure RSA clears easily and no other algorithm does, and this
repository signs with RSA, so nothing here ever exercised the gap.

It cost something elsewhere. The same guard clears the publication surface of
`sdl-decision-record`, which signs with Ed25519 by a recorded decision. An
Ed25519 PKCS#8 private key body is 64 base64 characters, so **five real private
keys scanned clean** and the guard still printed "private key material" among
the rules it reported checking. Nothing was published that should not have been
— every PRIVATE KEY header in this repository measures 0, which is the
documentation case the rule exists to allow — but the check was reporting a
property it did not have for one of the two trees it guards.

So the threshold is derived here instead of asserted: a real key is generated
per algorithm, its body measured, and the rule required to find it. A future
algorithm with a shorter key fails this test rather than passing silently
through the guard.

Breaking these: raise `KEY_BODY_MINIMUM` above the shortest measured body.
"""

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from publication_rules import (
    KEY_BODY,
    KEY_BODY_MINIMUM,
    KEY_HEADER,
    private_key_material,
)


def _pem(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _generators():
    return {
        "ed25519": ed25519.Ed25519PrivateKey.generate,
        "ed448": ed448.Ed448PrivateKey.generate,
        "ec-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
        "ec-p384": lambda: ec.generate_private_key(ec.SECP384R1()),
        "rsa-2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    }


def _body_length(pem: str) -> int:
    match = KEY_HEADER.search(pem)
    assert match, "a generated PKCS#8 PEM did not match KEY_HEADER"
    return len("".join(KEY_BODY.findall(match.group(2))))


@pytest.mark.parametrize("name", sorted(_generators()))
def test_a_real_key_of_every_algorithm_is_found(name):
    pem = _pem(_generators()[name]())
    found = private_key_material(pem)
    assert found, (
        f"a real {name} private key is not detected: its body is "
        f"{_body_length(pem)} base64 characters against KEY_BODY_MINIMUM={KEY_BODY_MINIMUM}"
    )


def test_the_threshold_is_below_the_shortest_real_key():
    """The bound, measured. Ed25519 is the shortest in use anywhere SDL signs."""
    lengths = {name: _body_length(_pem(gen())) for name, gen in _generators().items()}
    shortest = min(lengths.values())
    assert KEY_BODY_MINIMUM < shortest, (
        f"KEY_BODY_MINIMUM={KEY_BODY_MINIMUM} is not below the shortest real key body "
        f"({shortest}); measured: {lengths}"
    )
    assert lengths["ed25519"] == 64, f"ed25519 body is {lengths['ed25519']}, expected 64"


def test_a_documented_header_is_still_not_a_key():
    """The distinction the rule exists to draw must survive the lower bound."""
    for documentation in (
        "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        "a PEM file opens with -----BEGIN PRIVATE KEY----- and ends with -----END PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n<redacted>\n-----END PRIVATE KEY-----",
    ):
        assert private_key_material(documentation) == [], documentation


def test_this_repository_still_scans_clean_for_keys():
    """Every PRIVATE KEY header tracked here is documentation, and stays so."""
    import subprocess
    from pathlib import Path

    tracked = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True,
        cwd=Path(__file__).resolve().parents[1],
    ).stdout.split("\n")
    root = Path(__file__).resolve().parents[1]
    offences = []
    for rel in filter(None, tracked):
        try:
            text = (root / rel).read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        if "PRIVATE KEY" not in text:
            continue
        found = private_key_material(text)
        if found:
            offences.append(f"{rel}: {found}")
    assert not offences, "tracked files carry private key material:\n  " + "\n  ".join(offences)
