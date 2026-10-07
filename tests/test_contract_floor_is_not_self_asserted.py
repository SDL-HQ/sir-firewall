"""A certificate does not get to choose the contract that judges it.

``validate_certificate_contract.py`` selects a contract from the certificate's
own ``sir_firewall_version``. That field is inside the signed payload, so it
cannot be edited after signing, but it is written by the signer before signing.
A signer who wanted the weaker rules applied could stamp an older version onto
a certificate produced by a newer release, sign it, and the contract validator
would judge it by the older contract. Nothing in the signature detects that,
because nothing was altered.

This is the same shape as the two defects already fixed either side of it: the
revocation check read a self-asserted timestamp, and the chain rule was chosen
by the row that the rule was meant to bind. In each case the artefact chose the
rule.

The bound ledger closes it. Under chain version 2 a row's ``chain_version`` is
inside the row hash, each row hash is chained into the next, and the terminal
hash is signed on the certificate. Restamping a ledger from v2 to v1 therefore
breaks linkage. So the ledger states the era, the certificate does not, and
``verify_certificate.py`` requires the contract v4 fields of any certificate
bound to a chain version 2 ledger whatever version it claims.
"""

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ITGL = _load("itgl_floor", "tools/itgl.py")
VERIFIER = _load("verify_certificate_floor", "tools/verify_certificate.py")


# --- the shipped copy of the rule agrees with the published contract ---------


def test_the_verifier_requires_exactly_what_contract_v4_adds():
    """The verifier carries its own copy so a minimal bundle needs no spec file.

    The published contract is the authority. If a field is added to or removed
    from contract v4, this fails rather than the shipped copy quietly drifting
    out of agreement with the document a reader was given.
    """
    v3 = json.loads((ROOT / "spec/evidence_contract.v3.json").read_text(encoding="utf-8"))
    v4 = json.loads((ROOT / "spec/evidence_contract.v4.json").read_text(encoding="utf-8"))
    added = set(v4["required"]) - set(v3["required"])

    assert added, "contract v4 adds nothing over v3, so the floor has nothing to require"
    assert set(VERIFIER.CONTRACT_V4_ADDED_FIELDS) == added
    assert set(v3["required"]) <= set(v4["required"]), (
        "contract v4 drops a field v3 required, which would make a v4 certificate "
        "fail v3 and break the floor's assumption that v4 is the stronger rule"
    )


def test_the_contract_floor_and_the_chain_floor_name_the_same_release():
    """Two floors, one era. They are written in different files and must agree.

    ``MINIMUM_CHAIN_VERSION_FLOORS`` says which release had to write chain
    version 2. The contract's applicability metadata says which release contract
    v4 governs. If those diverge there is a release that must write v2 ledgers
    but need not carry the v4 fields, or the reverse.
    """
    v4 = json.loads((ROOT / "spec/evidence_contract.v4.json").read_text(encoding="utf-8"))
    floor = v4["x_contract_rules"]["applicability"]["minimum_sir_firewall_version"]
    chain_floors = {
        version: release
        for release, version in VERIFIER.MINIMUM_CHAIN_VERSION_FLOORS
    }

    assert VERIFIER._parse_semver(floor) == chain_floors[ITGL.CHAIN_VERSION_V2]


# --- behaviour ---------------------------------------------------------------


def _ledger(tmp_path, chain_version):
    rows = []
    prev = "GENESIS"
    for index in (1, 2):
        row = {
            "ts": f"2026-10-08T00:00:0{index}Z",
            "prompt_index": index,
            "status": "PASS",
            "expected": "allow",
            "systemic_reset_reason": "",
            "provider_call_attempted": False,
            "provider_call_outcome": "",
            "final_hash": hashlib.sha256(str(index).encode()).hexdigest(),
        }
        if chain_version >= ITGL.CHAIN_VERSION_V2:
            row["chain_version"] = chain_version
        row["prev_hash"] = prev
        row["ledger_hash"] = ITGL.compute_ledger_hash(prev, row)
        prev = row["ledger_hash"]
        rows.append(row)
    path = tmp_path / f"itgl_ledger_v{chain_version}.jsonl"
    path.write_text(
        "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )
    return path, rows


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("floor")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    (tmp / "pub.pem").write_text(pub, encoding="utf-8")
    (tmp / "registry.json").write_text(json.dumps({
        "version": "v1",
        "keys": [{
            "key_id": "ephemeral", "pubkey_pem": pub, "status": "active",
            "created_utc": "2026-01-01T00:00:00Z", "valid_from_utc": "2026-01-01T00:00:00Z",
        }],
    }), encoding="utf-8")
    return tmp, key


def _certificate(rows, claimed_version, **overrides):
    derived = ITGL.derive_counters(rows)
    cert = {
        "sir_firewall_version": claimed_version,
        "run_id": "20261008-000000-000000-gh1-abc",
        "detached_ledger": True,
        "itgl_final_hash": f"sha256:{rows[-1]['ledger_hash']}",
        "itgl_row_count": len(rows),
        "signing_key_id": "ephemeral",
        "configuration_hash": "sha256:" + "0" * 64,
        "counters_checked_against_ledger": True,
        **{k: v for k, v in derived.items() if k != "systemic_reset_counts_by_reason"},
    }
    cert.update(overrides)
    for field, value in list(cert.items()):
        if value is None:
            del cert[field]
    return cert


def _sign(cert, key):
    """The documented scheme: everything except signature and payload_hash."""
    cert = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    payload = json.dumps(cert, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    cert["signature"] = base64.b64encode(
        key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    return cert


def _verify(tmp, cert, ledger, name):
    path = tmp / name
    path.write_text(json.dumps(cert), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(ROOT / "tools/verify_certificate.py"), str(path),
         "--ledger", str(ledger), "--pubkey", str(tmp / "pub.pem"),
         "--key-registry", str(tmp / "registry.json")],
        capture_output=True, text=True,
    )


def test_a_v2_bound_certificate_carrying_the_v4_fields_verifies(world, tmp_path):
    tmp, key = world
    ledger, rows = _ledger(tmp_path, ITGL.CHAIN_VERSION_V2)
    result = _verify(tmp, _sign(_certificate(rows, "2.4.0"), key), ledger, "ok.json")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("field", sorted(VERIFIER.CONTRACT_V4_ADDED_FIELDS))
def test_a_v2_bound_certificate_missing_a_v4_field_is_refused(world, tmp_path, field):
    tmp, key = world
    ledger, rows = _ledger(tmp_path, ITGL.CHAIN_VERSION_V2)
    cert = _certificate(rows, "2.4.0")
    del cert[field]
    result = _verify(tmp, _sign(cert, key), ledger, f"missing-{field}.json")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "missing required fields" in result.stderr
    assert field in result.stderr


def test_claiming_an_older_version_does_not_escape_the_fields(world, tmp_path):
    """The defect this exists for.

    A certificate produced against a chain version 2 ledger, stamped 2.3.5 so
    the contract validator would apply contract v3, and signed. Nothing is
    tampered: the signature is valid over exactly these bytes. The ledger is
    what refuses it.
    """
    tmp, key = world
    ledger, rows = _ledger(tmp_path, ITGL.CHAIN_VERSION_V2)
    cert = _certificate(rows, "2.3.5")
    del cert["configuration_hash"]
    del cert["counters_checked_against_ledger"]
    result = _verify(tmp, _sign(cert, key), ledger, "understamped.json")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "chain version 2 ledger" in result.stderr
    assert "'2.3.5'" in result.stderr
    assert "configuration_hash" in result.stderr


def test_a_v1_ledger_does_not_acquire_the_requirement(world, tmp_path):
    """The 292 certificates published before 7 October 2026 bind v1 ledgers.

    None of them carry the v4 fields and none of them could. A floor taken from
    the ledger must leave them where they are, or it manufactures a wall of
    failures out of a format change.
    """
    tmp, key = world
    ledger, rows = _ledger(tmp_path, ITGL.CHAIN_VERSION_V1)
    cert = _certificate(rows, "2.3.5")
    for field in ("configuration_hash", "counters_checked_against_ledger", "content_evaluated"):
        cert.pop(field, None)
    result = _verify(tmp, _sign(cert, key), ledger, "legacy.json")

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_requirement_is_not_applied_without_a_ledger_to_take_it_from(world, tmp_path):
    """--no-ledger skips binding, and an unchecked binding states nothing.

    A certificate verified with no ledger has not been placed in an era, so the
    floor has no basis. The verifier must not infer one from the version claim,
    which is the thing this check exists to stop trusting.
    """
    tmp, key = world
    _, rows = _ledger(tmp_path, ITGL.CHAIN_VERSION_V2)
    cert = _certificate(rows, "2.3.5")
    del cert["configuration_hash"]
    path = tmp / "noledger.json"
    path.write_text(json.dumps(_sign(cert, key)), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/verify_certificate.py"), str(path),
         "--no-ledger", "--pubkey", str(tmp / "pub.pem"),
         "--key-registry", str(tmp / "registry.json")],
        capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
