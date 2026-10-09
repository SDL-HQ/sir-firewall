"""chain_version 2: the published row's contents are inside its own hash.

The defect, reproduced on a real archive on 2 October 2026. A published
archive was copied out of the tree and one row altered: the decision changed
from PASS to BLOCKED, the prompt identifier and prompt hash replaced, the leak
flag set, the provider call flag set, the timestamp moved to 2019. The three
chain fields were left untouched.

    cert + original ledger    exit 0
    cert + mutated ledger     exit 0      <- the defect
    archive receipt           exit 2      (file hash mismatch)

Under chain_version 1 the row hash is sha256(prev_hash + final_hash), so no
descriptive field of the row enters any hash. The chain binds order, not
contents, and the receipt was the only thing that noticed.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ITGL = _load("itgl_binding", "tools/itgl.py")
VERIFY_CERT = _load("verify_certificate_binding", "tools/verify_certificate.py")


def _row(index: int, **overrides) -> dict:
    row = {
        "chain_version": ITGL.CURRENT_CHAIN_VERSION,
        "ts": f"2026-10-08T00:00:0{index}Z",
        "prompt_index": index,
        "prompt_id": f"row-{index}",
        "prompt_hash": hashlib.sha256(f"prompt-{index}".encode()).hexdigest(),
        "status": "PASS",
        "expected": "allow",
        "leak_flag": "",
        "provider_call_attempted": False,
        "final_hash": hashlib.sha256(f"final-{index}".encode()).hexdigest(),
    }
    row.update(overrides)
    return row


def _chain(rows: list) -> list:
    prev = "GENESIS"
    chained = []
    for row in rows:
        row = dict(row)
        row["prev_hash"] = prev
        row["ledger_hash"] = ITGL.compute_ledger_hash(prev, row)
        prev = row["ledger_hash"]
        chained.append(row)
    return chained


def _ledger() -> list:
    return _chain([_row(1), _row(2), _row(3)])


# Exactly the fields altered in the 2 October reproduction.
@pytest.mark.parametrize("field,value", [
    ("status", "BLOCKED"),
    ("prompt_id", "fabricated-id"),
    ("prompt_hash", "0" * 64),
    ("leak_flag", "LEAK"),
    ("provider_call_attempted", True),
    ("ts", "2019-01-01T00:00:00Z"),
    ("expected", "block"),
])
def test_altering_a_published_row_now_breaks_its_own_hash(field, value):
    entries = _ledger()
    entries[1][field] = value
    with pytest.raises(ITGL.LedgerVerificationError) as caught:
        ITGL.verify_ledger(entries)
    assert "invalid ledger_hash" in str(caught.value)


def test_fields_attached_after_the_row_literal_are_covered_too():
    """pass_rule_explainability and the scenario fields are added to the row
    after the dict literal in the writer. Computing the hash before they were
    attached would leave them unbound, which is why the writer builds the row
    complete and hashes it last."""
    entries = _chain([
        _row(1, pass_rule_explainability={"evaluated_rule_families": ["a"]}),
        _row(2),
    ])
    ITGL.verify_ledger(entries)

    entries[0]["pass_rule_explainability"]["evaluated_rule_families"] = ["tampered"]
    with pytest.raises(ITGL.LedgerVerificationError):
        ITGL.verify_ledger(entries)


def test_downgrading_a_row_inside_a_v2_ledger_cannot_be_repaired():
    """What actually defeats a downgrade, established rather than assumed.

    The first draft of this test asserted that recomputing a tampered row
    under the v1 rule would reproduce its original hash, leaving the chain
    intact. That is true only in a ledger that was already v1. Here the
    original hash covered the row's contents, so the v1 recomputation differs,
    the next row's prev_hash no longer matches, and repairing the linkage
    changes the terminal hash that the certificate signed.

    So the external minimum is not what stops this. v2 putting row contents in
    the hash is, and the signed terminal hash pins the result. The minimum is a
    policy control, covered by the test below.
    """
    entries = _ledger()
    original_terminal = entries[-1]["ledger_hash"]

    forged = copy.deepcopy(entries)
    forged[1]["status"] = "BLOCKED"
    forged[1]["chain_version"] = ITGL.CHAIN_VERSION_V1
    forged[1]["ledger_hash"] = ITGL.compute_ledger_hash(forged[1]["prev_hash"], forged[1])

    assert forged[1]["ledger_hash"] != entries[1]["ledger_hash"]

    # Caught with no external minimum at all.
    with pytest.raises(ITGL.LedgerVerificationError):
        ITGL.verify_ledger(forged)

    # And repairing the linkage moves the terminal hash the certificate signed.
    repaired = _chain([dict(row) for row in forged])
    assert repaired[-1]["ledger_hash"] != original_terminal


def test_the_minimum_refuses_a_weaker_ledger_than_the_reader_requires():
    """A policy control, not an anti-tampering one. A reader who requires v2
    evidence should not silently receive a v1 archive, and standalone
    verification has no signed terminal hash to pin anything."""
    legacy = _chain([
        {k: v for k, v in _row(index).items() if k != "chain_version"}
        for index in (1, 2)
    ])
    ITGL.verify_ledger(legacy)

    with pytest.raises(ITGL.LedgerVerificationError) as caught:
        ITGL.verify_ledger(legacy, minimum_chain_version=ITGL.CHAIN_VERSION_V2)
    assert "at least 2 is required" in str(caught.value)


def test_a_mixed_version_ledger_is_refused():
    """One run writes one version. A mixture is tampering or a defect."""
    entries = _chain([_row(1), _row(2, chain_version=ITGL.CHAIN_VERSION_V1)])
    with pytest.raises(ITGL.LedgerVerificationError) as caught:
        ITGL.verify_ledger(entries)
    assert "also uses" in str(caught.value)


def test_reformatting_a_ledger_does_not_break_it():
    """The hash covers a canonical form of the parsed row, not the bytes on
    disk, so re-serialising with different key order and spacing survives."""
    entries = _ledger()
    reformatted = [
        json.loads(json.dumps(dict(reversed(list(row.items()))), indent=2))
        for row in entries
    ]
    ITGL.verify_ledger(reformatted)


def test_legacy_rows_without_the_field_still_verify():
    """All 292 published archives predate chain_version and carry no such
    field. They must keep verifying under the rule they were written with."""
    prev = "GENESIS"
    entries = []
    for index in range(1, 4):
        row = {
            "ts": f"2026-01-01T00:00:0{index}Z",
            "prompt_index": index,
            "status": "PASS",
            "final_hash": hashlib.sha256(f"legacy-{index}".encode()).hexdigest(),
        }
        row["prev_hash"] = prev
        row["ledger_hash"] = ITGL.compute_ledger_hash(prev, row)
        prev = row["ledger_hash"]
        entries.append(row)
    ITGL.verify_ledger(entries)

    with pytest.raises(ITGL.LedgerVerificationError):
        ITGL.verify_ledger(entries, minimum_chain_version=ITGL.CHAIN_VERSION_V2)


@pytest.mark.parametrize("version,expected", [
    ("1.0.2", 1),
    ("2.3.8", 1),
    ("2.3.9", 1),
    ("2.4.0", 2),
    ("2.5.0", 2),
    ("3.0.0", 2),
    ("unknown", 1),
    (None, 1),
])
def test_the_bar_comes_from_the_certificates_signed_version(version, expected):
    assert VERIFY_CERT.minimum_chain_version_for(version) == expected


def test_the_exclusion_set_is_exactly_the_two_chain_fields():
    """Expressed as an exclusion so new row fields are covered automatically.
    An include-list would make anything omitted an undetected tamper surface,
    and 3c is about to add fields to the row."""
    assert set(ITGL.CHAIN_FIELDS) == {"prev_hash", "ledger_hash"}

    row = _row(1)
    payload = json.loads(ITGL.chain_payload(row))
    assert set(payload) == set(row) - set(ITGL.CHAIN_FIELDS)
