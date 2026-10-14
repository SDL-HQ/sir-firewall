"""benchmark_index.v3 can hold a baseline record, and says what each kind may claim.

v3 exists because an ungated baseline stops producing an audit certificate and
produces a signed baseline record instead. A v2 entry requires a `result` and a
`proof_class`, and a baseline has neither: no gate ran, so there is no audit
outcome. Making those nullable instead would reproduce the defect this release
is named for, where a reader found a verdict field and read a verdict.

So entries and pairs declare their kind, and the schema states what each kind
must carry and what it must not. The forbidden half is the point. A baseline
entry that carried a result would validate under any schema that merely allowed
one.

Two properties are checked here, and the first is the one that constrains the
design:

  1. Everything published today can be expressed in v3 unchanged. Every entry
     and every pair in the live benchmark_index.v2.json is converted by adding
     its declared kind and nothing else, and must validate.
  2. The new shapes validate, and the shapes that would misdescribe a run do
     not.

Nothing is published against v3 yet. The producer arrives with the baseline
record itself; this is the contract it will be held to, written first so that
no artifact is published against a schema that has not been argued.

Exemplars for the new shapes are built in this file rather than committed under
spec/. A committed index of runs that never happened is a fabricated record
whatever the filename says, and this repository has spent two days correcting
records that described runs inaccurately.

Checked on 15 October 2026 against eight mutations of a scratch copy of the
schema, never the repository. Each count is what pytest reported:

    1. baseline entry allows a nullable result            2 failed
    2. gate figures allowed on any pair status            6 failed
    3. oneOf relaxed to anyOf for entries                 0 failed
    4. additionalProperties true on the baseline entry    7 failed
    5. prompt_set_hash not required                       1 failed
    6. legacy pair branch requires the new identity       1 failed
    7. baseline branch accepts any entry_kind             1 failed
    8. pair_form const dropped from the legacy branch     1 failed

and the restored copy passed 33 of 33. Mutation 3 is the one worth recording:
it is not detected, and no assertion here claims it is. The two branches cannot
both match one document, because each pins a different kind and forbids
undeclared fields, so oneOf and anyOf behave identically against every document
this file builds. Mutations 7 and 8 attack that structure instead, and they are
caught. Mutation 6 is the compatibility direction: a branch that grew a new
requirement would orphan the 54 published pairs.
"""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
V3_SCHEMA_PATH = ROOT / "spec/benchmark_index.v3.schema.json"
V2_INDEX_PATH = ROOT / "proofs/runs/benchmark_index.v2.json"


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


V3_SCHEMA = _load(V3_SCHEMA_PATH)


def _errors(document, schema=None):
    validator = Draft202012Validator(schema or V3_SCHEMA)
    return [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in validator.iter_errors(document)
    ]


def _index(entries=(), pairs=()):
    return {
        "version": "benchmark_index.v3",
        "supersedes": "benchmark_index.v2",
        "updated_at_utc": "2026-10-15T00:00:00Z",
        "entries": list(entries),
        "pairs": list(pairs),
    }


def _baseline_entry(**overrides):
    entry = {
        "entry_kind": "ungated_baseline_record",
        "run_id": "20261015-000000-000000-gh1-abc",
        "run_timestamp_utc": "2026-10-15T00:00:00Z",
        "sir_firewall_version": "2.5.0",
        "commit_sha": "0" * 40,
        "evaluation_target": {
            "target_kind": "domain_pack",
            "pack_id": "generic_safety",
            "pack_version": "1.0.0",
        },
        "provider": "xai",
        "model": "grok-4.3",
        "row_identity": "sir=2.5.0|target=generic_safety|provider=xai|model=grok-4.3",
        "forwarding": {
            "prompts_forwarded": 150,
            "expected_block_prompts_forwarded": 100,
            "expected_allow_prompts_forwarded": 50,
            "provider_call_attempts": 150,
            "provider_call_successes": 150,
            "provider_call_failures": 0,
        },
        "ci_run_url": "https://github.com/SDL-HQ/sir-firewall/actions/runs/1",
        "evidence": {
            "baseline": "runs/20261015-000000-000000-gh1-abc/baseline.json",
            "manifest": "runs/20261015-000000-000000-gh1-abc/manifest.json",
            "archive_receipt": "runs/20261015-000000-000000-gh1-abc/archive_receipt.json",
            "run_summary": "runs/20261015-000000-000000-gh1-abc/proofs/run_summary.json",
            "itgl_ledger": "runs/20261015-000000-000000-gh1-abc/proofs/itgl_ledger.jsonl",
            "itgl_final_hash": "runs/20261015-000000-000000-gh1-abc/proofs/itgl_final_hash.txt",
            "attempt_log": "runs/20261015-000000-000000-gh1-abc/proofs/latest-attempts.log",
        },
    }
    entry.update(overrides)
    return entry


def _record_pair(**overrides):
    pair = {
        "pair_form": "record_and_certificate",
        "pair_id": "20261015-000000-aaaaaaaaaaaa",
        "pair_key": "provider=xai|model=grok-4.3|pack_id=generic_safety",
        "pair_status": "valid_complete",
        "baseline_run_id": "20261015-000000-000000-gh1-abc",
        "gated_run_id": "20261015-000100-000000-gh1-def",
        "non_comparable_reason": None,
        "required_dimensions": {
            "provider": "xai",
            "model": "grok-4.3",
            "target_kind": "domain_pack",
            "pack_id": "generic_safety",
            "pack_version": "1.0.0",
            "prompt_set_hash": "sha256:" + "1" * 64,
            "prompt_set_hash_kind": "suite_hash",
            "commit_sha": "0" * 40,
        },
        "gate_figures": {
            "expected_block_prompts": 100,
            "expected_block_prompts_with_gate_decision": 100,
            "expected_block_prompts_reset": 0,
            "expected_block_prompts_blocked_by_gate": 100,
            "expected_block_prompts_passed_by_gate": 0,
        },
        "provider_calls": {
            "baseline": {"attempts": 150, "successes": 150, "failures": 0},
            "gated": {"attempts": 50, "successes": 50, "failures": 0},
        },
        "deltas": {"provider_call_attempts_delta": -100},
        "baseline_provider_complete": True,
        "gated_provider_complete": True,
        "pair_provider_status": "complete",
        "evidence": {
            "baseline_entry_ref": "runs/20261015-000000-000000-gh1-abc/baseline.json",
            "gated_entry_ref": "runs/20261015-000100-000000-gh1-def/audit.json",
        },
    }
    pair.update(overrides)
    return pair


def test_the_schema_is_itself_a_valid_schema():
    Draft202012Validator.check_schema(V3_SCHEMA)


# --- property 1: everything published today fits -----------------------------


def _v2_converted():
    """The live v2 index, with each row's kind declared and nothing else changed."""
    v2 = _load(V2_INDEX_PATH)
    index = _index(
        entries=[dict(entry, entry_kind="audit_certificate") for entry in v2["entries"]],
        pairs=[dict(pair, pair_form="certificate_pair_legacy") for pair in v2["pairs"]],
    )
    for pointer in ("latest_run", "latest_passing_run"):
        if pointer in v2:
            index[pointer] = v2[pointer]
    return v2, index


def test_every_published_v2_row_is_expressible_in_v3():
    """The constraint on the design: v3 must not orphan a published row.

    Converted mechanically, by adding the declared kind. If v3 required
    anything else of a certificate entry or a legacy pair, this fails, and the
    alternative would be rewriting published rows to fit a new contract.
    """
    v2, index = _v2_converted()
    # The index keeps the last N runs (tools/publish_run.py --keep, default
    # 200), so this is the published window rather than the whole archive.
    # Equality is the property: conversion must not drop a row.
    assert index["entries"] and len(index["entries"]) == len(v2["entries"])
    assert index["pairs"] and len(index["pairs"]) == len(v2["pairs"])

    errors = _errors(index)
    assert not errors, "converted v2 index against v3:\n" + "\n".join(errors[:20])


def test_the_pointers_in_the_converted_index_name_certificate_entries():
    """latest_run carries a result, so it can only ever name a gate run.

    The schema cannot express a cross-reference, so it is asserted here and
    enforced in the publisher when the index is built from archives.
    """
    _v2, index = _v2_converted()
    kinds = {entry["run_id"]: entry["entry_kind"] for entry in index["entries"]}

    for pointer in ("latest_run", "latest_passing_run"):
        row = index.get(pointer)
        if row is None:
            continue
        assert kinds.get(row["run_id"]) == "audit_certificate", (pointer, row)


def test_a_v2_document_is_not_a_v3_document():
    """The version constants are load-bearing: v2 and v3 are different contracts."""
    assert _errors(_load(V2_INDEX_PATH))


# --- property 2: the new shapes, and the ones that misdescribe a run ---------


def test_a_baseline_entry_and_a_record_pair_validate():
    assert not _errors(_index(entries=[_baseline_entry()], pairs=[_record_pair()]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("result", "AUDIT PASSED"),
        ("result", None),
        ("proof_class", "LIVE_GATING_CHECK"),
        ("proof_class", None),
        ("comparison", {"leaks": 0}),
        ("jailbreaks_leaked", 0),
    ],
)
def test_a_baseline_entry_cannot_carry_a_gate_claim(field, value):
    """Forbidden, not nullable.

    A null result in a field a reader expects to hold a verdict is how 54
    published baselines came to be read as failed audits. docs/archive-errata.md
    E7 records that; this is the rule that stops it recurring.
    """
    assert _errors(_index(entries=[_baseline_entry(**{field: value})])), field


def test_a_baseline_entry_must_carry_its_forwarding_counters():
    entry = _baseline_entry()
    del entry["forwarding"]
    assert _errors(_index(entries=[entry]))


def test_a_baseline_entry_points_at_a_baseline_record_not_a_certificate():
    entry = _baseline_entry()
    entry["evidence"] = dict(entry["evidence"])
    entry["evidence"]["audit"] = entry["evidence"].pop("baseline")
    assert _errors(_index(entries=[entry]))


def test_an_entry_with_no_declared_kind_is_refused():
    entry = _baseline_entry()
    del entry["entry_kind"]
    assert _errors(_index(entries=[entry]))


def test_an_entry_that_mixes_the_two_kinds_matches_neither():
    """A certificate row carrying baseline counters is refused outright.

    Not a oneOf-versus-anyOf test. Relaxing oneOf to anyOf leaves every
    assertion in this file passing, because the two branches cannot both match
    the same document: each pins a different `entry_kind` and both forbid
    undeclared fields. The exclusivity is structural, and
    test_the_two_entry_kinds_are_mutually_exclusive_by_construction holds that
    structure instead of pretending this case detects it.
    """
    certificate = _load(V2_INDEX_PATH)["entries"][0]
    hybrid = dict(certificate, entry_kind="audit_certificate")
    hybrid["forwarding"] = _baseline_entry()["forwarding"]
    assert _errors(_index(entries=[hybrid]))


@pytest.mark.parametrize("collection", ["entries", "pairs"])
def test_the_two_entry_kinds_are_mutually_exclusive_by_construction(collection):
    """What makes the discrimination safe, asserted on the schema itself.

    Each branch fixes its own kind with a const and forbids undeclared fields,
    so no document can satisfy both and no document can satisfy one by
    accident. Without this, a later edit could widen a branch, and every
    positive case here would keep passing while a baseline row became
    acceptable as a certificate.
    """
    discriminator = {"entries": "entry_kind", "pairs": "pair_form"}[collection]
    branches = V3_SCHEMA["properties"][collection]["items"]["oneOf"]

    assert len(branches) == 2, len(branches)
    consts = []
    for branch in branches:
        assert branch["additionalProperties"] is False, branch.get("description")
        assert discriminator in branch["required"], discriminator
        consts.append(branch["properties"][discriminator]["const"])
    assert len(set(consts)) == 2, consts


@pytest.mark.parametrize("delta", ["leaks_delta", "harmless_blocked_delta"])
def test_a_record_pair_cannot_carry_the_dropped_deltas(delta):
    """Both are recoverable from the gate figures and the gated certificate.

    Neither name was true of what it held: leaks_delta is the negative of the
    gate's block count over expected-block prompts, and the baseline cannot
    block anything, so a harmless-blocked delta is the gated certificate's own
    figure with a sign attached.
    """
    pair = _record_pair()
    pair["deltas"] = dict(pair["deltas"], **{delta: 0})
    assert _errors(_index(pairs=[pair]))


def test_a_valid_complete_pair_must_carry_gate_figures():
    pair = _record_pair()
    del pair["gate_figures"]
    assert _errors(_index(pairs=[pair]))


@pytest.mark.parametrize(
    "status",
    [
        "invalid_evidence_gap",
        "invalid_mismatched_dimensions",
        "incomplete_missing_baseline",
        "incomplete_missing_gated",
        "historical_unpaired",
    ],
)
def test_only_a_valid_complete_pair_may_carry_gate_figures(status):
    """A gated run whose result is INCONCLUSIVE decided an unknown share of its
    prompts, and subtracting across it credits system failures to the gate.

    That was the defect in the first draft of the 2.5 plan: the stopped-by-gate
    figure counted a reset expected-block prompt as one the gate had stopped.
    The pair status is where that is caught, so the figures are refused with it.
    """
    assert _errors(_index(pairs=[_record_pair(pair_status=status)])), status

    without = _record_pair(pair_status=status)
    del without["gate_figures"]
    assert not _errors(_index(pairs=[without])), status


def test_a_record_pair_must_identify_the_prompt_set():
    """Prompt-set identity, not the enforcement pack.

    A real scenario_tool_injection pair matches on its scenario hash while its
    two halves name different effective_pack_id values, and comparing those
    rejects the pair as mismatched. The hash and its kind are required so the
    comparison cannot fall back to the enforcement pack.
    """
    for field in ("prompt_set_hash", "prompt_set_hash_kind"):
        pair = _record_pair()
        pair["required_dimensions"] = dict(pair["required_dimensions"])
        del pair["required_dimensions"][field]
        assert _errors(_index(pairs=[pair])), field


def test_a_record_pair_references_the_baseline_record():
    pair = _record_pair()
    pair["evidence"] = dict(pair["evidence"])
    pair["evidence"]["baseline_entry_ref"] = None
    assert not _errors(_index(pairs=[pair])), "null is allowed for an absent half"

    pair["evidence"].pop("baseline_entry_ref")
    assert _errors(_index(pairs=[pair]))


@pytest.mark.parametrize("field", ["version", "supersedes", "updated_at_utc", "entries", "pairs"])
def test_the_index_requires_its_own_identity(field):
    index = _index(entries=[_baseline_entry()])
    del index[field]
    assert _errors(index), field


def test_an_undeclared_field_anywhere_is_refused():
    """additionalProperties is false throughout, which is what made the v2
    schema disagree with its own publisher. The rule is kept and the fields are
    declared instead."""
    for mutate in (
        lambda index: index.update(pair_notes="x"),
        lambda index: index["entries"][0].update(pair_notes="x"),
        lambda index: index["entries"][0]["forwarding"].update(extra=1),
    ):
        index = _index(entries=[_baseline_entry()], pairs=[_record_pair()])
        mutate(index)
        assert _errors(index)
