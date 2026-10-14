"""What a pair may report, and the three rules that cost us to learn.

A pair is an ungated baseline record and a gated certificate over the same
prompt set. tools/pair_validation.py decides whether the two are comparable and
what the comparison may say. It is pure, so every shape the two documents can
take is testable here rather than through a benchmark run.

Each rule below was wrong in the 2.5 specification's first draft, and an
independent review found each one:

  1. the gate's blocks were computed as the baseline's expected-block count
     minus the gated run's leaks, which credits a systemic reset to the gate as
     a block it made. test_a_reset_is_not_credited_to_the_gate is that case,
     with the review's own numbers.
  2. a pair whose gated half is INCONCLUSIVE was compared anyway. It is now
     invalid_evidence_gap and carries no gate figure at all.
  3. pairs were matched on the enforcement pack, which rejects a real scenario
     pair whose halves name different enforcement packs for the same scenario.
     Identity is the prompt set's own hash, by the kind the record declares.

Checked on 15 October 2026 against five mutations of a scratch copy, never the
repository. Each count is what pytest reported:

    1. gate blocks = forwarded minus leaks, as the first draft had it  2 failed
    2. INCONCLUSIVE treated as comparable                              2 failed
    3. identity compared through effective_pack_id                     1 failed
    4. document kinds not checked before comparing                     3 failed
    5. gate figures attached to every status                           5 failed

and the restored copy passed 29 of 29. Mutation 3 is the one worth noting: it
fails only the scenario case, because a domain-pack pair's enforcement pack and
its registry pack are the same string. The pair it rejects is the real one.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import pair_validation as pairs  # noqa: E402

V3_SCHEMA = json.loads((ROOT / "spec/benchmark_index.v3.schema.json").read_text(encoding="utf-8"))

PROMPT_SET_HASH = "sha256:" + "a" * 64


def record(**overrides):
    document = {
        "record_kind": "sir_ungated_baseline",
        "record_version": 1,
        "run_id": "20261015-000000-000000-gh1-abc",
        "provider": "xai",
        "model": "grok-4.3",
        "pack_id": "generic_safety",
        "pack_version": "1.0.0",
        "commit_sha": "c" * 40,
        "prompt_set_hash": PROMPT_SET_HASH,
        "prompt_set_hash_kind": "suite_hash",
        "counters": {
            "prompts_forwarded": 150,
            "expected_block_prompts_forwarded": 100,
            "expected_allow_prompts_forwarded": 50,
            "provider_call_attempts": 150,
            "provider_call_successes": 150,
            "provider_call_failures": 0,
        },
    }
    counters = overrides.pop("counters", None)
    document.update(overrides)
    if counters:
        document["counters"] = dict(document["counters"], **counters)
    return document


def certificate(**overrides):
    document = {
        "result": "AUDIT PASSED",
        "prompts_tested": 150,
        "provider": "xai",
        "model": "grok-4.3",
        "pack_id": "generic_safety",
        "pack_version": "1.0.0",
        "commit_sha": "c" * 40,
        "suite_hash": PROMPT_SET_HASH,
        "content_block_prompts": 100,
        "content_allow_prompts": 50,
        "jailbreaks_leaked": 0,
        "harmless_blocked": 0,
        "provider_call_attempts": 50,
        "provider_call_successes": 50,
        "provider_call_failures": 0,
    }
    document.update(overrides)
    return document


# --- the ordinary case ------------------------------------------------------


def test_a_matched_pair_is_valid_and_reports_the_gate_figures():
    assessment = pairs.validate_pair(record(), certificate())

    assert assessment["pair_status"] == pairs.VALID_COMPLETE
    assert assessment["non_comparable_reason"] is None
    assert assessment["gate_figures"] == {
        "expected_block_prompts": 100,
        "expected_block_prompts_with_gate_decision": 100,
        "expected_block_prompts_reset": 0,
        "expected_block_prompts_blocked_by_gate": 100,
        "expected_block_prompts_passed_by_gate": 0,
    }
    assert assessment["deltas"] == {"provider_call_attempts_delta": -100}
    assert assessment["provider_calls"]["baseline"]["attempts"] == 150
    assert assessment["provider_calls"]["gated"]["attempts"] == 50


def test_the_published_deltas_are_recoverable():
    """Nothing a reader had before 2.5 is lost by dropping the two deltas.

    leaks_delta was the gated leak count minus the baseline's expected-block
    forwarding, and harmless_blocked_delta was the gated certificate's own
    figure, because a baseline blocks nothing.
    """
    gated = certificate(jailbreaks_leaked=27, harmless_blocked=3)
    assessment = pairs.validate_pair(record(), gated)
    figures = assessment["gate_figures"]

    leaks_delta = figures["expected_block_prompts_passed_by_gate"] - figures["expected_block_prompts"]
    assert leaks_delta == 27 - 100
    assert gated["harmless_blocked"] == 3


def test_a_leaky_gated_run_is_still_comparable():
    """AUDIT FAILED is a decided run. The pair reports what the gate did."""
    assessment = pairs.validate_pair(
        record(), certificate(result="AUDIT FAILED", jailbreaks_leaked=40)
    )

    assert assessment["pair_status"] == pairs.VALID_COMPLETE
    assert assessment["gate_figures"]["expected_block_prompts_blocked_by_gate"] == 60
    assert assessment["gate_figures"]["expected_block_prompts_passed_by_gate"] == 40


# --- rule 1: resets are not the gate's work ---------------------------------


def test_a_reset_is_not_credited_to_the_gate():
    """An independent review's case, 14 October 2026.

    Two expected-block prompts forwarded, one decided by the gate and blocked,
    one stopped by a systemic reset before any content decision. The first
    draft's subtraction reported two prompts stopped by the gate. One was.
    """
    assessment = pairs.validate_pair(
        record(counters={"expected_block_prompts_forwarded": 2, "prompts_forwarded": 2}),
        certificate(content_block_prompts=1, jailbreaks_leaked=0, prompts_tested=2),
    )

    figures = assessment["gate_figures"]
    assert figures["expected_block_prompts"] == 2
    assert figures["expected_block_prompts_with_gate_decision"] == 1
    assert figures["expected_block_prompts_reset"] == 1
    assert figures["expected_block_prompts_blocked_by_gate"] == 1, (
        "the reset prompt was credited to the gate"
    )


def test_the_reset_count_and_the_gate_counts_partition_the_prompts():
    figures = pairs.validate_pair(
        record(counters={"expected_block_prompts_forwarded": 10}),
        certificate(content_block_prompts=7, jailbreaks_leaked=2),
    )["gate_figures"]

    assert (
        figures["expected_block_prompts_reset"]
        + figures["expected_block_prompts_blocked_by_gate"]
        + figures["expected_block_prompts_passed_by_gate"]
        == figures["expected_block_prompts"]
    )


# --- rule 2: an inconclusive gated half ends the comparison -----------------


@pytest.mark.parametrize("result", ["INCONCLUSIVE", "", "AUDIT UNKNOWN", None])
def test_a_gated_half_that_did_not_decide_is_an_evidence_gap(result):
    assessment = pairs.validate_pair(record(), certificate(result=result))

    assert assessment["pair_status"] == pairs.INVALID_EVIDENCE_GAP
    assert "gate_figures" not in assessment, (
        "a pair that cannot be compared must publish no gate figure"
    )
    assert "no content decision" in assessment["non_comparable_reason"]


def test_an_evidence_gap_still_reports_the_provider_calls():
    """Transport completeness is observed, not inferred from the gate."""
    assessment = pairs.validate_pair(record(), certificate(result="INCONCLUSIVE"))

    assert assessment["pair_status"] == pairs.INVALID_EVIDENCE_GAP
    assert assessment["provider_calls"]["gated"]["attempts"] == 50
    assert assessment["deltas"]["provider_call_attempts_delta"] == -100


def test_a_gated_certificate_predating_the_reset_counter_is_an_evidence_gap():
    """Without content_block_prompts the decided prompts cannot be told from the
    reset ones, which is the figure rule 1 rests on."""
    gated = certificate()
    del gated["content_block_prompts"]
    assessment = pairs.validate_pair(record(), gated)

    assert assessment["pair_status"] == pairs.INVALID_EVIDENCE_GAP
    assert "content_block_prompts" in assessment["non_comparable_reason"]


# --- rule 3: identity is the prompt set, not the enforcement pack -----------


def test_a_scenario_pair_matches_on_its_scenario_hash():
    """The case that rejected a real pair.

    Both halves name different enforcement packs for the same scenario, which
    is the suite-versus-policy coupling in docs/backlog.md. Identity does not
    read that field.
    """
    assessment = pairs.validate_pair(
        record(prompt_set_hash_kind="scenario_hash", effective_pack_id="generic_safety"),
        certificate(
            scenario_hash=PROMPT_SET_HASH,
            suite_hash=PROMPT_SET_HASH,
            effective_pack_id="scenario_tool_injection",
        ),
    )

    assert assessment["pair_status"] == pairs.VALID_COMPLETE
    assert assessment["required_dimensions"]["target_kind"] == "scenario_pack"
    assert assessment["required_dimensions"]["prompt_set_hash_kind"] == "scenario_hash"


def test_a_scenario_record_is_not_matched_against_a_suite_hash():
    """The kind the record declares picks the field compared on the certificate."""
    assessment = pairs.validate_pair(
        record(prompt_set_hash_kind="scenario_hash"),
        certificate(scenario_hash="sha256:" + "b" * 64),
    )

    assert assessment["pair_status"] == pairs.INVALID_MISMATCHED_DIMENSIONS
    assert "prompt_set_hash" in assessment["non_comparable_reason"]


@pytest.mark.parametrize(
    "field", ["provider", "model", "pack_id", "pack_version", "commit_sha"]
)
def test_each_matched_dimension_is_load_bearing(field):
    assessment = pairs.validate_pair(record(), certificate(**{field: "something else"}))

    assert assessment["pair_status"] == pairs.INVALID_MISMATCHED_DIMENSIONS
    assert field in assessment["non_comparable_reason"]


def test_a_different_prompt_set_is_refused():
    assessment = pairs.validate_pair(record(), certificate(suite_hash="sha256:" + "d" * 64))

    assert assessment["pair_status"] == pairs.INVALID_MISMATCHED_DIMENSIONS
    assert "prompt_set_hash" in assessment["non_comparable_reason"]


# --- document kinds ---------------------------------------------------------


def test_two_certificates_are_a_pair_missing_its_baseline():
    """Which is what every pair published before 2.5 is."""
    assessment = pairs.validate_pair(certificate(), certificate())

    assert assessment["pair_status"] == pairs.INCOMPLETE_MISSING_BASELINE
    assert "not an ungated baseline record" in assessment["non_comparable_reason"]


def test_two_records_are_a_pair_missing_its_gated_half():
    assessment = pairs.validate_pair(record(), record())

    assert assessment["pair_status"] == pairs.INCOMPLETE_MISSING_GATED


def test_the_halves_are_not_interchangeable():
    """Handed the right documents the wrong way round, the pair is refused."""
    assessment = pairs.validate_pair(certificate(), record())

    assert assessment["pair_status"] == pairs.INCOMPLETE_MISSING_BASELINE


@pytest.mark.parametrize(
    ("baseline", "gated", "status"),
    [
        (None, "certificate", pairs.INCOMPLETE_MISSING_BASELINE),
        ("record", None, pairs.INCOMPLETE_MISSING_GATED),
    ],
)
def test_an_absent_half_is_named(baseline, gated, status):
    assessment = pairs.validate_pair(
        record() if baseline else None, certificate() if gated else None
    )
    assert assessment["pair_status"] == status


# --- the index contract -----------------------------------------------------


def _as_index_pair(assessment):
    """The assessment as the benchmark index v3 stores it."""
    pair = {
        "pair_form": "record_and_certificate",
        "pair_id": "20261015-000000-aaaaaaaaaaaa",
        "pair_key": "provider=xai|model=grok-4.3",
        "baseline_run_id": "20261015-000000-000000-gh1-abc",
        "gated_run_id": "20261015-000100-000000-gh1-def",
        "baseline_provider_complete": True,
        "gated_provider_complete": True,
        "pair_provider_status": "complete",
        "evidence": {
            "baseline_entry_ref": "runs/a/baseline.json",
            "gated_entry_ref": "runs/b/audit.json",
        },
    }
    pair.update(assessment)
    return {
        "version": "benchmark_index.v3",
        "supersedes": "benchmark_index.v2",
        "updated_at_utc": "2026-10-15T00:00:00Z",
        "entries": [],
        "pairs": [pair],
    }


def _schema_errors(document):
    return [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in Draft202012Validator(V3_SCHEMA).iter_errors(document)
    ]


def test_a_valid_assessment_satisfies_the_index_contract():
    """What this module computes is what the index will be asked to hold."""
    assessment = pairs.validate_pair(record(), certificate())
    assert not _schema_errors(_as_index_pair(assessment))


def test_an_evidence_gap_assessment_satisfies_the_index_contract():
    """And the schema's rule that only a valid pair carries gate figures is the
    same rule this module applies, so the two cannot drift apart silently."""
    assessment = pairs.validate_pair(record(), certificate(result="INCONCLUSIVE"))
    assert not _schema_errors(_as_index_pair(assessment))


def test_the_dropped_deltas_are_not_produced():
    for assessment in (
        pairs.validate_pair(record(), certificate()),
        pairs.validate_pair(record(), certificate(result="INCONCLUSIVE")),
    ):
        assert "leaks_delta" not in assessment.get("deltas", {})
        assert "harmless_blocked_delta" not in assessment.get("deltas", {})


# --- purity -----------------------------------------------------------------


def test_the_module_reads_nothing_and_writes_nothing():
    """A pure function of the two documents, which is why the cases above can
    cover every shape. A module that read a file would be tested through
    whatever produced that file."""
    import ast

    source = (ROOT / "tools/pair_validation.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    forbidden = {"open", "print", "input"}
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & forbidden, called & forbidden

    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else node.names)
    }
    assert not imported & {"os", "pathlib", "subprocess", "json", "datetime", "time"}, imported


def test_validation_does_not_mutate_its_inputs():
    baseline, gated = record(), certificate()
    before = (json.dumps(baseline, sort_keys=True), json.dumps(gated, sort_keys=True))

    pairs.validate_pair(baseline, gated)

    assert (json.dumps(baseline, sort_keys=True), json.dumps(gated, sort_keys=True)) == before
