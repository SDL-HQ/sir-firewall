#!/usr/bin/env python3
"""What a paired benchmark may say, computed from the two signed documents.

A pair is an ungated baseline record and a gated certificate over the same
prompt set. This module decides whether they are comparable and, if they are,
what the comparison is entitled to report. It reads nothing from disk and
writes nothing: the caller supplies both documents, which is why it can be
tested over every shape they can take.

Three rules here exist because the 2.5 specification's first draft got them
wrong, and an independent review found each one.

**Reset accounting.** The draft reported the gate's blocks as the baseline's
expected-block count minus the gated run's leaks. With a systemic reset in the
gated half, an expected-block prompt that never reached a content decision was
credited to the gate as a block it had made. The figures are now computed from
the gated certificate's own content_block_prompts, which counts expected-block
prompts the gate actually decided, and the difference from the baseline's count
is reported as reset rather than folded into the gate's work.

**Applicability.** A gated run whose own result is INCONCLUSIVE decided an
unknown share of its prompts. No gate figure is reported for such a pair at
all; the pair is `invalid_evidence_gap`. Subtracting across an inconclusive run
is how the first defect happened.

**Prompt-set identity.** Pairs are matched on the prompt set's own hash, not on
the enforcement pack. A real scenario_tool_injection pair matches on its
scenario hash while its two halves name different effective_pack_id values, and
comparing those rejects a valid pair as mismatched. The suite-versus-policy
coupling behind that is recorded in docs/backlog.md and is not fixed here.

What a pair never carries, from 2.5: leaks_delta and harmless_blocked_delta.
docs/benchmark-cycle.v1.md had to warn readers that leaks_delta was not harm
prevented, and a figure whose name has to be disclaimed is the wrong figure.
Both are recoverable from what is here and from the gated certificate.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

RECORD_KIND = "sir_ungated_baseline"

VALID_COMPLETE = "valid_complete"
INCOMPLETE_MISSING_BASELINE = "incomplete_missing_baseline"
INCOMPLETE_MISSING_GATED = "incomplete_missing_gated"
INVALID_MISMATCHED_DIMENSIONS = "invalid_mismatched_dimensions"
INVALID_EVIDENCE_GAP = "invalid_evidence_gap"

# Results a gated certificate may carry and still be compared. INCONCLUSIVE is
# deliberately absent: it means an unknown share of the prompts reached no
# content decision.
COMPARABLE_RESULTS = ("AUDIT PASSED", "AUDIT FAILED")

# Dimensions both halves must agree on, beyond the prompt set's own hash.
MATCHED_DIMENSIONS = ("provider", "model", "pack_id", "pack_version", "commit_sha")


def _int_or_none(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _is_baseline_record(document: Dict[str, Any]) -> bool:
    return document.get("record_kind") == RECORD_KIND


def _is_certificate(document: Dict[str, Any]) -> bool:
    return "record_kind" not in document and "result" in document and "prompts_tested" in document


def _provider_calls(document: Dict[str, Any], *, counters: Dict[str, Any]) -> Dict[str, Optional[int]]:
    return {
        "attempts": _int_or_none(counters.get("provider_call_attempts")),
        "successes": _int_or_none(counters.get("provider_call_successes")),
        "failures": _int_or_none(counters.get("provider_call_failures")),
    }


def _assessment(
    status: str,
    *,
    reason: Optional[str] = None,
    dimensions: Optional[Dict[str, Any]] = None,
    provider_calls: Optional[Dict[str, Any]] = None,
    deltas: Optional[Dict[str, Any]] = None,
    gate_figures: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    assessment: Dict[str, Any] = {
        "pair_status": status,
        "non_comparable_reason": reason,
        "required_dimensions": dimensions or {},
    }
    if provider_calls is not None:
        assessment["provider_calls"] = provider_calls
    if deltas is not None:
        assessment["deltas"] = deltas
    # Present only on a valid_complete pair. The v3 index schema refuses it on
    # any other status, so this is the same rule stated in two places that
    # tests/test_pair_validation.py holds together.
    if gate_figures is not None:
        assessment["gate_figures"] = gate_figures
    return assessment


def required_dimensions(
    baseline_record: Dict[str, Any], gated_certificate: Dict[str, Any]
) -> Dict[str, Any]:
    """The pair's identity, taken from the gated half and the record's own hash."""
    kind = baseline_record.get("prompt_set_hash_kind")
    return {
        "provider": gated_certificate.get("provider"),
        "model": gated_certificate.get("model"),
        "target_kind": "scenario_pack" if kind == "scenario_hash" else "domain_pack",
        "pack_id": gated_certificate.get("pack_id"),
        "pack_version": gated_certificate.get("pack_version"),
        "prompt_set_hash": baseline_record.get("prompt_set_hash"),
        "prompt_set_hash_kind": kind,
        "commit_sha": gated_certificate.get("commit_sha"),
    }


def _row_coverage_mismatch(
    baseline_record: Dict[str, Any], gated_certificate: Dict[str, Any]
) -> Optional[str]:
    """Whether the two halves ran the same number of prompts.

    A matching prompt-set hash says the two halves selected the same suite
    file. It does not say they ran all of it. A baseline whose run stopped
    after k of n rows, or whose rows were filtered, carries the same
    suite_hash as a gated run that covered all n, and every dimension above
    matches.

    The gate figures survive the case where the missing rows are labelled
    block, because gate_figures refuses when the gated run decided more
    expected-block prompts than the baseline forwarded. They do not survive
    the case where only allow-labelled rows are missing: every gate figure is
    then correct and provider_call_attempts_delta is computed across two
    different row counts, so it reads as calls the gate stopped when some of
    it is prompts the baseline never sent.

    The runner cannot produce this: proofs/run_summary.json is written after
    the loop, so a run that stops partway publishes no record. What it takes
    is a hand-built ledger, which is the producer section 9 of the
    specification says the record cannot rule out. The pair validator can
    notice, and that is cheaper than a reader noticing.
    """
    forwarded = _int_or_none((baseline_record.get("counters") or {}).get("prompts_forwarded"))
    tested = _int_or_none(gated_certificate.get("prompts_tested"))
    if forwarded is None or tested is None:
        return None
    if forwarded != tested:
        return (
            f"the halves cover different row counts: the baseline forwarded {forwarded} "
            f"and the gated run tested {tested}. A matching prompt-set hash says they "
            "selected the same suite, not that they ran all of it."
        )
    return None


def _identity_mismatches(
    baseline_record: Dict[str, Any], gated_certificate: Dict[str, Any]
) -> Tuple[list, Optional[str]]:
    mismatches = [
        field
        for field in MATCHED_DIMENSIONS
        if str(baseline_record.get(field) or "") != str(gated_certificate.get(field) or "")
    ]

    kind = baseline_record.get("prompt_set_hash_kind")
    if kind not in ("suite_hash", "scenario_hash"):
        return mismatches, f"the baseline record names no prompt-set hash kind: {kind!r}"

    # The gated certificate carries both hashes by name; the record carries one
    # and says which it is. Compared by that name, never through the
    # enforcement pack.
    baseline_hash = str(baseline_record.get("prompt_set_hash") or "")
    gated_hash = str(gated_certificate.get(kind) or "")
    if not baseline_hash or not gated_hash:
        return mismatches, (
            f"a prompt-set hash is missing: baseline {baseline_hash or 'absent'}, "
            f"gated {kind}={gated_hash or 'absent'}"
        )
    if baseline_hash != gated_hash:
        mismatches.append("prompt_set_hash")
    return mismatches, None


def gate_figures(
    baseline_record: Dict[str, Any], gated_certificate: Dict[str, Any]
) -> Tuple[Optional[Dict[str, int]], Optional[str]]:
    """What the gate did to the expected-block prompts, or why it cannot be said.

    Every figure is from one of the two signed documents. Nothing is inferred
    from a delta, which is the arithmetic that credited system failures to the
    gate.
    """
    counters = baseline_record.get("counters")
    counters = counters if isinstance(counters, dict) else {}
    forwarded = _int_or_none(counters.get("expected_block_prompts_forwarded"))
    decided = _int_or_none(gated_certificate.get("content_block_prompts"))
    leaked = _int_or_none(gated_certificate.get("jailbreaks_leaked"))

    if forwarded is None:
        return None, "the baseline record carries no expected-block forwarding count"
    if decided is None:
        return None, (
            "the gated certificate carries no content_block_prompts, so the prompts the "
            "gate decided cannot be told from the prompts a system failure stopped"
        )
    if leaked is None:
        return None, "the gated certificate carries no leak count"

    if decided > forwarded:
        return None, (
            f"the gated run decided {decided} expected-block prompts and the baseline "
            f"forwarded {forwarded}; the halves disagree about the prompt set"
        )
    if leaked > decided:
        return None, (
            f"the gated run reports {leaked} leaks among {decided} decided expected-block "
            "prompts"
        )

    return {
        "expected_block_prompts": forwarded,
        "expected_block_prompts_with_gate_decision": decided,
        "expected_block_prompts_reset": forwarded - decided,
        "expected_block_prompts_blocked_by_gate": decided - leaked,
        "expected_block_prompts_passed_by_gate": leaked,
    }, None


def validate_pair(
    baseline_record: Optional[Dict[str, Any]], gated_certificate: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Assess one pair. Pure: no I/O, no clock, no environment."""
    if baseline_record is None:
        return _assessment(INCOMPLETE_MISSING_BASELINE, reason="no baseline record was supplied")
    if gated_certificate is None:
        return _assessment(INCOMPLETE_MISSING_GATED, reason="no gated certificate was supplied")

    # Document kind, before anything is compared. A pair of two certificates is
    # what every pair published before 2.5 was, and it is missing its baseline.
    if not _is_baseline_record(baseline_record):
        return _assessment(
            INCOMPLETE_MISSING_BASELINE,
            reason=(
                "the baseline half is not an ungated baseline record "
                f"(record_kind={baseline_record.get('record_kind')!r})"
            ),
        )
    if not _is_certificate(gated_certificate):
        return _assessment(
            INCOMPLETE_MISSING_GATED,
            reason=(
                "the gated half is not an audit certificate "
                f"(record_kind={gated_certificate.get('record_kind')!r})"
            ),
        )

    dimensions = required_dimensions(baseline_record, gated_certificate)
    mismatches, identity_error = _identity_mismatches(baseline_record, gated_certificate)
    if identity_error:
        return _assessment(INVALID_EVIDENCE_GAP, reason=identity_error, dimensions=dimensions)
    if mismatches:
        return _assessment(
            INVALID_MISMATCHED_DIMENSIONS,
            reason="mismatched required attribution dimensions: " + ", ".join(sorted(mismatches)),
            dimensions=dimensions,
        )

    coverage_mismatch = _row_coverage_mismatch(baseline_record, gated_certificate)
    if coverage_mismatch:
        return _assessment(
            INVALID_MISMATCHED_DIMENSIONS, reason=coverage_mismatch, dimensions=dimensions
        )

    baseline_counters = baseline_record.get("counters")
    baseline_counters = baseline_counters if isinstance(baseline_counters, dict) else {}
    provider_calls = {
        "baseline": _provider_calls(baseline_record, counters=baseline_counters),
        "gated": _provider_calls(gated_certificate, counters=gated_certificate),
    }
    baseline_attempts = provider_calls["baseline"]["attempts"]
    gated_attempts = provider_calls["gated"]["attempts"]
    deltas = {
        "provider_call_attempts_delta": (
            None
            if baseline_attempts is None or gated_attempts is None
            # Gated minus baseline, the direction the published pairs use, so
            # the value is negative whenever the gated run made fewer calls.
            #
            # Its magnitude is forwarded prompts that did not reach the
            # provider on the gated side, and the gate is not the only reason
            # one did not: a systemic reset stops the run before the gate
            # decides the rows it had not reached. So this is gate blocks plus
            # reset-stopped rows, and it is the gate's blocks alone only when
            # the gated run reset nothing. The comment here used to call it
            # "requests the gate stopped", which is the magnitude with both the
            # sign and the reset case dropped.
            else gated_attempts - baseline_attempts
        )
    }

    result = str(gated_certificate.get("result") or "").strip()
    if result not in COMPARABLE_RESULTS:
        return _assessment(
            INVALID_EVIDENCE_GAP,
            reason=(
                f"the gated run's result is {result!r}, so an unknown share of its prompts "
                "reached no content decision and no gate figure can be computed"
            ),
            dimensions=dimensions,
            provider_calls=provider_calls,
            deltas=deltas,
        )

    figures, figures_error = gate_figures(baseline_record, gated_certificate)
    if figures is None:
        return _assessment(
            INVALID_EVIDENCE_GAP,
            reason=figures_error,
            dimensions=dimensions,
            provider_calls=provider_calls,
            deltas=deltas,
        )

    return _assessment(
        VALID_COMPLETE,
        dimensions=dimensions,
        provider_calls=provider_calls,
        deltas=deltas,
        gate_figures=figures,
    )
