# D11 — Structured evidence surfacing review (April 5, 2026)

## Scope

This D11 round reviewed deterministic gate-native metadata that already exists in current machine surfaces.

Non-goals enforced in this review:

- no payload analysis
- no semantic clustering
- no threat-intelligence overclaiming
- no scorecards or dashboard expansion
- no new independent truth surface

## Surfaces reviewed

- `tools/publish_run.py`
- `spec/benchmark_index.v1.schema.json`
- `proofs/runs/benchmark_index.v1.json`
- `docs/benchmark-cycle.v1.md`
- `docs/d5-benchmark-first-cycle-review.md`
- `docs/assurance-kit.md`
- `docs/evaluator-technical-explainer.md`

## What gate-native metadata already exists but was under-surfaced

From current benchmark rows, SIR already provides deterministic fields needed for narrow evidence reading:

- explicit comparability identity: `row_identity`
- target attribution: `evaluation_target.target_kind`, `pack_id`, `pack_version`, optional `scenario_id`
- proof class attribution: `proof_class`
- run outcome: `result`
- integrity continuity anchors: `comparison.trust_fingerprint`, `comparison.itgl_final_hash`
- provider/model/run context and evidence links

These are sufficient for evaluators to inspect repeated-run behavior without adding analytics constructs.

## Metadata that improves legibility now (without product drift)

D11 decision: clarify usage of existing fields rather than introducing new machine fields.

Recommended in-scope evaluator reads:

1. Repeated outcome pattern by `row_identity` (PASS/FAIL/INCONCLUSIVE sequence).
2. Certificate series stability check via repeated `comparison.trust_fingerprint` values.
3. Integrity chain stability check via repeated `comparison.itgl_final_hash` values.

These are deterministic restatements from existing benchmark entries and do not create ranking semantics.

## Metadata explicitly deferred/rejected now

Deferred to avoid analytics creep or weak inference:

- rule/category hit distribution summaries
- proof-class distribution summaries as performance-like metrics
- pack/scenario coverage-over-time trend surfaces
- any weighted/composite score, ranking, leaderboard, or dashboard layer

## Implementation decision

D11 makes a review-first, minimal decision:

- docs clarified to state what deterministic evidence reads are in scope
- docs clarified to state what remains out of scope
- no benchmark schema changes
- no benchmark publisher output changes

Reason: no unambiguous machine-surface addition was required to improve evaluator readability at this stage.

## Revisit trigger (future)

Revisit only if repeated evaluator/auditor reviews show consistent friction that cannot be resolved with existing row fields and plain guidance.
Any future addition must remain deterministic, attributable, non-derived, and non-scoring.
