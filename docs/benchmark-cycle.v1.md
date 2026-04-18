# SIR Canonical Benchmark Cycle v1

This document locks the **first benchmark cycle contract**.

Scope is intentionally narrow: define one small, repeatable set and how to record it for apples-to-apples comparison.
For comparison wording discipline used in round reviews, see `docs/comparison-discipline.v2.md`.

## R1 E3a binding clarification (operator-executable vs exploratory)

For the R1 E3 current-line execution path, keep operator-executable benchmark runs and exploratory structured validation explicitly separate.

Operator-executable E3 line (registry-managed `pack_id` via `sir run --pack ...`):

- `generic_safety`
- `support_operator_override`
- `data_exfiltration_pressure`

Separate exploratory structured validation surface (not operator `--pack` execution):

- `structured_account_recovery_benchmark` fixture at `tests/domain_packs/structured_account_recovery_benchmark.json`
- validation path remains the structured fixture test surface (`tests/test_structured_benchmark_pack.py`)

This clarification does not admit a new registry pack, does not expand operator execution semantics, and does not change benchmark/proof/archive semantics.

## Canonical first benchmark set (locked)

Run exactly these packs/proof classes for cycle `benchmark_cycle.v1`:

1. `generic_safety` as `FIREWALL_ONLY_AUDIT` (taxonomy coverage: `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection`)
2. `support_operator_override` as `FIREWALL_ONLY_AUDIT` (taxonomy coverage: `benign_control`, `direct_bypass`, `exfiltration`)
3. `data_exfiltration_pressure` as `FIREWALL_ONLY_AUDIT` (taxonomy coverage: `benign_control`, `exfiltration`)

Current core benchmark pack sizes:

- `generic_safety` = 150
- `support_operator_override` = 50
- `data_exfiltration_pressure` = 50

Why this set:

- `generic_safety` is the broad baseline continuity anchor.
- `support_operator_override` adds explicit operator-override pressure on the same operator-executable surface.
- `data_exfiltration_pressure` adds explicit exfiltration-pressure coverage on the same operator-executable surface.

Out of scope for v1: broad pack sweeps, scenario-pack expansion in this operator line, model tournaments, scoring/ranking logic.

## Valid benchmark cycle criteria

A benchmark cycle counts as **valid canonical cycle v1** only when all of the following are true:

- All 3 required runs above are executed and archived.
- Every run has a published archive directory with:
  - `manifest.json`
  - `audit.json`
  - `archive_receipt.json`
  - copied `proofs/run_summary.json`
  - copied `proofs/itgl_ledger.jsonl`
  - copied `proofs/itgl_final_hash.txt`
  - copied `proofs/latest-attempts.log`
- `proofs/runs/benchmark_index.v1.json` includes attributable rows for each required run.
- Rows include explicit `evaluation_target`, `proof_class`, `provider`, `model`, and `row_identity` fields.

A cycle is **non-comparable / out-of-band** if any required row is missing, unarchived, malformed, or mixed with ad-hoc dimensions that change attribution semantics.

## Procedure (run order and repeatability)

Run order for each cycle:

1. Audit baseline: `generic_safety` (`FIREWALL_ONLY_AUDIT`; taxonomy coverage `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection`)
2. Audit operator-override pressure: `support_operator_override` (`FIREWALL_ONLY_AUDIT`; taxonomy coverage `benign_control`, `direct_bypass`, `exfiltration`)
3. Audit exfiltration-pressure slice: `data_exfiltration_pressure` (`FIREWALL_ONLY_AUDIT`; taxonomy coverage `benign_control`, `exfiltration`)

Repeatability expectations:

- Use the same committed pack versions from `spec/packs/pack_registry.v1.json`.
- Keep run command semantics stable (`sir run --mode audit|scenario|live --pack <pack_id>`).
- Treat provider/model as recorded metadata; do not backfill or rename after run publication.
- Do not collapse proof classes: compare within the same `proof_class` only.

## Provider/model naming rules (locked)

For repeatable comparison rows:

- Record provider/model exactly as emitted in `audit.json` and copied to benchmark index.
- Keep original case and separators; no alias normalization in v1.
- Missing provider/model is allowed only for audit rows where no model call path exists.

## Naming and output conventions

- Canonical cycle label: `benchmark_cycle.v1` (documentation contract label).
- Machine index stays `benchmark_index.v1` (`proofs/runs/benchmark_index.v1.json`).
- Use `row_identity` as the strict comparability key. Rows are comparable only when `row_identity` dimensions align (`sir`, `commit`, `target`, `proof_class`, `provider`, `model`).
- Keep domain-pack and scenario-pack rows separate via `evaluation_target.target_kind`; never blend them into one row interpretation.

## Interpretation rules

- `comparison` values are observed run metadata only (not scores, no ranking).
- `latest_run` and `latest_passing_run` pointers remain informational and do not replace row-level evidence checks.
- Trend read-through is allowed only against prior rows with matching `row_identity` attribution semantics.

## B1 baseline cycle attempt record (2026-04-16, historical note)

This section records the B1 post-2.0 baseline attempt as historical context only.

- date (UTC): `2026-04-16`
- why run: establish the first clean post-2.0 baseline attempt after documented weak-attribution local artefacts in the earlier 2026-04-05 local cluster
- provider/model recorded by run artefacts: `xai` / `xai/grok-3-beta`
- cycle status: **PARTIAL** (not full)
- live blocker for partial status:
  - `ERROR: LIVE mode requires your own provider credentials (XAI_API_KEY). Set XAI_API_KEY before running LIVE mode. SIR does not ship keys.`

Rows executed and archived in this B1 attempt:

1. `generic_safety` + `FIREWALL_ONLY_AUDIT`
   - run_id: `20260416-003923-000000-ef03803fc756`

This B1 record predates the current operator-executable three-pack line defined above and is not a completeness record for the current line.

Semantics note:

- Gate outcomes remain `PASS` / `BLOCK` at prompt level.
- Run/publication status remains `PASS` / `FAIL` / `INCONCLUSIVE` where applicable.
- The B1 cycle record status (`PARTIAL`) describes cycle completeness only and does not redefine gate or run result semantics.

## Change control

Any expansion beyond this first set (additional packs, additional live permutations, ranking logic, dashboards) is post-D4 scope and requires a new contract revision.

## D11 structured evidence surfacing decision (review-only)

D11 reviewed deterministic gate-native metadata already present in run artefacts and benchmark rows.

Decision for v1:

- Keep benchmark index as an evidence map, not an analytics surface.
- Do not add scorecards, rankings, or derived trend metrics.
- Allow lightweight readability checks performed by evaluators from existing deterministic fields.

What is already available and should be read more explicitly:

- repeated outcome patterns for the same `row_identity` (PASS/FAIL/INCONCLUSIVE sequence)
- certificate/integrity continuity via repeated `comparison.trust_fingerprint` and `comparison.itgl_final_hash`
- target/proof-class attribution via `evaluation_target` + `proof_class`

What is explicitly not surfaced in v1:

- rule/category hit distribution rollups
- proof-class distribution rollups as summary metrics
- pack/scenario coverage-over-time rollups beyond cycle validity checks
- any weighted scoring, ranking, composite index, or dashboard surface

Rationale:

- The allowed reads above are deterministic restatements of existing row metadata.
- New aggregate metadata fields were not added in D11 because current evidence remains auditable without creating a second truth surface.
- Additional machine-surface summarization can be revisited only if evaluator friction persists and the change remains non-derived, deterministic, and non-analytic.
