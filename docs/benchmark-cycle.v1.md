# SIR Canonical Benchmark Cycle v1 + E1 Pair Contract Lock

This document locks the **first benchmark cycle contract** and the **E1 paired benchmark contract direction**.

Scope is intentionally narrow: define one small, repeatable set and how to record it for apples-to-apples comparison.
For comparison wording discipline used in round reviews, see `docs/comparison-discipline.v2.md`.

## E1 benchmark contract lock (authoritative)

E1 locks benchmark semantics without changing audit/proof/archive foundations.

### Surface separation (locked)

- **Audit row evidence**: single-run evidence from archived run artifacts.
- **Benchmark**: a comparison method layered over audit row evidence.
- **Live gating evidence**: single-run audit evidence where `proof_class=LIVE_GATING_CHECK`.

Benchmark is not a proof class and does not replace row-level evidence.

### Ungated baseline definition (locked)

For benchmark pairing, **ungated baseline** means:

- the same prompt set forwarded to the provider **without SIR pre-inference gate intervention**
- run under attributable conditions required for pair comparability

This is stricter than "non-provider-call row" and must not be inferred from provider-call counts alone.

From SIR 2.5 an ungated baseline requires live mode and produces a **signed
baseline record** at `baseline.json`, not an audit certificate. The record
carries one claim: that this prompt set was forwarded to the named provider
with the gate out of the path, and what came back at the transport level. It
carries no result and no proof class, because a run with no gate in it has
nothing to say about the gate. Its rows record status `FORWARDED`, which means
a provider call was attempted with that row's content and is not a gate
decision; the gate returns only `PASS` or `BLOCKED`, so a `FORWARDED` row
cannot come from a gated run. Each row also carries `row_version`, the baseline
row format it is in, which the record declares once in its `ledger` block; a
verifier refuses a format it does not read rather than applying this format's
rules to it. `docs/terminology.md` says why it is covered by the chain and not
by the per-prompt digest.

**What the ungated half is for.** Stated here because the documents described
what a baseline record is before they said why one is run, and the first
dispatch under this design publishes evidence.

A baseline record establishes that a named prompt set was forwarded to a named
provider with the gate out of the path, and how many of those calls returned.
That is its whole claim. It is the provenance half of a comparison whose
measured side is the gated run: it fixes which prompts went to which model
under which repository state, so the gated run's own figures can be attributed
to that prompt set rather than asserted over one nobody can identify.

It is **not** a control for the provider's own safety layer. Telling what the
provider did with a forwarded prompt would require reading the response back,
and the baseline does not: `provider_call_outcome` records whether the call
raised, so a provider's content-policy refusal that returns a response counts
as a success, and one returned as an error counts as a failure that cannot be
told apart from an outage. `docs/terminology.md` states that definition and
`docs/evidence-perimeter.v6.md` lists what a verified record therefore does not
establish.

So a pair says what the gate did to a prompt set the baseline identifies. It
does not say what the provider would have done without the gate, and no figure
in a pair is named as though it did.

Baselines published before 2.5 are audit certificates. All 54 of them say
`"result": "AUDIT FAILED"` under a proof class naming firewall activity that
did not occur. They stay published, are not re-signed, and carry a
qualification wherever their result is shown. `docs/archive-errata.md` records
what they are.

### Paired benchmark unit (locked for successor schema)

A paired benchmark unit is:

1. `baseline` (ungated baseline as defined above)
2. `gated` (SIR gated run)

With identical required attribution dimensions:

- provider
- model
- target kind
- pack id
- pack version (or equivalent prompt-set identity)
- commit/context
- other required attribution dimensions declared by schema

And, for pairs published before SIR 2.5, explicit deltas:

- `leaks_delta`
- `harmless_blocked_delta`
- `provider_call_attempts_delta` (when relevant to compared rows)

`leaks_delta` must not be read as harm prevented. An ungated baseline row records
no gate decision and no assessment of the model's response, so the baseline leak
count is the number of prompts the suite labels as requiring a block, and the
delta is the number of prompts the gate blocked, reported from the other side.
A gated run's own leak count is a genuine gate-conformance measure and may be
compared across rule versions.

`provider_call_attempts_delta` is the one delta that survives into 2.5, and its
earlier description here was wrong in two ways. It is stored as **gated attempts
minus baseline attempts**, so it is negative whenever the gate stopped a call:
the published pairs carry `-74` against a baseline of 150 attempts and a gated
run of 76. The earlier sentence called it "requests that did not reach the
provider because the gate stopped them", which is its magnitude with the sign
dropped.

Its magnitude is the number of forwarded prompts that did not reach the provider
on the gated side, and the gate is not the only reason a prompt did not. A
systemic reset stops a run before the gate decides the rows it had not reached,
and those rows did not reach the provider either. So the magnitude is gate
blocks plus reset-stopped rows, and it equals the gate's blocks only when the
gated run reset nothing. Read the gated certificate's own `systemic_reset_count`
to tell the two apart, and `expected_block_prompts_reset` below for the
labelled prompts specifically.

**From SIR 2.5 a pair carries no leak delta and no harmless-blocked delta.**
The paragraph above is the reason: a figure that has to be explained in four
sentences before it can be read is better replaced than annotated. In their
place a pair states the gate's own figures over the prompts the suite labels
for blocking, all counted from the two signed documents:

- `expected_block_prompts`: how many the prompt set labels for blocking
- `expected_block_prompts_with_gate_decision`: how many the gate decided
- `expected_block_prompts_blocked_by_gate`
- `expected_block_prompts_passed_by_gate`
- `expected_block_prompts_reset`: how many the gate did not decide, because a
  system failure reset the run before it reached them

The last one is why the deltas went. A subtraction credits a reset
expected-block prompt to the gate, which did not see it.

These five are **three leaves and two totals**, not a five-way partition, and
the earlier wording here said otherwise. `expected_block_prompts` is the total.
The partition of it is the three leaves:

    expected_block_prompts_reset
    + expected_block_prompts_blocked_by_gate
    + expected_block_prompts_passed_by_gate
    = expected_block_prompts

`expected_block_prompts_with_gate_decision` is a subtotal of two of those
leaves, `blocked_by_gate + passed_by_gate`. So a reader can see what the gate
decided and what it never reached, which is the point, but the five figures are
not five disjoint parts of anything.

A pair publishes these figures only when it is `valid_complete`, which requires
the gated run's result to be `AUDIT PASSED` or `AUDIT FAILED`. An
`INCONCLUSIVE` gated run makes the pair `invalid_evidence_gap` and it publishes
no gate figures at all: a run whose own evidence is incomplete cannot be the
measured side of a comparison.

Both old deltas remain derivable from the new fields, so nothing published
becomes unrecoverable, on one identity worth stating rather than relying on.
`leaks_delta` was the gated leak count minus the baseline leak count, and the
baseline leak count was equal to the labelled count: an ungated run recorded
`PASS` on every row, so every prompt labelled for blocking counted as a leak.
That is why `expected_block_prompts` can stand in for it, and
`leaks_delta` is `expected_block_prompts_passed_by_gate -
expected_block_prompts`. The identity would fail for a legacy baseline that had
reset rows, which would have been excluded from its leak count; none of the 54
published baseline certificates carries a reset counter at all, so for every
published pair the recovery is exact. `harmless_blocked_delta` is the gated run's
own `harmless_blocked`, because an ungated run blocks nothing and all 54 report
`harmless_blocked` of zero.

Pairs compare **prompt-set identity**, `suite_hash` for a CSV suite or
`scenario_hash` for a scenario, together with the registry pack id that
selected it. They do not compare `effective_pack_id`, which is the enforcement
pack: two runs over the same prompt set can carry different enforcement packs,
and rejecting that pair would be rejecting it for a difference the comparison
is not about. Provider, model and commit must match, as before.

### Pair status values (locked)

Use machine-clear status labels only:

- `valid_complete`
- `incomplete_missing_baseline`
- `incomplete_missing_gated`
- `invalid_mismatched_dimensions`
- `invalid_evidence_gap`
- `historical_unpaired`

**What produces each.** The list above was locked without saying which case
reaches which label, so a reader holding a non-`valid_complete` pair could not
tell what had gone wrong, and the cases 2.5 added had no stated home. Every
status below is produced by `tools/pair_validation.py`, and every one it
produces carries a `non_comparable_reason` naming the specific case.

| Status | Produced when |
|---|---|
| `valid_complete` | Both halves are present and of the right kind, every required attribution dimension matches, the halves cover the same row count, the gated run's result is `AUDIT PASSED` or `AUDIT FAILED`, and the gate figures compute. Only this status carries gate figures. |
| `incomplete_missing_baseline` | No baseline half was supplied, **or** the baseline half is not an ungated baseline record. The second case is every pair published before 2.5: both halves are certificates, so the pair is missing its baseline rather than holding a defective one. |
| `incomplete_missing_gated` | No gated half was supplied, **or** the gated half is not an audit certificate, which includes a pair of two baseline records. |
| `invalid_mismatched_dimensions` | A required attribution dimension differs, including the prompt set's own hash, **or** the two halves report different row counts. The row-count case is new in 2.5: a matching prompt-set hash says both halves selected the same suite, not that both ran all of it. |
| `invalid_evidence_gap` | The halves are comparable but no figure may be computed. The baseline names no prompt-set hash kind, or a hash is absent; or the gated run's result is `INCONCLUSIVE` or anything other than the two comparable results; or a figure input is missing or contradictory, which covers an absent forwarding count, an absent `content_block_prompts` or leak count, a gated run that decided more expected-block prompts than the baseline forwarded, and more leaks than decided prompts. |
| `historical_unpaired` | A pre-E benchmark row, marked by hand. It has no constant in the validator because nothing computes it: it is a label for evidence that predates the pair contract. |

Nothing withholds gate figures except `invalid_evidence_gap` and the three
statuses above it that stop before the figures are reached. A `valid_complete`
pair always carries them.

### Non-comparability rules (locked)

A pair is non-comparable when any required attribution dimension differs, required artifacts are missing/malformed, or baseline/gated role requirements are not satisfied.

### Pre-E historical handling (locked)

Pre-E benchmark rows remain valid historical evidence rows.

They are **not automatically pair-comparable** and must be marked `historical_unpaired` unless explicitly proven pair-comparable from archived artifacts.

### Truth-surface coexistence (locked)

`latest-audit.*` and `latest-run.*` remain single-run truth surfaces.

They are not benchmark pair claims and must not be interpreted as pair completeness or pair validity signals.

**A baseline record is not a run on any of those surfaces.**
`latest-run.*`, `latest-audit.*`, `latest-live-audit.*`, the monitor window and
`proofs/runs/index.json` describe gate runs: every row there carries a result
and a proof class, and a row with neither would put a verdict-shaped hole where
a reader expects a verdict. That is the shape that made 54 published baselines
read as failed audits. A baseline record is published in its own archive and
appears in `benchmark_index.v3.json`, which is built from the archives rather
than from the run index, because an index derived from the run index could never
see one.

`docs/runs/index.html` paired rows are a benchmark interpretation view over archived run evidence; pair rows do not replace per-run archive artifacts as source-of-truth.

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
  - exactly one signed document: `audit.json` for a gated run, or
    `baseline.json` for an ungated baseline. An archive holding both cannot be
    read as either kind and is refused by the verifiers, the exports and the
    publisher; an archive holding neither has no kind at all.
  - `archive_receipt.json`
  - copied `proofs/run_summary.json`
  - copied `proofs/itgl_ledger.jsonl`
  - copied `proofs/itgl_final_hash.txt`
  - copied `proofs/latest-attempts.log`
- `proofs/runs/benchmark_index.v3.json` includes attributable entries for each
  required run, and satisfies `spec/benchmark_index.v3.schema.json`. The v1 and
  v2 indexes remain published and are superseded: both carry one entry shape, so
  a baseline record could only appear in them as a gate run with fields
  missing.
- Every entry declares its `entry_kind` and includes explicit
  `evaluation_target`, `provider`, `model` and `row_identity` fields. A
  `proof_class` is required of an `audit_certificate` entry and must be absent
  from an `ungated_baseline_record` entry, which carries forwarding counts in
  place of a result.

A cycle is **non-comparable / out-of-band** if any required row is missing, unarchived, malformed, or mixed with ad-hoc dimensions that change attribution semantics.

## Procedure (run order and repeatability)

Run order for each cycle:

1. Audit baseline: `generic_safety` (`FIREWALL_ONLY_AUDIT`; taxonomy coverage `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection`)
2. Audit operator-override pressure: `support_operator_override` (`FIREWALL_ONLY_AUDIT`; taxonomy coverage `benign_control`, `direct_bypass`, `exfiltration`)
3. Audit exfiltration-pressure slice: `data_exfiltration_pressure` (`FIREWALL_ONLY_AUDIT`; taxonomy coverage `benign_control`, `exfiltration`)

Publication:

A benchmark dispatch opens a pull request and **leaves it open**. Unlike the
ordinary audit job, the benchmark job does not arm auto-merge, so a pair does
not reach `main` until a person merges it. That is deliberate, decided
16 October 2026: both pairs published on 15 October exposed defects in how this
repository describes a pair, each caught by a person reading the evidence while
the required checks were still running, and twice auto-merge completed first. A
pull request sitting open after a benchmark is the expected state and says so in
the job log. `tests/test_audit_workflow_cannot_pass_without_verifying.py` holds
which job arms auto-merge and which does not.

Do not merge anything to `main` while a benchmark runs. The concurrency group is
`sir-audit-and-sign-${{ github.ref }}` with `cancel-in-progress: true`, so a push
to `main` cancels an in-flight benchmark after the provider credit is spent and
before anything publishes.

Repeatability expectations:

- Use the same committed pack versions from `spec/packs/pack_registry.v1.json`.
- Keep run command semantics stable (`sir run --mode audit|scenario|live --pack <pack_id>`).
- Treat provider/model as recorded metadata; do not backfill or rename after run publication.
- Do not collapse proof classes: compare within the same `proof_class` only.

## Provider/model naming rules (locked)

For repeatable comparison rows:

- Record provider/model exactly as emitted in the archive's signed document,
  `audit.json` or `baseline.json`, and copied to the benchmark index.
- Keep original case and separators; no alias normalization in v1.
- Missing provider/model is allowed only for audit rows where no model call path exists.

## Naming and output conventions

- Canonical cycle label: `benchmark_cycle.v1` (documentation contract label).
- The current machine index is `benchmark_index.v3` (`proofs/runs/benchmark_index.v3.json`). `benchmark_index.v1.json` and `.v2.json` remain published and are superseded; they describe gate runs only, because their entries carry a result and a proof class. This line named v1 as current until 15 October 2026, while the assurance kit named v2 and the archive view read v3, which left a reader three documents and no way to tell which was current.
- Use `row_identity` as the strict comparability key **for certificate entries**. Those rows are comparable only when `row_identity` dimensions align (`sir`, `commit`, `target`, `proof_class`, `provider`, `model`).
- A baseline record entry has no `row_identity` and is not compared row to row, because it carries no `proof_class` and no result: the key would require a field the document is forbidden to hold. A baseline reaches a comparison only as one half of a pair, and a pair is matched on its required attribution dimensions, which are provider, model, target kind, pack id, pack version, prompt-set hash and its kind, and commit. `proof_class` is deliberately not among them.
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

- Gate request statuses remain `PASS` / `BLOCKED` at prompt level.
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
