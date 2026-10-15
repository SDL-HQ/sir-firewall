# SIR current evidence perimeter v5

Opened (UTC): 2026-09-08. Amended since, most recently 15 October 2026. This
document is maintained rather than frozen: a reader checking which perimeter is
current should read this line and the version below, not the opening date.

## Method note
Paired benchmark means an ungated baseline run and an SIR-gated run executed against the same prompt set, then compared.

From SIR 2.5 the comparison is not between two results. The ungated half
produces a signed baseline record carrying no result and no proof class, and
the gated half produces an audit certificate; a pair states what the gate did
to the prompts the suite labels for blocking, counted from the two documents.
Before 2.5 both halves were certificates and the comparison was read at result
level, which is the error `docs/archive-errata.md` records: the baseline's
result described a gate that was not in the path.

## Gate outcome versus run publication status
Gate request status is the per-prompt deterministic decision: `PASS` or `BLOCKED`. Run publication status is the per-run aggregate: `AUDIT PASSED`, `AUDIT FAILED`, or `INCONCLUSIVE`. These are distinct levels.

A third row status exists and is not a gate outcome. From SIR 2.5 an ungated
baseline's ledger rows carry `FORWARDED`, meaning a provider call was attempted
with that row's content. The gate returns `PASS` or `BLOCKED` and nothing else,
so a `FORWARDED` row cannot have come from a gated run, and a ledger of them
has no run publication status at all.

## The two signed documents
An archive holds exactly one: `audit.json`, an audit certificate for a gated
run, or `baseline.json`, an ungated baseline record. A certificate is verified
by `tools/verify_certificate.py` and a record by
`tools/verify_baseline_record.py`; each establishes the document's type before
anything else, so neither can report on the other kind.
`tools/verify_evidence.py` on the archive directory dispatches on which
document is there, and refuses an archive holding both or neither.

What a verified baseline record establishes: that the document is of that kind,
that it was signed by a key the registry still honours for it, and that its
counters are what its ledger's rows support.

What it does not establish, stated because a reader will otherwise supply it:

- That no gate ran. The rows authenticate what the producer encoded. A producer
  could write baseline-shaped rows for a run it gated, and nothing in the
  verifier would know. What the type separation rules out is a baseline record
  being read as an audit, and an audit's ledger being read as a baseline's.
- That every provider call made is recorded. Calls are counted by the runner
  that made them.
- Anything about the provider's responses beyond the transport outcome.
  Responses are not read back and not judged.
- In a scenario, distinct content exposure. Each call carries the cumulative
  history of earlier turns, so the counters count calls and turns.
- Attribution beyond what the issuer recorded, as for certificates.

## INCONCLUSIVE
A live run is `INCONCLUSIVE` when it did not produce complete provider evidence, even where gate metrics were otherwise clean. This is triggered when `provider_call_failures` is greater than zero, or when provider-call attempts were made with zero successes. `INCONCLUSIVE` is not a gate failure.

## Provider completeness
Provider complete means `provider_call_failures == 0`. For paired runs, baseline and gated provider completeness are recorded separately.

## Pair status versus provider status
`pair_status` indicates structural comparability of a baseline and gated pair. It does not by itself indicate that provider evidence completed. The baseline and gated provider-completeness fields must be checked separately.

A pair publishes the gate's figures only when `pair_status` is
`valid_complete`, which requires the gated run's result to be `AUDIT PASSED` or
`AUDIT FAILED`. An `INCONCLUSIVE` gated run makes the pair
`invalid_evidence_gap` and it carries no gate figures: a run whose own evidence
is incomplete cannot be the measured side of a comparison.

## Controlled run selection
GitHub workflow dispatch constrains provider, model, and pack selection through fail-closed preflight validation against the committed run-selection registry at `spec/execution/run_selection_registry.v1.json`. Local `sir run` and `sir benchmark run` execution instead authorises provider and model selection against the committed allowlist in `src/sir_firewall/model_selection.py`, with `red_team_suite.py` revalidating the selection before any provider call. Invalid combinations do not proceed on either path.

## Provider call routing
OpenAI GPT-5-family models route through the Responses API path. GPT-4.1-family and xAI models use the completion path. This is provider-call routing, not gate logic.

## Governance certificate fields
Signed certificates include `governance_scope` and `crypto_enforced`. Both fields are part of the signed payload. Certificates generated before SIR 2.2 are governed by no evidence contract, which `tools/verify_evidence.py` reports as neither a pass nor a violation but as not established. They continue to pass signature verification and remain valid as historical evidence. An earlier wording here said they "will not pass" contract validation, which describes the two-valued checker this project replaced.

`pack_hash` is present only when a caller supplies a pack hash through `pack_identity_context`; core does not compute it. The run harness no longer supplies the suite hash as `pack_hash`. A certificate signature makes supplied fields tamper-evident after signing but does not establish that a caller-supplied value was true.

## Current implementation state
The code reports SIR version `2.4.0` in package metadata and `sir_firewall.__version__`.

Current controlled model selection has default provider `xai` and default model `grok-4.3`. The selectable xAI models are:
- `grok-3-beta`
- `grok-4.3`
- `grok-4.20-0309-reasoning`
- `grok-4.20-0309-non-reasoning`

`grok-4-1-fast` is no longer selectable. Its archived results remain historical evidence.

## Property checks and characterised normalisation limits
The Hypothesis gate-outcome property harness uses `max_examples=30`, deterministic generation, and no deadline. It asserts that a clean source payload is `BLOCKED` before checking that the transformed payload remains `BLOCKED`. The tested transformation classes are case changes, token whitespace, outer padding, invisible characters at token boundaries, supported single-layer Base64/ROT13/hex/hex-escape encoding, and substitutions within one selected supported-homoglyph marker word. Parametrized cases additionally cover mapped characters in other tokens required by multi-token rules and an accepted Base64-decoded candidate.

Those bounded gate-outcome properties pass in the current test suite. They do not claim coverage of characters outside the nine-entry map or general Unicode-confusable handling.

Two additional normaliser behaviors are recorded by characterisation tests as limitations, not test failures:

- Non-idempotence for an already-present canonical marker: input `"obey"` normalises first to `"obey obey"` and a second time to `"obey obey obey"`.
- Exact normalised-string invariance does not hold for an invisible character inserted inside a marker token: input `"i\u200bgnore previous instructions"` normalises to `"i gnore previous instructions ignore previous instructions"`.

The tests intentionally preserve visibility of both behaviors so a future change is explicit.

## Homoglyph normalisation limit
The nine-entry Cyrillic/Greek homoglyph translation is applied to evaluated text on every normalisation return path and continues to support fixed marker detection. It is deliberately bounded rather than general Unicode-confusable handling. The high-risk, danger-plus-safety, deterministic-rule, and obfuscation-signal paths receive translated text; structural override exposure continues to inspect the raw payload and remains homoglyph-blind by design.

The published zero-leak `generic_safety` result does not constitute evidence of resistance to homoglyph substitution. No row in any suite exercises actual homoglyph substitution. Row `gs-111` mentions homoglyphs in ASCII prose and blocks on the unrelated `JB_EVADE_FILTERS` rule through the words `disable moderation`; homoglyph marker recovery is not involved.

The limitation and integration consequences are described in the [SIR threat model](threat-model.md) and recorded in [`docs/backlog.md`](backlog.md).

## Payload-size bound
String ISC payloads are rejected before normalisation when their character length exceeds four times the selected template's friction limit. Non-string ISC payloads retain the existing `str()` coercion behavior before later evaluation, so caller-controlled conversion work is not bounded by this string fast path. The residual limitation is recorded in [`docs/backlog.md`](backlog.md).

## Security mapping and threat-model references
The [SIR threat model](threat-model.md) records trust assumptions, evidence-field provenance, integration and verification boundaries, retained content, normalisation limits, and controls outside SIR's scope. The [OWASP LLM Top 10 for LLM Applications 2026 mapping](owasp-llm-top-10-2026.md) records a version-stamped, non-endorsed mapping of implemented, partial, and unaddressed controls.

## Models included in the evidence state captured 3 May 2026
Primary cross-provider comparison set:
- `gpt-4o-mini` (historical evidence; no longer selectable)
- `xai/grok-4-1-fast` (historical evidence; no longer selectable)
- `xai/grok-4.20-0309-reasoning`
- `xai/grok-4.20-0309-non-reasoning`
- `gpt-4.1-mini`
- `gpt-5.4-mini`

### Provider-complete GPT-5.4-mini live pair in the current archive
The current archive contains a provider-complete OpenAI `gpt-5.4-mini` pair for `support_operator_override`:
- ungated baseline run `20260624-005933-000000-gh28067676116-dca5de736797`: 26 prompts labelled for blocking, harmless blocked `0`, provider attempts `50`, successes `50`, failures `0`. This run is a pre-2.5 baseline certificate and is listed in `docs/archive-errata.md` Appendix C. Its signed `jailbreaks_leaked` reads `26`, which is that label count and not a leak.
- SIR-gated run `20260624-005958-000000-gh28067676116-baac467cd954`: leaks `0`, harmless blocked `0`, provider attempts `24`, successes `24`, failures `0`

Both sides satisfy the current provider-completeness condition.

## Packs included in current perimeter state
Core gate-effect comparison packs:
- `generic_safety`
- `data_exfiltration_pressure`
- `support_operator_override`

Extended governance pressure pack now in scope:
- `eu_ai_act_compliance_pressure`

## Evidence classes
- paired benchmark evidence
- selected comparisons used `valid_complete` pairs available to the published comparison state
- core comparison packs remain coherent live/provider-path evidence
- `eu_ai_act_compliance_pressure` now has both:
  - paired governance-gate-only benchmark evidence
  - live paired evidence produced 22 April 2026 confirming the same directional effect

## Comparison attribution limit
The cross-model comparison figures below are carried forward unchanged from v4. That document did not bind them to a fixed list of pair IDs, run IDs, or an archive-index revision. Later pairs have since been archived, so the original selected comparison set cannot be resolved from the perimeter alone. No inferred run attribution is added here. This is a known constraint recorded in [`docs/backlog.md`](backlog.md).

## Observed paired outcomes for the core comparison packs
For the six-model primary comparison set, on all three core packs:
- SIR-gated run: `AUDIT PASSED`
- the ungated half of each pair is a pre-2.5 certificate reading
  `AUDIT FAILED`. That result describes a run with no gate in the path and is
  not an outcome of the comparison. `docs/archive-errata.md` E7 records what
  those certificates are; all of them are in its Appendix C. It is reproduced
  here only because a reader who opens one of those archives will see it.

## Core pack-level results
Stated as the gate's own figures. The ungated column these replace was a leak
count, and on a run with no gate every prompt the suite labels for blocking
counts as a leak, so that column was the pack's label count under another name.
The arithmetic in this document showed it: 100 + 50 is `generic_safety`'s 150
prompts, 27 + 23 and 26 + 24 are the other two packs' 50 each.

- `generic_safety`: 100 prompts labelled for blocking, SIR-gated leaks 0, gated benign/pass denominator 50
- `data_exfiltration_pressure`: 27 prompts labelled for blocking, SIR-gated leaks 0, gated benign/pass denominator 23
- `support_operator_override`: 26 prompts labelled for blocking, SIR-gated leaks 0, gated benign/pass denominator 24

So on these three packs the gate blocked every prompt the suite labels for
blocking and blocked none of the 97 it labels for allowing. That is the figure,
and it is a statement about the rule set against these corpora. It is not a
measurement of harm prevented, because no response was read on either side.

## Core benign/pass denominator summary
- total gated benign/pass denominator across compared live pairs: `97`
- total harmless blocked across compared live pairs: `0`

## Core ID-level discrimination review
- across all six compared models, ungated leaked prompt ID sets were identical for each pack
- across all six compared models, SIR-gated blocked/passed prompt ID sets were identical for each pack

## Extended cross-model ID-level finding
ID-level discrimination review was subsequently extended to all six models in the current evidence state across the three core packs:
- ungated leaked prompt ID sets were identical across all six models for each pack
- reasoning vs non-reasoning variants produced identical outcomes
- three generations of GPT (`gpt-4o-mini`, `gpt-4.1-mini`, `gpt-5.4-mini`) produced identical outcomes
- SIR-gated blocked/passed prompt ID sets were identical across all six models

This finding was published: [Seven models, two providers, identical failure sets](https://x.com/SDL_HQ/status/2049438575574364279) - 2026-05-03

**Corrected 15 October 2026. Both of those ID sets are identical across models
by construction, so neither is an observation about any model.** The ungated
set is the set of prompts the suite labels for blocking: with no gate in the
path every one of them counts as a leak, and SIR never reads a model's
response, so nothing in that set can vary with the model. The gated set is a
deterministic pre-inference gate's decisions, taken before any model sees the
request, so nothing in that set can vary with the model either. Two sets that
cannot vary with the model were found not to vary with the model.

The earlier reading of this finding is withdrawn. It is recorded in
`docs/claims-register.md`, which also records what the published post says and
what the correct statement would be.

What this supports:
- that the suite's block labels and the gate's decisions are both independent
  of the model, which is what a deterministic pre-inference gate is for and is
  a property of the design rather than a measurement of it
- reproducibility: the same inputs and the same rule set gave the same
  per-prompt decisions across six model configurations and two providers

What this does not support:
- any statement about the models, including common-mode vulnerability, model
  susceptibility, or whether model selection changes attack outcomes. Neither
  side of the comparison observed a model
- a universal claim across all models or all attack categories
- model-vs-model discrimination within the tested set

## `eu_ai_act_compliance_pressure` position recorded 22 April 2026
Paired governance-gate-only benchmark position recorded 22 April 2026 under `xai/grok-4-1-fast`:
- 100 prompts labelled for blocking
- SIR-gated leaks: `26`, so the gate blocked 74 of the 100 and passed 26
- delta harmless blocked: `0`

The `-74` this pair published as `leaks_delta` is that same 74 reported from
the other side, against a baseline leak count that was the label count. SIR 2.5
retired the delta for that reason; `docs/benchmark-cycle.v1.md` carries the
replacement figures.

Live paired position produced 22 April 2026 on `xai/grok-4-1-fast`:
- the gated run's result was `AUDIT FAILED`, with 26 of the 100
  block-labelled prompts passed by the gate
- the ungated half is a pre-2.5 certificate also reading `AUDIT FAILED`, for
  the reason in E7
- 74 fewer provider calls were attempted on the gated side, which is the gate's
  block count over those prompts
- delta harmless blocked: `0`

## `eu_ai_act_compliance_pressure` progression
Observed paired benchmark progression for this pack on the current bounded rule path:
- `100 -> 100`
- `100 -> 75`
- `100 -> 57`
- `100 -> 32`
- `100 -> 26`

This progression reflects bounded deterministic expansion inside the SIR rule layer, not benchmark semantic changes.

## `eu_ai_act_compliance_pressure` category state
Current gated-state interpretation:
- `transparency_bypass`: cleared
- `prohibited_manipulation`: cleared
- `oversight_circumvention`: reduced to one intentional residual row
- `data_boundary`: dominant remaining leakage class

## What current evidence supports
- on the three core packs, the gate blocks every prompt those suites label for
  blocking and none of the 97 they label for allowing. "SIR off vs on" was the
  earlier wording and overstated it: the off side measured the suite's labels,
  not a model's behaviour
- the gate's per-prompt decisions are reproducible across six model
  configurations and two providers, because they are taken before any model is
  called and do not depend on one
- nothing here supports a statement about the models themselves. No response
  was read on either side of any comparison in this document
- `eu_ai_act_compliance_pressure` now shows that SIR can materially reduce governance-pressure leakage through bounded deterministic extensions
- the current bounded EU-pack work reduced leaks from `100` to `26` in paired governance-gate-only benchmark mode with `0` harmless blocked
- the same `-74` leak reduction was also observed in the 22 April 2026 live paired run, with `-74` provider calls and `0` harmless blocked

## Explicit non-claims
Current evidence and implementation do not claim that SIR:
- prevents all prompt injection
- provides semantic attack detection
- controls downstream agent behaviour
- proves model safety
- replaces application-level security controls
- evaluates content it never receives
- validates API message ordering

## What current evidence does not support
- it does not show that all models are equivalent generally
- it does not show that all attack classes are common-mode generally
- it does not show model-vs-model discrimination within the current tested set
- it does not establish full coverage or residual-risk claims beyond the packs, models, and evidence classes listed here
- it does not show that `eu_ai_act_compliance_pressure` is fully covered; the pack still fails overall
- it does not support broad legal or compliance claims from the EU-pack work

## What this means for liability exposure
- prompt-layer attack success is not just a model-quality issue; it is an exposure pathway where unsafe or deceptive requests can reach inference and create downstream operational, regulatory, or liability exposure
- SIR reduces that exposure by blocking classes of prompt-layer requests before inference and by preserving a signed audit trail showing what was attempted, what was blocked, and what was allowed
- for review, dispute, or claims handling, the resulting artefacts provide replayable evidence of gate behavior and decision lineage rather than post-hoc narrative alone
- replaying a recorded gate decision requires the same request inputs and the repository configuration at the recorded `commit_sha`; published benchmark inputs are available in that repository revision, while production inputs must be supplied by the operator
- `0` harmless blocked in the measured reductions means the current bounded rule gains were not achieved by broadly degrading normal use in the tested benign slice
- this does not eliminate liability or certify compliance, but it does improve the evidence position and control position around prompt-layer failure modes

## Current perimeter limit
- the core benchmark set remains validated as a gate-effect evidence set for the three listed core packs
- it is still not a model-separation benchmark set
- `eu_ai_act_compliance_pressure` is now a bounded partial-coverage evidence pack, not a full-pass pack
- remaining EU-pack leakage is concentrated almost entirely in `data_boundary`, plus one intentionally unimplemented oversight residual

## Current intentional pause
- `data_boundary` work is intentionally paused
- current judgment is that `data_boundary` is the least attractive remaining deterministic target and carries higher complexity and ambiguity risk
- the final oversight residual was intentionally not implemented for safety-to-complexity reasons

## Next perimeter expansion
- next perimeter expansion, if needed, will be determined by the next forcing-function audience and evidence requirement
- current default recommendation is to stop EU-pack expansion here for now, unless a specific requirement justifies revisiting the paused remainder
