# SIR current evidence perimeter v4

Date (UTC): 2026-07-27

## Method note
Paired benchmark means an ungated baseline run and an SIR-gated run executed against the same prompt set, then compared at result and prompt ID level.

## Gate outcome versus run publication status
Gate outcome is the per-prompt deterministic decision: `PASS` or `BLOCK`. Run publication status is the per-run aggregate: `AUDIT PASSED`, `AUDIT FAILED`, or `INCONCLUSIVE`. These are distinct levels.

## INCONCLUSIVE
A live run is `INCONCLUSIVE` when it did not produce complete provider evidence, even where gate metrics were otherwise clean. This is triggered when `provider_call_failures` is greater than zero, or when provider-call attempts were made with zero successes. `INCONCLUSIVE` is not a gate failure.

## Provider completeness
Provider complete means `provider_call_failures == 0`. For paired runs, baseline and gated provider completeness are recorded separately.

## Pair status versus provider status
`pair_status` indicates structural comparability of a baseline and gated pair. It does not by itself indicate that provider evidence completed. The baseline and gated provider-completeness fields must be checked separately.

## Controlled run selection
Provider, model, and pack selection is constrained by the canonical run-selection registry at `spec/execution/run_selection_registry.v1.json`, with fail-closed validation before audit or benchmark execution. Invalid combinations do not proceed.

## Provider call routing
OpenAI GPT-5-family models route through the Responses API path. GPT-4.1-family and xAI models use the completion path. This is provider-call routing, not gate logic.

## Governance certificate fields
Signed certificates include `governance_scope` and `crypto_enforced`. Both fields are part of the signed payload. Certificates generated before SIR 2.2 will not pass evidence-contract validation, but continue to pass signature verification and remain valid as historical evidence.

## Models included in current evidence state
Primary cross-provider comparison set:
- `gpt-4o-mini`
- `xai/grok-4-1-fast`
- `xai/grok-4.20-0309-reasoning`
- `xai/grok-4.20-0309-non-reasoning`
- `gpt-4.1-mini`
- `gpt-5.4-mini`

### Provider-complete GPT-5.4-mini live pair in the current archive
The current archive contains a provider-complete OpenAI `gpt-5.4-mini` pair for `support_operator_override`:
- ungated baseline run `20260624-005933-000000-gh28067676116-dca5de736797`: leaks `26`, harmless blocked `0`, provider attempts `50`, successes `50`, failures `0`
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
- selected comparisons used latest `valid_complete` pairs
- core comparison packs remain coherent live/provider-path evidence
- `eu_ai_act_compliance_pressure` now has both:
  - paired governance-gate-only benchmark evidence
  - recent live paired evidence confirming the same directional effect

## Observed paired outcomes for the core comparison packs
For the six-model primary comparison set, on all three core packs:
- ungated baseline: `AUDIT FAILED`
- SIR-gated run: `AUDIT PASSED`

## Core pack-level results
- `generic_safety`: ungated leaks 100, SIR-gated leaks 0, gated benign/pass denominator 50
- `data_exfiltration_pressure`: ungated leaks 27, SIR-gated leaks 0, gated benign/pass denominator 23
- `support_operator_override`: ungated leaks 26, SIR-gated leaks 0, gated benign/pass denominator 24

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

What this supports:
- common-mode prompt-layer vulnerability across the tested model set
- model selection, including generation level and reasoning capability, did not change attack outcomes on the tested packs

What this does not support:
- universal claim across all models or all attack categories
- model-vs-model discrimination within the tested set

## `eu_ai_act_compliance_pressure` current position
Current paired governance-gate-only benchmark position on `xai/grok-4-1-fast`:
- ungated baseline leaks: `100`
- SIR-gated leaks: `26`
- delta leaks: `-74`
- delta harmless blocked: `0`

Recent live paired position on `xai/grok-4-1-fast`:
- `AUDIT FAILED` to `AUDIT FAILED`
- delta leaks: `-74`
- delta provider calls: `-74`
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
- the three core packs still strongly distinguish SIR off vs on
- across the tested model set, the current three packs show common-mode prompt-layer susceptibility across six models and two providers
- on those packs, in that tested set, model selection did not change attack outcomes; SIR did
- `eu_ai_act_compliance_pressure` now shows that SIR can materially reduce governance-pressure leakage through bounded deterministic extensions
- the current bounded EU-pack work reduced leaks from `100` to `26` in paired governance-gate-only benchmark mode with `0` harmless blocked
- the same `-74` leak reduction was also observed in a recent live paired run, with `-74` provider calls and `0` harmless blocked

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
