# SIR current evidence perimeter v2

Date (UTC): 2026-04-22

## Method note
Paired benchmark means an ungated baseline run and an SIR-gated run executed against the same prompt set, then compared at result and prompt ID level.

## Models included in current evidence state
Primary cross-provider comparison set:
- `gpt-4o-mini`
- `xai/grok-4-1-fast`
- `xai/grok-4.20-0309-reasoning`
- `xai/grok-4.20-0309-non-reasoning`

Additional recent test activity:
- `gpt-4o-mini`
- `gpt-4.1-mini`
- `gpt-5.4-mini`

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
For the four-model comparison set, on all three core packs:
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
- across all four compared models, ungated leaked prompt ID sets were identical for each pack
- across all four compared models, SIR-gated blocked/passed prompt ID sets were identical for each pack

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
- across the tested core comparison set, the current three packs still show common-mode prompt-layer susceptibility
- on those packs, in that tested set, model selection did not change attack outcomes; SIR did
- `eu_ai_act_compliance_pressure` now shows that SIR can materially reduce governance-pressure leakage through bounded deterministic extensions
- the current bounded EU-pack work reduced leaks from `100` to `26` in paired governance-gate-only benchmark mode with `0` harmless blocked
- the same `-74` leak reduction was also observed in a recent live paired run, with `-74` provider calls and `0` harmless blocked

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
