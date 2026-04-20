# SIR current evidence perimeter v1

Date (UTC): 2026-04-20

## Method note
Paired benchmark means an ungated baseline run and an SIR-gated run executed against the same prompt set, then compared at result and prompt ID level.

## Models included in current cross-provider comparison
- `gpt-4o-mini`
- `xai/grok-4-1-fast`
- `xai/grok-4.20-0309-reasoning`
- `xai/grok-4.20-0309-non-reasoning`

## Packs included
- `generic_safety`
- `data_exfiltration_pressure`
- `support_operator_override`

## Evidence class
- paired benchmark evidence
- selected comparisons used latest `valid_complete` pairs
- selected rows were coherent live/provider-path evidence

## Observed paired outcomes
For all four compared models, on all three packs:
- ungated baseline: `AUDIT FAILED`
- SIR-gated run: `AUDIT PASSED`

## Pack-level results
- `generic_safety`: ungated leaks 100, SIR-gated leaks 0, gated benign/pass denominator 50
- `data_exfiltration_pressure`: ungated leaks 27, SIR-gated leaks 0, gated benign/pass denominator 23
- `support_operator_override`: ungated leaks 26, SIR-gated leaks 0, gated benign/pass denominator 24

## Benign/pass denominator summary
- total gated benign/pass denominator across compared live pairs: `97`
- total harmless blocked across compared live pairs: `0`

## ID-level discrimination review
- across all four compared models, ungated leaked prompt ID sets were identical for each pack
- across all four compared models, SIR-gated blocked/passed prompt ID sets were identical for each pack

## What current evidence supports
- the current three packs strongly distinguish SIR off vs on
- across the tested model set, the current three packs show common-mode prompt-layer susceptibility
- on these packs, in this tested set, model selection did not change attack outcomes; SIR did

## What current evidence does not support
- it does not show that all models are equivalent generally
- it does not show that all attack classes are common-mode generally
- it does not show model-vs-model discrimination within the current tested set
- it does not establish a full coverage or residual-risk claim beyond the tested packs/models above

## Current perimeter limit
- the current benchmark set is validated as a gate-effect evidence set for the three listed packs
- it is not yet a model-separation benchmark set

## Next perimeter expansion
- next perimeter expansion, if needed, will be determined by the next forcing-function audience and evidence requirement
