# EU AI Act Compliance Pressure (Domain Pressure Pack)

## Purpose

`tests/domain_packs/eu_ai_act_compliance_pressure.csv` is a **governance/domain pressure pack** for SIR pre-inference evaluation.

It is designed to:
- test deterministic gating against prompts involving transparency, human oversight, manipulation pressure, and data-boundary misuse,
- provide a stable suite hash + prompt count for governance proofs and domain testing,
- exercise both overblocking risk (`allow`) and leakage risk (`block`) in one pack.

## Important Limitation

This pack is **not** a formal legal determination of EU AI Act compliance.

It is a bounded deterministic evaluation pack for pressure-testing request handling related to:
- transparency expectations,
- human oversight expectations,
- prohibited manipulation-style requests,
- data-boundary and sensitive-data misuse,
- compliance-pressure style requests in high-risk AI contexts.

## CSV Schema

The repo supports both suite formats:
- `id,prompt,expected,note,category`
- `id,prompt_b64,expected,note,category`

`expected` values are strictly `allow` or `block`.

## Category Mix

This pack uses the following categories:
- `benign` (allow)
- `prohibited_manipulation` (block)
- `transparency_bypass` (block)
- `oversight_circumvention` (block)
- `data_boundary` (block)

Target operating ratio for this pack:
- allow: 50 / 150
- block: 100 / 150

## Intended Interpretation

This pack should be read as a **pressure pack**, not a certification pack.

A strong result on this pack supports the claim that SIR can reduce or prevent unsafe request patterns in this bounded governance domain.

A mixed or weak result on this pack does **not** imply broad legal non-compliance or compliance. It indicates how the current deterministic gate performs against this specific prompt set.

## Canary Rows

The suite includes explicit canary rows for workflow sanity checks:
- `CANARY_ALLOW` rows must remain allowed
- `CANARY_BLOCK` rows must remain blocked

These canaries are intentionally simple and deterministic so CI regressions are easy to detect.
