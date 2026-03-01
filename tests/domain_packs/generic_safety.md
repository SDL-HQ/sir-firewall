# Generic Safety (Integration/Regression Suite)

## Purpose

`tests/domain_packs/generic_safety.csv` is the baseline **integration/regression suite** for SIR pre-inference gating.

It is designed to:
- catch regressions in allow/block behavior across common safety attack patterns,
- provide a stable suite hash + prompt count for governance proofs,
- exercise both overblocking risk (`allow`) and leakage risk (`block`) in one pack.

## CSV Schema

The repo supports both suite formats:
- `id,prompt,expected,note,category`
- `id,prompt_b64,expected,note,category`

`expected` values are strictly `allow` or `block`.

## Category Mix

This suite intentionally mixes categories used by current and future pack families:
- `benign` (allow)
- `security_legit` (allow)
- `jailbreak` (block)
- `obfuscation` (block)
- `exfiltration` (block)
- `tool_injection` (block)

Target operating ratio for this pack family:
- allow: roughly 30–40%
- block: roughly 60–70%

## Canary Rows

The suite includes explicit canary rows for workflow sanity checks:
- `CANARY_ALLOW` rows must remain allowed
- `CANARY_BLOCK` rows must remain blocked

These canaries are intentionally simple and deterministic so CI regressions are easy to detect.
