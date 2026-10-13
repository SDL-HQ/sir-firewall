# Scenario Packs

Scenario packs are multi-turn JSON suites for text-only prompt-path evaluation.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

## Inventory

- [Scenario Injection Chain](./scenario_injection_chain.md) — taxonomy: `benign_control`, `injection`, `exfiltration`
- [Scenario Tool Injection](./scenario_tool_injection.md) — taxonomy: `benign_control`, `injection`

## Current execution constraint

Both scenario suites are registry-active. Neither has a same-named ISC policy pack; both declare `generic_safety` as their `enforcement_pack`, and the runner resolves through that field, so selecting either through the `--pack` route evaluates every turn. This sentence described systemic-reset blocks until 13 October 2026, which stopped being true on 8 October.

## Artefacts

- Scenario suites: `tests/scenario_packs/*.json`
- Scenario docs: `tests/scenario_packs/*.md`

## Scope posture

- Scenario packs remain text-first and request-path scoped.
- They are not multimodal, tool-execution, or post-inference governance tests.
