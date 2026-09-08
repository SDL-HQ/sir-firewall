# Scenario Packs

Scenario packs are multi-turn JSON suites for text-only prompt-path evaluation.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

## Inventory

- [Scenario Injection Chain](./scenario_injection_chain.md) — taxonomy: `benign_control`, `injection`, `exfiltration`
- [Scenario Tool Injection](./scenario_tool_injection.md) — taxonomy: `benign_control`, `injection`

## Current execution constraint

Both scenario suites are registry-active, but selecting either through the `--pack` route currently produces systemic-reset blocks rather than meaningful suite evaluation because no same-named ISC policy pack exists.

## Artefacts

- Scenario suites: `tests/scenario_packs/*.json`
- Scenario docs: `tests/scenario_packs/*.md`

## Scope posture

- Scenario packs remain text-first and request-path scoped.
- They are not multimodal, tool-execution, or post-inference governance tests.
