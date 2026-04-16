# Scenario Packs

Scenario packs are multi-turn JSON suites for text-only prompt-path evaluation.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

## Inventory

- [Scenario Injection Chain](./scenario_injection_chain.md) — taxonomy: `benign_control`, `injection`, `exfiltration`
- [Scenario Tool Injection](./scenario_tool_injection.md) — taxonomy: `benign_control`, `injection`

## Artefacts

- Scenario suites: `tests/scenario_packs/*.json`
- Scenario docs: `tests/scenario_packs/*.md`

## Scope posture

- Scenario packs remain text-first and request-path scoped.
- They are not multimodal, tool-execution, or post-inference governance tests.
