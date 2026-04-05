# Scenario Packs

Scenario packs are multi-turn JSON suites for text-only prompt-path evaluation.

## Inventory

- [Scenario Injection Chain](./scenario_injection_chain.md)
- [Scenario Tool Injection](./scenario_tool_injection.md)

## Artefacts

- Scenario suites: `tests/scenario_packs/*.json`
- Scenario docs: `tests/scenario_packs/*.md`

## Scope posture

- Scenario packs remain text-first and request-path scoped.
- They are not multimodal, tool-execution, or post-inference governance tests.
