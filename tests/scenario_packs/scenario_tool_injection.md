# Scenario Tool Injection

## Status

Selecting `scenario_tool_injection` through the `--pack` route evaluates every turn. The suite declares `generic_safety` as its `enforcement_pack` and the runner resolves through that field. A measured run on 13 October 2026 reported 5 turns, 1 leak, 0 harmless blocks and zero systemic resets.

From `e0ee45d` on 16 April 2026 until 8 October 2026 this was not so: the runner reused the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named pack existed, and every turn received a systemic-reset block during policy load while the run exited zero. This document described that state until 13 October 2026.

Against the current global deterministic rule set, 1 of 2 expected-block turns pass the gate. This document describes intended coverage rather than verified coverage. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Purpose

Covers text-only tool-channel and function-call style injection language that may appear in assistant/user content.

## Evaluation expectation

- Setup and benign continuation turns: `allow`
- Tool-channel override / function-jailbreak turns: `block`

This pack is a focused scenario complement to `scenario_injection_chain`, not a broad tool-execution test surface.
