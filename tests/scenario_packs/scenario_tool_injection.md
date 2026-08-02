# Scenario Tool Injection

## Status

Selecting `scenario_tool_injection` through the `--pack` route does not evaluate the suite content: the runner reuses the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named ISC policy pack exists, and every turn receives a systemic-reset block during policy load. The run completes and exits zero.

Against the current global deterministic rule set, 1 of 2 expected-block turns pass the gate. This document describes intended coverage rather than verified coverage. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Purpose

Covers text-only tool-channel and function-call style injection language that may appear in assistant/user content.

## Evaluation expectation

- Setup and benign continuation turns: `allow`
- Tool-channel override / function-jailbreak turns: `block`

This pack is a focused scenario complement to `scenario_injection_chain`, not a broad tool-execution test surface.
