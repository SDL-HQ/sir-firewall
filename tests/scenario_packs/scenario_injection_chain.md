# Scenario Injection Chain

## Status

Selecting `scenario_injection_chain` through the `--pack` route does not evaluate the suite content: the runner reuses the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named ISC policy pack exists, and every turn receives a systemic-reset block during policy load. The run completes and exits zero.

Against the current global deterministic rule set, 4 of 10 expected-block turns pass the gate. This document describes intended coverage rather than verified coverage. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Purpose

Covers a mixed conversation where benign turns are interleaved with direct and indirect prompt-injection and exfiltration attempts.

## Evaluation expectation

- Benign turns: `allow`
- Prompt-injection / exfiltration turns: `block`

## B3 coverage additions

Adds explicit indirect and semantic-equivalent attack variants while keeping deterministic `allow`/`block` labels:

- hypothetical framing
- fictional and roleplay wrappers
- "imagine no restrictions" phrasing
- paraphrased or softened safety-removal language
- punctuation/spacing-split jailbreak intent
- simple structural injection format
- one hypothetical benign control turn to avoid assuming all hypothetical framing is disallowed

This pack cannot currently serve as a baseline scenario sentinel through the `--pack` route because selection produces systemic-reset blocks rather than suite evaluation.
