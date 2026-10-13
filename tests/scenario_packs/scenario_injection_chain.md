# Scenario Injection Chain

## Status

Selecting `scenario_injection_chain` through the `--pack` route evaluates every turn. The suite declares `generic_safety` as its `enforcement_pack` and the runner resolves through that field. A measured run on 13 October 2026 reported 15 turns, 4 leaks, 1 harmless block and zero systemic resets.

From `e0ee45d` on 16 April 2026 until 8 October 2026 this was not so: the runner reused the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named pack existed, and every turn received a systemic-reset block during policy load while the run exited zero. This document described that state until 13 October 2026.

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

This pack can serve as a baseline scenario sentinel through the `--pack` route: selection resolves to `generic_safety` and evaluates every turn. Its current result differs from its three published April 2026 archives, which report zero leaks and zero harmless blocks against today's 4 and 1, and whether the rules changed or the suite changed is not established. That divergence, not the selection route, is what qualifies its use as a sentinel. It is recorded in `docs/backlog.md`, which is where the open item lives.
