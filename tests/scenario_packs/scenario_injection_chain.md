# Scenario Injection Chain

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

This pack remains suitable as a baseline scenario sentinel in small benchmark cycles.
