# Mental Health Clinical

## Status

Registered `active` with `encoded` visibility, `canonical` maturity, and risk class `encoded_high_risk`. The pack is excluded from `sir packs list` by design because its visibility is not `public`; the registry validator requires `encoded` visibility for `encoded_high_risk` packs.

Runnable. Enforced under the `generic_safety` ISC policy pack, declared as `enforcement_pack` in `spec/packs/pack_registry.v1.json`.

From `e0ee45d` on 16 April 2026 until 8 October 2026 this suite could not be run, for the reason described in `account_recovery_fraud.md`. It has never produced a published run. Current result: 25 prompts, 10 leaks, 0 harmless blocked.

`generic_safety` is declared rather than `hipaa_mental_health` because, as recorded below and in `README.md`, those are different artefact classes with no naming correspondence. Measurement on 8 October 2026 found that the enforcement pack changes no verdict in any registry suite, so the choice does not affect this suite's result.

Earlier revisions of this document stated that such a run "completes and exits zero". That stopped being true when item 1 landed in `6852e05`: a run that content-evaluated nothing exits 2 and reports INCONCLUSIVE.

Against the current global deterministic rule set, 10 of 15 expected-block rows pass the gate. This document describes intended coverage rather than verified coverage. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Purpose

This pack provides an encoded benchmark surface for mental-health and clinical request patterns without exposing prompt content in plain text.

## Suite shape

- Test suite: `tests/domain_packs/mental_health_clinical.csv`
- Rows: 25
- Prompt storage: base64-encoded values in `prompt_b64`; there is no plain `prompt` column
- Categories: `benign` 10, `jailbreak` 15
- Expected outcomes: `allow` 10, `block` 15

## Boundaries

- The encoding is deliberate; this document describes only suite shape, counts, categories, and expected outcomes.
- `mental_health_clinical` is a registry-managed benchmark suite.
- `hipaa_mental_health` is a related-in-subject ISC policy pack. They are different artefact classes, have no naming correspondence, and no mapping connects them.
