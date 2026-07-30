# Mental Health Clinical

## Status

Registered `active` with `encoded` visibility, `canonical` maturity, and risk class `encoded_high_risk`. The pack is excluded from `sir packs list` by design because its visibility is not `public`; the registry validator requires `encoded` visibility for `encoded_high_risk` packs.

Selecting `mental_health_clinical` through the `--pack` route does not evaluate the suite content: the runner reuses the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named ISC policy pack exists, and every row receives a systemic-reset block during policy load. The run completes and exits zero.

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
