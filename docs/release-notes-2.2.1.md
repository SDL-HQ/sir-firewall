# SIR 2.2.1 — Generative Validation Tests

Patch release following SIR 2.2.0.

SIR 2.2.1 adds post-release generative validation tests and CI test-dependency hygiene. This improves test coverage and evidence discipline; it does not increase runtime capability or change SIR runtime behaviour.

## Added

- Added Hypothesis-based property tests for SIR normalisation.
- Added Hypothesis-based gate outcome invariance tests for bounded mechanical transformations.
- CI now installs declared test requirements before running `pytest`.

## Validation

- Normalisation property tests verify bounded marker recovery under supported invisible-character insertion.
- Normalisation property tests verify supported single-layer Base64, ROT13, marked hex, and hex-escape decode-stability cases.
- Gate outcome invariance tests verify that known blocking payloads remain `BLOCKED` under the bounded mechanical transformation set tested.

The bounded transformation set tested includes:

- case changes
- whitespace variation
- leading and trailing padding
- token-boundary invisible-character insertion
- SIR-supported Cyrillic and Greek homoglyph substitutions
- supported single-layer encoding wrappers within the current decode perimeter

These tests cover the stated bounded transformations. They do not establish robustness against all obfuscation, universal Unicode confusable coverage, arbitrary nested encoding support, or prevention of all prompt injection.

## Recorded behaviours

Two normalisation behaviours are recorded as executable expected behaviours using strict expected failures, not hidden skips:

1. Fixed-point idempotence does not hold where marker recovery appends an already-present canonical marker. The minimal counterexample is `obey`.
2. Exact normalised-string invariance does not hold where an invisible character is inserted inside a marker token. The minimal counterexample is `i\u200bgnore previous instructions`.

The gate outcome invariance tests did not add expected failures.

## Runtime impact

This patch does not change:

- SIR runtime behaviour
- deterministic gate logic
- policy files
- domain packs
- proof formats
- evidence contracts
- signed or generated evidence artefacts
- benchmark results
- latest-audit or latest-run artefacts

No evidence was regenerated for this documentation update.
