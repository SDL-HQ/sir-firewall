# Pack Scale and Hygiene

This file is the canonical pack guidance for the current pack registry model.

## What a pack is

A pack is a versioned test suite plus metadata in `spec/packs/pack_registry.v1.json`.

A pack entry exists to make selection, validation, and review deterministic.

## Scope boundary

- Domain packs are CSV suites under `tests/domain_packs/`.
- Scenario packs use scenario JSON suites under `tests/scenario_packs/`.
- The registry already contains both pack types. This guidance does not introduce new scenario-pack semantics.
- Pack evaluation binds to request-path inputs for deterministic pre-inference gate testing; this file does not define post-inference or full system-governance semantics.

## Required metadata

Each registry entry must include:

- `pack_id` (stable lowercase snake_case)
- `schema` (`csv_single_turn_v1` or `scenario_json_v1`)
- `risk_class` (`baseline`, `domain`, or `encoded_high_risk`)
- `status` (`active`, `draft`, or `deprecated`)
- `version`
- `suite_path`
- `hash_binds_to` (`decoded_prompt_content`)
- `pack_class` (`domain` or `scenario`)
- `visibility` (`public` or `encoded`)
- `maturity` (`canonical` or `demo`)

Optional:

- `doc_path` when a pack has a companion markdown file.

## Minimum pack quality bar

A pack must meet all of the following:

- Purpose is explicit and narrow.
- Rows are reviewable and non-duplicative.
- `expected` labels are deterministic (`allow` or `block`).
- `prompt` vs `prompt_b64` usage follows validator rules.
- Registry entry passes metadata validation.

## Add or update flow

1. Add or modify pack suite file.
2. Add or update pack metadata in `spec/packs/pack_registry.v1.json`.
3. Add or update pack documentation under `tests/domain_packs/` when applicable.
4. Run validators:
   - `python tools/validate_pack_registry.py --file spec/packs/pack_registry.v1.json`
   - `python tools/validate_domain_pack.py --glob 'tests/domain_packs/*.csv'`

## Determinism constraints

- No scoring, ranking, or probabilistic pack selection.
- Hash binding remains `decoded_prompt_content`.
- Metadata is declarative and allow-listed.
