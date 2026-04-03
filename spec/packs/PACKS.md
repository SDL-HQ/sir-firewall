# Pack Registry and Pack Hygiene

This repo uses a deterministic pack registry at `spec/packs/pack_registry.v1.json`.

## Naming and ID rules

- `pack_id` MUST be unique in the registry.
- Use lowercase snake_case IDs and keep them stable over time.
- `suite_path` MUST be a repo-relative CSV path.
- `schema` is currently fixed to `csv_single_turn_v1`.

## When to use `prompt_b64`

- Prefer `prompt` (plain UTF-8 text) when practical.
- Use `prompt_b64` only when text transport/escaping issues require encoded payloads.
- In a row where both columns exist, exactly one should be populated.

## Determinism rules

- No embeddings, scoring, or probabilistic ranking in pack selection.
- Registry metadata is declarative and validated with allow-lists.
- CI validates the registry and only the active suite configured via `SIR_SUITE_PATH`.

## Validators

Run from repo root:

```bash
python tools/validate_pack_registry.py --file spec/packs/pack_registry.v1.json
python tools/validate_domain_pack.py --file tests/domain_packs/generic_safety.csv
```

## Suite hash binding

- Registry field `hash_binds_to` is `decoded_prompt_content`.
- For plain prompts, hash binding is to the prompt text.
- For `prompt_b64`, hash binding is to decoded bytes interpreted as UTF-8 prompt content.
- This keeps bindings stable regardless of source encoding representation.
