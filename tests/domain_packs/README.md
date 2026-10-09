# Domain Packs

Portable policy artefacts for testing governance enforcement.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

## Pack categories

Three categories of file carry the word "pack" in this project:

1. **ISC policy packs** — `src/sir_firewall/policy/isc_packs/*.json`. These are runtime gate configurations loaded by `load_domain_pack()`. They control ISC templates, friction limits, enforcement flags, and structured schemas.
2. **Registry-managed benchmark suites** — `tests/domain_packs/*.csv` and `tests/scenario_packs/*.json`. These are prompt sets intended for runner evaluation and are listed in `spec/packs/pack_registry.v1.json`. They are discoverable through `sir packs list` when their visibility is `public`. Each registry entry names the ISC policy pack it is enforced under in its `enforcement_pack` field, separately from its own `pack_id`, and a suite whose declared enforcement pack does not exist is refused at selection rather than producing a run in which every row is a systemic reset. `canary_fail` is the single entry that declares `enforcement_expected_to_fail`, because its pack-load failure is the fixture that proves a run evaluating no content cannot resemble a clean one.
3. **Non-registry exploratory fixtures** — `structured_account_recovery_benchmark.json` and `tool_result_ingress_benchmark.json`. Dedicated tests load these files directly; they are not registry-managed and are not discoverable through `sir packs list`.

`hipaa_mental_health` is an ISC policy pack, while `mental_health_clinical` is a separate benchmark suite. They are related in subject but are different artefacts with no naming correspondence, and the suite is enforced under `generic_safety` by declaration. Measurement on 8 October 2026 found that no verdict in any registry suite changes with the enforcement pack: 453 prompts across 8 suites produce an identical per-prompt result under all 6 ISC policy packs, while the signed `configuration_hash` differs for each. The pack must load, and which one loads changes nothing these suites measure.

`structured_account_recovery_benchmark.json` is an exploratory test fixture and is not a registry-managed pack discoverable via `sir packs list`.

## ISC policy-pack minimum schema

Every ISC policy pack is a JSON object with required `pack_id`, `templates`,
and `flags` keys. `pack_id` is a non-empty string matching the selected pack.
`templates` contains every identifier derived from the gate's built-in allowed
template set, and each template object carries a positive native JSON integer
`max_tokens`. `flags` contains native JSON booleans for
`CHECKSUM_ENFORCED` and `CRYPTO_ENFORCED`. The legacy `STRICT_ISC_ENFORCEMENT`
key is optional and has no behavioural meaning; structural ISC validation is unconditional.
It is not currently consulted, and ISC structural rejection is unconditional.
`description` and `structured_request_schema` are optional; when a structured
schema is present, the structured-ingress validator enforces its detailed
contract.

## Inventory

### Active public registry suites

- [Generic Safety](./generic_safety.md) — taxonomy: `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection`
- [Account Recovery and Fraud](./account_recovery_fraud.md) — taxonomy: `benign_control`, `direct_bypass`; registry-active, but `--pack` currently produces systemic-reset blocks
- [Support / Operator Override](./support_operator_override.md) — taxonomy: `benign_control`, `direct_bypass`, `exfiltration`
- [Data Exfiltration Pressure](./data_exfiltration_pressure.md) — taxonomy: `benign_control`, `exfiltration`
- [EU AI Act Compliance Pressure](./eu_ai_act_compliance_pressure.md) — taxonomy: `benign_control`, `direct_bypass`

### Active encoded registry suite

- [Mental Health Clinical](./mental_health_clinical.md) — active, `encoded` visibility; taxonomy: `benign_control`, `direct_bypass`; explicit `--pack` selection currently produces systemic-reset blocks

### Draft/internal packs

- `canary_fail` — draft/internal benchmark infrastructure check; it has no companion document by design.

## Current execution constraint

Four registry suites have no same-named ISC policy counterpart: `account_recovery_fraud`, `mental_health_clinical`, `scenario_injection_chain`, and `scenario_tool_injection`. Selecting one through the `--pack` route produces systemic-reset blocks during policy load rather than meaningful suite evaluation. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Artefacts

- Test suites: `tests/domain_packs/*.csv`
- CSV schema (supported): `id,prompt,expected,note,category` or `id,prompt_b64,expected,note,category`
