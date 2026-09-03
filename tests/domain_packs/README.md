# Domain Packs

Portable policy artefacts for testing governance enforcement.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

## Pack categories

Three categories of file carry the word "pack" in this project:

1. **ISC policy packs** — `src/sir_firewall/policy/isc_packs/*.json`. These are runtime gate configurations loaded by `load_domain_pack()`. They control ISC templates, friction limits, enforcement flags, and structured schemas.
2. **Registry-managed benchmark suites** — `tests/domain_packs/*.csv` and `tests/scenario_packs/*.json`. These are prompt sets intended for runner evaluation and are listed in `spec/packs/pack_registry.v1.json`. They are discoverable through `sir packs list` when their visibility is `public`, but registry discoverability does not guarantee that a same-named ISC policy pack exists.
3. **Non-registry exploratory fixtures** — `structured_account_recovery_benchmark.json` and `tool_result_ingress_benchmark.json`. Dedicated tests load these files directly; they are not registry-managed and are not discoverable through `sir packs list`.

`hipaa_mental_health` is an ISC policy pack, while `mental_health_clinical` is a separate benchmark suite. They are related in subject but are different artefacts with no naming correspondence.

`structured_account_recovery_benchmark.json` is an exploratory test fixture and is not a registry-managed pack discoverable via `sir packs list`.

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

- [Healthcare Compliance](./healthcare_compliance.md) — draft/internal placeholder; taxonomy: `benign_control`
- [Financial Services](./financial_services.md) — draft/internal placeholder; taxonomy: `benign_control`
- [PII Protection](./pii_protection.md) — draft/internal placeholder; taxonomy: `benign_control`
- [Code Generation Safety](./code_generation_safety.md) — draft/internal placeholder; taxonomy: `benign_control`
- [Educational Content](./educational_content.md) — draft/internal placeholder; taxonomy: `benign_control`
- [Legal & Contracts](./legal_contracts.md) — draft/internal placeholder; taxonomy: `benign_control`
- [Insurance Underwriting](./insurance_underwriting.md) — draft/internal placeholder; taxonomy: `benign_control`
- `canary_fail` — draft/internal benchmark infrastructure check; it has no companion document by design.

## Current execution constraint

Four registry suites have no same-named ISC policy counterpart: `account_recovery_fraud`, `mental_health_clinical`, `scenario_injection_chain`, and `scenario_tool_injection`. Selecting one through the `--pack` route produces systemic-reset blocks during policy load rather than meaningful suite evaluation. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Artefacts

- Test suites: `tests/domain_packs/*.csv`
- CSV schema (supported): `id,prompt,expected,note,category` or `id,prompt_b64,expected,note,category`
