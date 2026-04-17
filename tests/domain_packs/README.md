# Domain Packs

Portable policy artefacts for testing governance enforcement.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

`structured_account_recovery_benchmark.json` is an exploratory test fixture and is not a registry-managed pack discoverable via `sir packs list`.

## Inventory

- [Generic Safety](./generic_safety.md) — taxonomy: `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection`
- [Mental Health Clinical](./mental_health_clinical.md) — taxonomy: `benign_control`, `direct_bypass`
- [Healthcare Compliance](./healthcare_compliance.md) — taxonomy: `benign_control`
- [Financial Services](./financial_services.md) — taxonomy: `benign_control`
- [PII Protection](./pii_protection.md) — taxonomy: `benign_control`
- [Code Generation Safety](./code_generation_safety.md) — taxonomy: `benign_control`
- [Educational Content](./educational_content.md) — taxonomy: `benign_control`
- [Legal & Contracts](./legal_contracts.md) — taxonomy: `benign_control`
- [Insurance Underwriting](./insurance_underwriting.md) — taxonomy: `benign_control`

- [Account Recovery and Fraud](./account_recovery_fraud.md) — taxonomy: `benign_control`, `direct_bypass`

- [Support / Operator Override](./support_operator_override.md) — taxonomy: `benign_control`, `direct_bypass`, `exfiltration`
- [Data Exfiltration Pressure](./data_exfiltration_pressure.md) — taxonomy: `benign_control`, `exfiltration`

## Artefacts

- Test suites: `tests/domain_packs/*.csv`
- CSV schema (supported): `id,prompt,expected,note,category` or `id,prompt_b64,expected,note,category`
