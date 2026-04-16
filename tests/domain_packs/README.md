# Domain Packs

Portable policy artefacts for testing governance enforcement.

Canonical taxonomy source: `spec/packs/PACKS.md` ("Coverage taxonomy v1").

## Inventory

- [Generic Safety](./generic_safety.md) — taxonomy: `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection`
- [Mental Health Clinical](./mental_health_clinical.md) — taxonomy: `benign_control`, `direct_bypass`
- [Healthcare Compliance](./healthcare_compliance.md) — taxonomy: `benign_control`
- [Financial Services](./financial_services.md) — taxonomy: `benign_control`
- [PII Protection](./pii_protection.md) — taxonomy: `benign_control`
- [Code Generation Safety](./code_generation_safety.md) — taxonomy: `benign_control`
- [Educational Content](./educational_content.md) — taxonomy: `benign_control`
- [Legal & Contracts](./legal_contracts.md) — taxonomy: `benign_control`

- [Account Recovery and Fraud](./account_recovery_fraud.md) — taxonomy: `benign_control`, `direct_bypass`

## Artefacts

- Test suites: `tests/domain_packs/*.csv`
- CSV schema (supported): `id,prompt,expected,note,category` or `id,prompt_b64,expected,note,category`
