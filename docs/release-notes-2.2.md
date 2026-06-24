# SIR v2.2.0 — Release Notes

## Evidence Integrity and Controlled Execution

### Highlights

- Added controlled provider/model/pack selection for governance runs.
- Added fail-closed run-selection validation before audit and benchmark execution.
- Added live-provider incompleteness semantics: provider-call failures now produce INCONCLUSIVE rather than clean PASS evidence.
- Protected latest-audit as the latest conclusive PASS proof, while latest-run reflects the most recent run state.
- Added provider-completeness fields to paired benchmark artefacts and benchmark indexes.
- Hardened invisible Unicode normalisation coverage including variation selectors, tag block characters, and supplemental variation selectors.
- Updated audit/live wording across workflow, certificate, and operator documentation surfaces.
- Updated ISC policy description and regenerated signed policy hash.
- Added OpenAI GPT-5-family live-call support through the Responses API path.
- Added evidence perimeter documentation for SIR 2.2 semantics.
- Added public backlog for known constraints, planned hardening items, current packs, and not-in-scope claims.

### Evidence semantics

AUDIT PASSED now requires complete provider evidence for live proof classes. Gate-clean live runs with provider-call failures are marked INCONCLUSIVE.

latest-audit remains the latest conclusive PASS proof. latest-run reflects the most recent run including FAIL or INCONCLUSIVE.

### Governance certificate

Signed certificates now include governance_scope and crypto_enforced fields. These fields are part of the signed payload and verifiable offline. The evidence contract now requires these fields. Certificates generated before SIR 2.2 will not pass contract validation but will continue to pass signature verification. Pre-2.2 certificates remain valid as historical evidence.

### Normalisation hardening

Base64 keyword gate expanded to cover all seven deterministic rule families. Hex decoding added for explicit hex: marker and \xNN escape sequences. Arbitrary contiguous hex strings are not decoded.

### Operator changes

Manual free-text provider/model/pack entry replaced with controlled dropdowns backed by fail-closed validation. Invalid combinations fail before audit or benchmark execution.

### Security hardening

- Tightened domain pack ID validation to prevent path traversal via SIR_ISC_PACK.
- Added boundary check on SIR_POLICY_PATH overrides.
- Corrected ISC structure validation to block unconditionally.

### Non-claims

SIR remains a deterministic, rules-based pre-inference governance gate. It does not claim universal prompt-injection prevention, semantic attack detection, model safety certification, or control over content it does not receive.
