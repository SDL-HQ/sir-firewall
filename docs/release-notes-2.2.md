# SIR v2.2.0 — Release Notes

## Evidence Integrity and Controlled Execution

### Highlights

- Added controlled provider/model/pack selection for governance runs.
- Added fail-closed run-selection validation before audit and benchmark execution.
- Added live-provider incompleteness semantics: provider-call failures now produce INCONCLUSIVE rather than clean PASS evidence.
- Protected latest-audit as the latest conclusive PASS proof, while latest-run reflects the most recent run state.
- Added provider-completeness fields to paired benchmark artefacts and benchmark indexes.
- Hardened invisible Unicode normalisation coverage including variation selectors, tag block characters, and supplemental variation selectors.
- Added OpenAI GPT-5-family live-call support through the Responses API path.
- Added the SIR 2.2 evidence perimeter at `docs/evidence-perimeter.v4.md`.
- Added the public backlog at `docs/backlog.md` for known constraints, planned hardening items, current packs, and not-in-scope claims.

### Evidence semantics

AUDIT PASSED now requires complete provider evidence for live proof classes. Gate-clean live runs with provider-call failures are marked INCONCLUSIVE.

latest-audit remains the latest conclusive PASS proof. latest-run reflects the most recent run including FAIL or INCONCLUSIVE.

The run harness no longer supplies the suite hash under the `pack_hash` field in per-prompt governance context and ITGL entries. `pack_hash` is populated only when a caller supplies a genuine pack hash through `pack_identity_context`; pack hash self-computation remains a backlog item.

The audit workflow now uses the certificate path actually produced by the current run for contract validation, signature verification, run archival, latest-run status, docs publication, and commit staging. Previously, a gate-clean run with failed provider calls could publish a historical passing certificate to the docs surface as current evidence and record the run as PASS; non-passing runs now preserve their current `local-audit` certificate without replacing the latest passing proof.

The paired benchmark workflow now determines gated-run status from the current gated member's archived certificate, verified byte-identical to the canonical proof, rather than reading a hard-coded path. The CLI acceptance workflow now verifies and archives the certificate actually produced by each run. Previously, an inconclusive gated benchmark member could republish a historical passing certificate to the docs surface, and a non-passing scenario run could verify and archive a certificate from an earlier step in the same job.

### Governance certificate

Signed certificates now include `governance_scope` and `crypto_enforced` fields. These fields are part of the signed payload and verifiable offline. The evidence contract now requires these fields. Certificates generated before SIR 2.2 will not pass contract validation but will continue to pass signature verification. Pre-2.2 certificates remain valid as historical evidence.

### Normalisation hardening

Base64 keyword gate expanded to cover all seven deterministic rule families. Hex decoding added for explicit `hex:` marker and `\\xNN` escape sequences. Arbitrary contiguous hex strings are not decoded.

### Operator changes

Manual free-text provider/model/pack entry was replaced with controlled dropdowns backed by fail-closed validation. Invalid combinations fail before audit or benchmark execution.

### Security hardening

- Tightened domain pack ID validation to prevent path traversal via `SIR_ISC_PACK`.
- Added a boundary check on `SIR_POLICY_PATH` overrides.
- Corrected ISC structure validation to block unconditionally.
- Retained `STRICT_ISC_ENFORCEMENT` for policy and pack schema compatibility; it no longer gates ISC structure rejection.
- Renamed the generic multi-ingress-mode error code to `multiple_ingress_modes_not_allowed` and added a dedicated `mixed_mode_validation` ITGL component and rule metadata, so generic multi-mode conflicts are no longer recorded as tool-result-specific failures.

### Non-claims

SIR remains a deterministic, rules-based pre-inference governance gate. It does not claim universal prompt-injection prevention, semantic attack detection, model safety certification, control over downstream agent behaviour, application-level security coverage, API message-ordering validation, or control over content it does not receive.
