# SIR Public Backlog

This backlog tracks known hardening items, constraints, and planned work. Inclusion does not imply a committed release date.

SIR separates current implemented behaviour from planned hardening work and future candidate coverage.

## Status labels

- Current
- Planned
- Investigating
- Known constraint
- Future candidate
- Not in scope

## Current domain packs

| Pack | Status | Notes |
|---|---|---|
| generic_safety | Current | Baseline coverage for bypass attempts, harmful requests, and prompt injection patterns. |
| data_exfiltration_pressure | Current | Attempts to extract restricted content, secrets, or internal data through pressure and reframing. |
| support_operator_override | Current | Override-style prompts invoking authority, support escalation, or operator language. |
| eu_ai_act_compliance_pressure | Current | Pressure patterns testing whether stated governance, disclosure, and control boundaries hold. Bounded partial-coverage pack, not a full-pass pack. |
| hipaa_mental_health | Current | Domain pack for HIPAA-bound mental health workloads. |
| pci_payments | Current | Domain pack for PCI-style payment workloads. |

## Evidence hardening backlog

| Item | Status | Notes |
|---|---|---|
| Pack hash self-computation | Planned | load_domain_pack() does not compute a content hash of the loaded pack file. pack_hash is populated only when supplied by a caller via pack_identity_context. |
| Raw pre-normalisation obfuscation signal | Planned | obfuscation_signal_detected is evaluated on post-normalisation text. Payloads containing only invisible Unicode with no signal keywords normalise silently without the signal firing. |
| Granular early-exit ITGL components | Planned | ISC structure and structured schema declaration failures produce ITGL entries that reuse generic component types, with the specific error code carried in entry data. The malformed payload early return produces no dedicated ITGL entry. Dedicated component types per error class are not implemented for these paths. |
| Version-source consistency check | Planned | No automated check prevents package and artefact version drift. |
| Provider response trace metadata | Investigating | Non-sensitive provider response id, model, and token metadata for live evidence. |
| Transient provider retry policy | Investigating | Limited retries for provider or server errors without concealing final failures. |
| RSA-PSS signature padding | Planned | Certificate signing and verification currently use PKCS1v15. RSA-PSS is the recommended padding for new systems. |
| CJK token estimation | Planned | _estimate_tokens() uses a character-based approximation that underestimates token count for CJK text, making friction limits more permissive for non-whitespace-delimited languages. |

## Known constraints

| Item | Status | Notes |
|---|---|---|
| Structured schema extensibility | Known constraint | Adding new structured schema types requires multiple explicit change points. Intentional for v1. |
| GitHub dependent dropdowns | Known constraint | GitHub Actions does not support dynamic dependent dropdowns. Invalid provider and model combinations fail closed in validation. |
| Deterministic rule scope | Known constraint | SIR evaluates deterministic rules over declared ingress content. It does not infer hidden downstream agent state. |
| strict_isc flag | Known constraint | STRICT_ISC_ENFORCEMENT is retained for policy and pack schema compatibility. ISC structure rejection is unconditional and no longer gated by this flag. |

## Future pack candidates

Possible expansion areas only. Not current implemented coverage.

| Candidate | Status |
|---|---|
| Tool result injection pressure | Future candidate |
| Mental health clinical | Future candidate |
| PII protection | Future candidate |
| Financial services | Future candidate |
| Legal and contracts | Future candidate |
| Insurance and underwriting | Future candidate |
| Code generation safety | Future candidate |

## Not in scope

| Item | Notes |
|---|---|
| Semantic prompt-injection detection | SIR remains deterministic and rules-based. |
| Universal agentic-injection prevention | SIR evaluates declared ingress content. It does not control every downstream agent path. |
| Model safety certification | SIR produces gate and evidence artefacts, not model safety certification. |
| Content SIR never receives | SIR cannot evaluate content outside its declared ingress path. |
| API message-ordering validation | SIR does not validate API-level message ordering or role sequence. Deployments using self-hosted inference should independently enforce message-ordering validation. |
| Multi-turn context accumulation | SIR evaluates declared ingress at the request boundary. It does not evaluate state accumulated across conversation turns. |
