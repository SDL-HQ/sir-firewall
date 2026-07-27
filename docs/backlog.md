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

## Current pack surfaces

ISC policy packs and benchmark test suites are distinct artefacts. ISC policy packs configure the runtime gate, while benchmark test suites provide prompts that the runner executes to produce evidence. Four identifiers exist in both surfaces: `generic_safety`, `data_exfiltration_pressure`, `support_operator_override`, and `eu_ai_act_compliance_pressure`. `hipaa_mental_health` and `pci_payments` are policy packs with no corresponding test suite.

### ISC policy packs

These runtime configurations are loaded by `load_domain_pack()`. They control allowed ISC templates, per-template friction limits, enforcement flags, and, where noted, a `structured_request_schema`.

| Policy pack | Configuration |
|---|---|
| data_exfiltration_pressure | Baseline template limits and enforcement flags; declares `structured_request_schema`. |
| eu_ai_act_compliance_pressure | Baseline template limits and enforcement flags; no structured schema. |
| generic_safety | Baseline template limits and enforcement flags; declares `structured_request_schema`. |
| hipaa_mental_health | Tighter template limits for HIPAA-bound mental-health workloads and enforcement flags; no structured schema. |
| pci_payments | Payment-oriented template limits, including the tightest PCI limit, and enforcement flags; no structured schema. |
| support_operator_override | Baseline template limits and enforcement flags; declares `structured_request_schema`. |

### Current benchmark test suites

These substantive prompt sets are active, public registry entries executed by the runner to produce evidence.

| Benchmark suite | Size |
|---|---:|
| generic_safety | 150 rows |
| eu_ai_act_compliance_pressure | 150 rows |
| data_exfiltration_pressure | 50 rows |
| support_operator_override | 50 rows |
| account_recovery_fraud | 8 rows |
| scenario_injection_chain | 15 turns |

**Other registered suites:** `mental_health_clinical` has 25 rows and `encoded` visibility because its risk class is `encoded_high_risk`; its prompts are stored base64-encoded and it is not listed by `sir packs list` by design. `scenario_tool_injection` has 5 turns and is active and public. `canary_fail` is a draft/internal benchmark infrastructure check.

**Non-registry fixtures:** `structured_account_recovery_benchmark.json` has 13 cases and is loaded directly by `tests/test_structured_benchmark_pack.py`. `tool_result_ingress_benchmark.json` has 4 cases and is loaded directly by `tests/test_tool_result_benchmark_pack.py`. Both are exploratory fixtures outside the registry and outside `sir packs list`.

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
| Review bundle contents | Investigating | tools/export_review_bundle.py includes a superseded historical benchmark review in every exported compliance bundle. Reviewer-facing documentation also references it in two places. Whether superseded records belong in a review bundle intended to convey current state needs deciding. |
| Silent skip on missing archive copy targets | Planned | publish_run.py silently skips --copy targets that do not exist. A run archive can be published with expected evidence files absent and no warning emitted. Consider warning on skipped targets, or recording skipped paths in the manifest so an archive consumer can tell the difference between a file that was never produced and one that was excluded. |

## Known constraints

| Item | Status | Notes |
|---|---|---|
| Structured schema extensibility | Known constraint | Adding new structured schema types requires multiple explicit change points. Intentional for v1. |
| GitHub dependent dropdowns | Known constraint | GitHub Actions does not support dynamic dependent dropdowns. Invalid provider and model combinations fail closed in validation. |
| Deterministic rule scope | Known constraint | SIR evaluates deterministic rules over declared ingress content. It does not infer hidden downstream agent state. |
| strict_isc flag | Known constraint | STRICT_ISC_ENFORCEMENT is retained for policy and pack schema compatibility. ISC structure rejection is unconditional and no longer gated by this flag. |

## Future pack candidates

Possible expansion areas only. Not current implemented coverage.

| Candidate | Description |
|---|---|
| Mental Health Clinical | Clinical and mental-health interaction cases. |
| PII Protection | Identity data, re-identification, and personal data handling cases. |
| Healthcare Compliance | Healthcare process and restricted-handling cases. |
| Financial Services | Transaction, account, and high-trust financial handling cases. |
| Legal & Contracts | Contractual and sensitive document handling cases. |
| Insurance & Underwriting | Evidence review and underwriting-adjacent workflow cases. |
| Code Generation Safety | Code, command, and secret-handling cases. |
| Educational Content | Restricted-topic and assessment-integrity cases. |

Seven of these candidates have placeholder suites in the repository containing a single row. They are registered as draft/internal/demo and are not available through `sir packs list`. Mental Health Clinical is listed as a future candidate for the domain area; a separate `mental_health_clinical` test suite with 25 encoded rows exists and is registered active.

## Not in scope

| Item | Notes |
|---|---|
| Semantic prompt-injection detection | SIR remains deterministic and rules-based. |
| Universal agentic-injection prevention | SIR evaluates declared ingress content. It does not control every downstream agent path. |
| Model safety certification | SIR produces gate and evidence artefacts, not model safety certification. |
| Content SIR never receives | SIR cannot evaluate content outside its declared ingress path. |
| API message-ordering validation | SIR does not validate API-level message ordering or role sequence. Deployments using self-hosted inference should independently enforce message-ordering validation. |
| Multi-turn context accumulation | SIR evaluates declared ingress at the request boundary. It does not evaluate state accumulated across conversation turns. |
