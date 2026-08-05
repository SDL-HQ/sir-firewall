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
| Test-only dependencies in runtime dependency surface | Investigating | pytest and PyYAML are declared in the primary dependency list in pyproject.toml and requirements.txt, though neither is required at runtime by any code under src/. For deployment contexts where minimising the runtime dependency surface matters, these belong in a test or dev extra. Moving them would require any CI workflow that installs the package to install that extra. |
| Non-relocatable package distribution | Investigating | The sir console entry point resolves repository-relative paths via Path(__file__).resolve().parents[2] and executes red_team_suite.py and tools/*.py, none of which are declared as package data. Suite CSVs, scenario JSONs, the pack registry, the baseline policy and trust material are also outside the package. A non-editable install is therefore not a viable runtime and is documented as unsupported. Making the distribution self-contained would require relocating the runner and tools into the package, resolving immutable assets with importlib.resources, moving suite data out of tests/, and establishing an explicit workspace contract for mutable outputs. It would also change suite_path values recorded in evidence unless a stable logical resource identifier replaces filesystem paths. |
| Pack hash self-computation | Planned | load_domain_pack() does not compute a content hash of the loaded pack file. pack_hash is populated only when supplied by a caller via pack_identity_context. |
| Raw pre-normalisation obfuscation signal | Planned | obfuscation_signal_detected is evaluated on post-normalisation text. Payloads containing only invisible Unicode with no signal keywords normalise silently without the signal firing. |
| Granular early-exit ITGL components | Planned | ISC structure and structured schema declaration failures produce ITGL entries that reuse generic component types, with the specific error code carried in entry data. The malformed payload early return produces no dedicated ITGL entry. Dedicated component types per error class are not implemented for these paths. |
| Version-source consistency check | Planned | No automated check prevents package and artefact version drift. |
| Certificate result not the single authority for CI outcome | Planned | The finalize step derives its exit condition from `AUDIT_PASS`, computed from gate counters before the certificate exists. That value cannot represent live provider incompleteness, certificate generation failure, or certificate validation failure. The latest-run marker and proof commit message now derive status from the signed certificate result, but the finalizer still consults the counter-derived value. Consider deriving the CI outcome from the certificate result directly, and renaming the counter value to something explicitly limited such as `GATE_COUNTERS_CLEAN`. |
| Benchmark marker maps unrecognised certificate results to FAIL | Planned | The benchmark latest-run marker recognises `AUDIT PASSED` and `INCONCLUSIVE` explicitly and maps every other value to `FAIL`. An absent, malformed, or unrecognised result is therefore classified as a conclusive failure rather than failing closed. The single-run marker now recognises all three values explicitly and fails on anything else. The benchmark marker should receive the same treatment. |
| Provider response trace metadata | Investigating | Non-sensitive provider response id, model, and token metadata for live evidence. |
| Perimeter comparison claims not bound to specific pairs | Planned | docs/evidence-perimeter.v4.md states that selected comparisons used the latest valid_complete pairs, without recording pair IDs, run IDs or an index revision. Later pairs have since been archived, so "latest" no longer resolves to the pairs that produced the published figures. The backing pairs can be correlated from archive contents but are not stated in the document, so the cross-model claims are not independently verifiable from the perimeter alone. Consider recording pair IDs for each published position. |
| Provider-returned model identity not recorded | Planned | The certificate model field records the identifier SIR requested. The provider response is hashed and optionally excerpted but never inspected for a model identifier, so a provider-side resolution or redirect is not detected or recorded. xAI's 15 May 2026 retirement redirected grok-4-1-fast requests to grok-4.3 while SIR continued to sign grok-4-1-fast. Consider capturing the response model identifier and recording it alongside the requested identifier, or failing the call when the two differ. |
| Transient provider retry policy | Investigating | Limited retries for provider or server errors without concealing final failures. |
| RSA-PSS signature padding | Planned | Certificate signing and verification currently use PKCS1v15. RSA-PSS is the recommended padding for new systems. |
| CJK token estimation | Planned | _estimate_tokens() uses a character-based approximation that underestimates token count for CJK text, making friction limits more permissive for non-whitespace-delimited languages. |
| Review bundle contents | Investigating | tools/export_review_bundle.py includes a superseded historical benchmark review in every exported compliance bundle. Reviewer-facing documentation also references it in two places. Whether superseded records belong in a review bundle intended to convey current state needs deciding. |
| Silent skip on missing archive copy targets | Planned | publish_run.py silently skips --copy targets that do not exist. A run archive can be published with expected evidence files absent and no warning emitted. Consider warning on skipped targets, or recording skipped paths in the manifest so an archive consumer can tell the difference between a file that was never produced and one that was excluded. |
| Signed policy correspondence not automatically verified | Planned | The certificate's policy_hash and the signed record's payload_hash use identical canonicalization and currently match, so correspondence can be established by manual digest comparison. Nothing verifies it automatically. Runtime policy loading does not check the signed record, and no test or CI step asserts the two digests agree. Consider verifying the signed policy at load time, or asserting correspondence during certificate generation. |
| Signed policy staleness undetected | Planned | If policy/isc_policy.json is modified without re-running tools/sign_policy.py, policy/isc_policy.signed.json becomes stale and the digests diverge. No test, tool or CI step detects this. Consider a CI check that the signed record matches the current policy file. |
| Systemic reset counted as prompt-level result | Planned | When an explicitly requested ISC policy pack is missing, `validate_sir()` returns `systemic_reset_domain_pack_load_failed` with status `BLOCKED`. `red_team_suite.py` compares only status against the expected label, so expected-block rows are credited as correct and expected-allow rows are counted as `harmless_blocked`. The runner does not inspect verdict `reason` or `sr` fields, emits no warning, and exits 0. A suite containing only expected-block rows would report 0 leaks and 0 harmless blocked from a total policy-load failure. Minimal fix: resolve the ISC policy pack once before the row loop and fail non-zero before writing evidence. |
| Benchmark suite identity coupled to ISC policy pack identity | Investigating | `red_team_suite.py` passes the resolved registry `pack_id` to `validate_sir()` as `enforcement_pack_id`, which becomes the explicit `pack_id` argument to `load_domain_pack()`. Registry benchmark suites and ISC policy packs are documented as distinct artefact classes, and the registry accepts suites with no same-named policy pack. Four currently do: `account_recovery_fraud`, `mental_health_clinical`, `scenario_injection_chain`, `scenario_tool_injection`. The workflow allowlist in `spec/execution/run_selection_registry.v1.json` is exactly the intersection of registry suite IDs and ISC policy pack IDs. Options: decouple suite identity from policy selection with an explicit or default policy choice preserving benchmark attribution, or provide an ISC policy pack per suite. No code comment or documentation states the coupling is intended. |
| Rule coverage gaps in four benchmark suites | Planned | Deterministic rule families in `deterministic_rules.py` are global. `_check_jailbreak()` receives no `domain_cfg`, and ISC policy packs contain no rule configuration—only `pack_id`, description, templates, flags and optionally `structured_request_schema`. Evaluated against the current rule set, expected outcomes fail: `account_recovery_fraud` 5 of 5 expected-block rows leak, `mental_health_clinical` 10 of 15, `scenario_injection_chain` 4 of 10, `scenario_tool_injection` 1 of 2. Three published `account_recovery_fraud` certificates from April 2026 record `AUDIT FAILED` with 5 leaks, so the gap is already visible in the evidence archive. Providing ISC policy packs would restore execution attribution but would not make these expectations pass, because the rules are global. |
| R1 scenario acceptance assertions insufficient | Planned | `.github/workflows/r1-cli-acceptance.yml` runs `sir run --mode scenario --pack scenario_injection_chain` and asserts pack ID, suite name, scenario ID presence, `SCENARIO_AUDIT` proof class, positive prompt count and zero provider calls. It does not assert absence of systemic reset, `harmless_blocked`, or gate request statuses. The workflow therefore passes when every turn is systemic-reset blocked and nothing is evaluated. The correct assertion for a CLI acceptance test is absence of systemic reset, not zero leaks—zero leaks is a pack-quality assertion, not a CLI acceptance assertion. |
| No row-level expected-outcome test coverage | Planned | No test asserts row-level expected outcomes for any benchmark suite. `tests/test_cli_run_py.py` mocks `_run_py` and tests dispatch, not gate results. `tests/test_validate_run_selection.py` checks allowlist rejection without executing suites. Suite content can therefore diverge from what the rules actually catch without any test failing. |

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
