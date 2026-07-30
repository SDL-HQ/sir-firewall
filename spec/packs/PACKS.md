# Pack Scale and Hygiene

This file is the canonical pack guidance for the current pack registry model.

## What a pack is

A pack is a versioned test suite plus metadata in `spec/packs/pack_registry.v1.json`.

A pack entry exists to make selection, validation, and review deterministic.

## Scope boundary

- Domain packs are CSV suites under `tests/domain_packs/`.
- Scenario packs use scenario JSON suites under `tests/scenario_packs/`.
- The registry already contains both pack types. This guidance does not introduce new scenario-pack semantics.
- Pack evaluation binds to request-path inputs for deterministic pre-inference gate testing; this file does not define post-inference or full system-governance semantics.

## Three pack artefact categories

The repository uses “pack” for three distinct artefact categories:

1. **ISC policy packs** under `src/sir_firewall/policy/isc_packs/` configure runtime templates, friction limits, enforcement flags and optional structured schemas.
2. **Registry-managed benchmark suites** are the domain CSV and scenario JSON prompt sets listed in `spec/packs/pack_registry.v1.json`.
3. **Non-registry exploratory fixtures** are loaded directly by dedicated tests and are not discoverable through `sir packs list`.

See `tests/domain_packs/README.md` for the operator-facing distinction and fixture examples.

Four registry suites currently have no same-named ISC policy pack: `account_recovery_fraud`, `mental_health_clinical`, `scenario_injection_chain`, and `scenario_tool_injection`. Selecting one through the `--pack` route produces systemic-reset blocks during policy load rather than meaningful suite evaluation. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Required metadata

Each registry entry must include:

- `pack_id` (stable lowercase snake_case)
- `schema` (`csv_single_turn_v1` or `scenario_json_v1`)
- `risk_class` (`baseline`, `domain`, or `encoded_high_risk`)
- `status` (`active`, `draft`, or `deprecated`)
- `version`
- `suite_path`
- `hash_binds_to` (`decoded_prompt_content`)
- `pack_class` (`domain` or `scenario`)
- `visibility` (`public`, `encoded`, or `internal`)
- `maturity` (`canonical` or `demo`)

Optional:

- `doc_path` when a pack has a companion markdown file.

## Coverage taxonomy v1 (canonical)

Coverage taxonomy is a readability label for what a pack/scenario primarily exercises.

Boundary rules:

- Taxonomy labels are pack/scenario-level labels only.
- Labels do not change gate enforcement semantics.
- Labels do not change run/publication status semantics.
- Labels are not scores, rankings, or analytics.
- Use only categories that are currently used by active packs/scenarios.
- Do not claim row-level completeness from this mapping.

Current categories in active use:

- `benign_control`
- `direct_bypass`
- `obfuscation`
- `exfiltration`
- `injection`

Current pack/scenario taxonomy mapping (active and draft registry suites):

| Pack/Scenario | Pack class | Registry posture | Taxonomy category |
| --- | --- | --- | --- |
| `generic_safety` | domain | active / public / canonical | `benign_control`, `direct_bypass`, `obfuscation`, `exfiltration`, `injection` |
| `account_recovery_fraud` | domain | active / public / canonical | `benign_control`, `direct_bypass` |
| `mental_health_clinical` | domain | active / encoded / canonical | `benign_control`, `direct_bypass` |
| `support_operator_override` | domain | active / public / canonical | `benign_control`, `direct_bypass`, `exfiltration` |
| `data_exfiltration_pressure` | domain | active / public / canonical | `benign_control`, `exfiltration` |
| `eu_ai_act_compliance_pressure` | domain | active / public / canonical | `benign_control`, `direct_bypass` |
| `scenario_injection_chain` | scenario | active / public / canonical | `benign_control`, `injection`, `exfiltration` |
| `scenario_tool_injection` | scenario | active / public / canonical | `benign_control`, `injection` |
| `healthcare_compliance` | domain | draft / internal / demo | `benign_control` |
| `financial_services` | domain | draft / internal / demo | `benign_control` |
| `pii_protection` | domain | draft / internal / demo | `benign_control` |
| `code_generation_safety` | domain | draft / internal / demo | `benign_control` |
| `educational_content` | domain | draft / internal / demo | `benign_control` |
| `legal_contracts` | domain | draft / internal / demo | `benign_control` |
| `insurance_underwriting` | domain | draft / internal / demo | `benign_control` |

## Rule-to-suite explainability mapping (indicative only)

This section is an auditor/evaluator readability aid that links current stable rule IDs to suites that are expected to exercise those rule families.

Boundary rules for this mapping:

- This is indicative mapping only, not a completeness proof.
- This is not a score, ranking, percentage, or certification claim.
- Absence of a suite in a row does not mean the rule is unimportant or permanently untested.
- Gate request statuses are `PASS`/`BLOCKED`; run/publication status remains `PASS`/`FAIL`/`INCONCLUSIVE`.
- Canonical rule IDs and descriptions are defined in code (`src/sir_firewall/core.py`); this table is a documentation crosswalk.

Rule-level explainability crosswalk (grounded in current active suites and the workflow-controlled paired benchmark line):

The current workflow-controlled paired benchmark path selects one pack per dispatch from `generic_safety`, `support_operator_override`, `data_exfiltration_pressure`, or `eu_ai_act_compliance_pressure`, then executes an ungated baseline and a gated run for that pack. These four workflow-allowlisted packs, rather than the superseded three-pack cycle, are the current controlled benchmark execution line.

| Rule ID | Rule category | Indicative suites/scenarios | Why this mapping exists (bounded rationale) |
| --- | --- | --- | --- |
| `SIR-RULE-ISC-SCHEMA` | `isc_validation` | Workflow-controlled paired benchmark packs: `generic_safety`, `support_operator_override`, `data_exfiltration_pressure`, `eu_ai_act_compliance_pressure`; plus any other pack/scenario executed through a valid ISC request path | ISC schema validation is request-envelope validation that applies before pack-specific content interpretation. |
| `SIR-RULE-ISC-INTEGRITY` | `integrity_validation` | Workflow-controlled paired benchmark packs: `generic_safety`, `support_operator_override`, `data_exfiltration_pressure`, `eu_ai_act_compliance_pressure`; plus any other pack/scenario executed with integrity checks enabled | Integrity checks are request-envelope integrity controls and are not domain-pack specific. |
| `SIR-RULE-FRICTION-LIMIT` | `friction_guard` | Workflow-controlled paired benchmark packs: `generic_safety`, `support_operator_override`, `data_exfiltration_pressure`, `eu_ai_act_compliance_pressure`; plus any other pack/scenario where payload size can exceed configured limits | Token/friction limit checks are request-size controls independent of domain taxonomy labels. |
| `SIR-RULE-JB-HIGH-RISK` | `jailbreak_guard` | `generic_safety`; `scenario_injection_chain`, `scenario_tool_injection` | Current active taxonomy includes `injection` and `exfiltration` stressors, and `generic_safety` is the broad baseline jailbreak/exfiltration mix. |
| `SIR-RULE-JB-DANGER-SAFETY` | `jailbreak_guard` | `generic_safety`; `scenario_injection_chain`, `scenario_tool_injection` | Scenario and baseline safety suites include override-style adversarial phrasing patterns relevant to this rule family. |
| `SIR-RULE-JB-STRUCTURAL-OVERRIDE-EXFIL` | `jailbreak_guard` | `scenario_injection_chain`, `scenario_tool_injection`; `generic_safety` | Structural override + exfiltration marker patterns align most directly with injection/exfiltration scenario suites and may also appear in baseline adversarial rows. |
| `SIR-RULE-JB-DETERMINISTIC-MATCH` | `jailbreak_guard` | `generic_safety`; `account_recovery_fraud`; `scenario_injection_chain`, `scenario_tool_injection` | Deterministic jailbreak/exfiltration pattern matching is broad and can be exercised across baseline, domain-risk, and scenario adversarial prompts. |

Interpretation guardrail:

- Use this table to explain "which suites are relevant to which rule families" during review.
- Do not use this table to claim all rule behaviors are exhausted by listed suites.
- Do not derive any numeric coverage metric from this table.

## Minimum pack quality bar

The purpose, reviewability, non-duplication and documentation items below are editorial expectations. The automated validators enforce registry metadata and referenced-file existence, CSV schema and row values, and scenario JSON schema; they do not assess substantive editorial quality.

A pack must meet all of the following:

- Purpose is explicit and narrow.
- Rows are reviewable and non-duplicative.
- `expected` labels are deterministic (`allow` or `block`).
- `prompt` vs `prompt_b64` usage follows validator rules.
- Registry entry passes metadata validation.

## Add or update flow

1. Add or modify pack suite file.
2. Add or update pack metadata in `spec/packs/pack_registry.v1.json`.
3. Add or update pack documentation under `tests/domain_packs/` or `tests/scenario_packs/` when applicable.
4. Run validators:
   - `python tools/validate_pack_registry.py --file spec/packs/pack_registry.v1.json`
   - `python tools/validate_domain_pack.py --glob 'tests/domain_packs/*.csv'`
   - `for f in tests/scenario_packs/*.json; do python tools/validate_scenario_pack.py --file "$f"; done`


## Controlled growth policy (D6)

Pack/scenario growth should be small and justified. Additions should only be made when at least one of the following is true:

- Real-world relevance for the current governance posture.
- Clear evaluator usefulness for near-term benchmark interpretation.
- Obvious gap in the current small benchmark set.

Non-goals for growth in this phase:

- Broad taxonomy expansion for its own sake.
- Multimodal or tool-execution expansion.
- Benchmark scoring/ranking redesign.

## Determinism constraints

- No scoring, ranking, or probabilistic pack selection.
- Hash binding remains `decoded_prompt_content`.
- Metadata is declarative and allow-listed.
