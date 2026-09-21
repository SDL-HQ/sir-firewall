# SIR 2.3.2 — Parser symmetry and registry cleanup

SIR 2.3.2 aligns raw JSON parser failure handling, removes misleading benchmark
placeholders, and makes two assurance constraints explicit. Existing populated
suite coverage counts and gate decisions are unchanged.

## Parser symmetry

- String `tool_result` parsing now catches `MemoryError` alongside
  `JSONDecodeError` and `RecursionError`, matching `structured_request` parsing.
- An in-process tool-result parser `MemoryError` returns `BLOCKED` with reason
  `tool_result_validation_failed` and type `tool_result_invalid_json`.
- The outer `systemic_reset_internal_error` boundary remains in place for
  genuinely unexpected validation failures. Process-level OOM termination
  remains outside any in-process guarantee.

## Registry cleanup

- Seven one-row placeholder suites were removed from the pack registry and from
  `tests/domain_packs/`: `pii_protection`, `healthcare_compliance`,
  `financial_services`, `legal_contracts`, `insurance_underwriting`,
  `code_generation_safety`, and `educational_content`.
- `canary_fail` remains because it is an intentional benchmark-infrastructure
  check rather than a claimed domain suite.
- The generated rule-coverage report now contains nine registry rows instead of
  sixteen. Only seven `0/0` placeholder rows disappeared; every remaining
  suite's deterministic and full-gate `n/n` figures are unchanged.

## Assurance and compatibility

- The threat model now records enumerable rules as a design constraint: adding
  embedding similarity, learned classifiers, semantic scoring, or another
  non-enumerable mechanism forfeits the current reproducible coverage artefact.
- `safety_fingerprint` is deprecated but remains emitted throughout SIR 2.x. It
  is scheduled for removal in SIR 3.0.0. Consumers must read the canonical
  `trust_fingerprint` field before upgrading to 3.0.0.
- Existing signed audit pointers are historical evidence and remain unchanged
  and verifiable.
