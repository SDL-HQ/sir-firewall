# D5 — First benchmark execution and evidence review (April 5, 2026)

This note records the D5 execution outcome for the canonical benchmark cycle contract in `docs/benchmark-cycle.v1.md`.

## Scope discipline

- Executed only the canonical first benchmark rows from D4.
- Did not add packs, scenarios, scoring, ranking, or UI/product surface.
- Kept D5 as execution/evidence review, not feature work.

## Canonical row execution status

Required set from D4:

1. `generic_safety` as `FIREWALL_ONLY_AUDIT` → **executed + archived**
   - run_id: `20260405-040319-000000-702b336916d3`
2. `account_recovery_fraud` as `FIREWALL_ONLY_AUDIT` → **executed + archived**
   - run_id: `20260405-040322-000000-aed41b22e195`
3. `scenario_injection_chain` as `SCENARIO_AUDIT` → **executed + archived**
   - run_id: `20260405-040324-000000-2c99d5f16574`
4. `generic_safety` as `LIVE_GATING_CHECK` sentinel slice → **blocked (not executed)**
   - exact blocker: `ERROR: LIVE mode requires your own provider credentials (XAI_API_KEY). SIR does not ship keys.`

## Evidence quality findings (based on produced D5 artefacts)

### What is working as intended

- Each executed row has a run archive containing `manifest.json`, `audit.json`, `archive_receipt.json`, and copied proof artefacts (`proofs/run_summary.json`, `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`, `proofs/latest-attempts.log`).
- `proofs/runs/benchmark_index.v1.json` includes attributable rows for all three executed runs with explicit:
  - `evaluation_target` (including `target_kind`)
  - `proof_class`
  - `provider` / `model`
  - `row_identity`
  - evidence links
- Scenario row is correctly represented as `evaluation_target.target_kind = "scenario_pack"`; domain-pack rows remain `"domain_pack"`.
- Leaks attribution in benchmark entries is present and useful (`comparison.leaks` captured as `0`, `5`, `0` for the three D5 rows).

### Friction/gaps exposed by actual use

- This D5 execution is **truthfully partial** against the strict D4 validity rule because the required live sentinel row is blocked by missing `XAI_API_KEY`.
- Local/dev archive receipt verification can fail by default when `signing_key_id` points at registry keys but the archive was signed with a local ephemeral key; verification succeeds when explicitly using `--pubkey <dev-pubkey>` and bypassing key-registry resolution. This is interpretation friction, not evidence corruption.
- `sir_firewall_version` and `commit_sha` are blank/unknown in this local environment for new D5 rows, which weakens comparability precision even though row-level artefacts remain attributable.

### Historical attribution classification for the April 5 local cluster

- Decision: **retain/document as historical pre-fix local/out-of-band artefacts** (do not regenerate in-place).
- Rationale:
  - These files are already referenced as concrete historical run evidence for the first D5 execution pass.
  - Regenerating would mutate historical payloads/signatures/fingerprints and blur what was actually produced at that time.
  - They should remain inspectable as pre-fix local outputs, while newer local runs use improved attribution fallback.
- Included artefacts in this retained cluster:
  - `proofs/audit-certificate-2026-04-05T040320Z.json`
  - `proofs/audit-certificate-2026-04-05T040322Z.json`
  - `proofs/audit-certificate-2026-04-05T040325Z.json`
  - `proofs/runs/20260405-040319-000000-702b336916d3/{audit.json,manifest.json,archive_receipt.json}`
  - `proofs/runs/20260405-040322-000000-aed41b22e195/{audit.json,manifest.json,archive_receipt.json}`
  - `proofs/runs/20260405-040324-000000-2c99d5f16574/{audit.json,manifest.json,archive_receipt.json}`

## Conclusion

- D5 produced usable attributable evidence for the three runnable canonical rows.
- D5 did **not** produce a full valid canonical v1 cycle because the live sentinel row could not run without provider credentials.
- No workflow/product redesign was done in D5; only benchmark execution evidence and a review note were added.
