# SIR – Standards and Governance Alignment

This document explains how SIR’s pre inference governance gate, ISC policy and templates, suite domain packs, and audit artefacts map to common governance and assurance frameworks.

## 1. Core architecture

**Component:** SIR pre inference governance gate (`src/sir_firewall/`)

- **What it does:** Enforces policy on a structured ISC envelope before any prompt is sent to the model.
- **Key properties:**
  - Deterministic rules only execution in Python. No training. No heuristics.
  - Fail closed on malformed ISC or disallowed templates.
  - Normalisation and jailbreak pattern checks (suite driven).
  - Produces evidence artefacts suitable for audit.

**Standards hooks:**
- **EU AI Act:** supports technical controls for robustness, monitoring, and auditability in high risk contexts.
- **NIST AI RMF:** aligns with Govern and Measure as a pre inference control surface with measurable evidence.
- **ISO IEC 42001:** supports implementing and demonstrating operational controls for AI system governance.

## 2. Policy and templates (ISC policy)

**Component:** ISC policy file and signature
- Policy source: `policy/isc_policy.json`
- Signed policy: `policy/isc_policy.signed.json`
- Signing tool: `tools/sign_policy.py`

- **What it does:** Defines allowed ISC templates and constraints that the gate enforces deterministically before inference.
- **Why it matters:** Provides provenance and tamper detection for the policy that governs pre inference enforcement.

**Standards hooks:**
- **ISO IEC 42001:** supports controlled documentation, change control, and evidence of implemented governance controls.
- **Assurance and audit:** signed policy helps demonstrate that the enforced policy is the approved policy.

## 3. Suite domain packs (test suites)

**Component:** Suite CSV files (domain packs)
- Location: `tests/domain_packs/`
- Example: `tests/domain_packs/generic_safety.csv`
- Validator: `tools/validate_domain_pack.py`
- Runner: `red_team_suite.py`

- **What they do:** Define prompts, expected outcomes, and categories for repeatable evaluation runs.
- **Why it matters:** Provides stable, versionable inputs for regression testing and audit evidence.

**Standards hooks:**
- **NIST AI RMF Measure:** supports repeatable evaluation and evidence generation.
- **EU AI Act monitoring:** supports documented testing and oversight artefacts.

## 4. ITGL ledger (hash chained run log)

**Component:** ITGL ledger
- Ledger: `proofs/itgl_ledger.jsonl`
- Final hash: `proofs/itgl_final_hash.txt`
- Verifier: `tools/verify_itgl.py`

Each run records a structured decision trace and a hash chain so the log history is tamper evident.

**Standards hooks:**
- **EU AI Act logging:** supports auditability with step level evidence.
- **NIST AI RMF Measure:** provides structured trace evidence for runs.
- **Assurance and insurance:** supports reconstruction and independent verification that the recorded run matches the claimed outcome.

## 5. Signed audit certificates and proof surfaces (CI)

**Component:** Signed audit certificate and human view
- Latest PASS proof pointer: `proofs/latest-audit.json` and `proofs/latest-audit.html`
- Latest run status marker: `docs/latest-run.json`
- Run archives: `proofs/runs/<run_id>/...`

Published proof surfaces (GitHub Pages):
- Latest PASS human page: `/latest-audit.html`
- Latest run status (PASS, FAIL, INCONCLUSIVE): `/latest-run.json`
- Run archive index: `/runs/index.html`

**Semantics:**
- `latest-audit.*` means latest passing audit proof (last known good).
- `latest-run.json` reflects the most recent run status, including FAIL or INCONCLUSIVE.
- The run archive is per run artefacts intended to be truth preserving.

**Standards hooks:**
- **ISO IEC 42001:** supports evidence of monitoring, review, and control operation.
- **NIST AI RMF:** supports Govern and Measure with machine verifiable artefacts.
- **Insurability and assurance:** provides a stable evidence object that binds configuration and results.

## 6. How to cite SIR in governance documents

When describing SIR in internal policies, you can refer to it as:

> “A deterministic pre inference governance gate (SIR) that enforces a signed ISC policy and records results into a hash chained ITGL ledger. CI runs publish signed audit certificates and per run archives that can be verified offline.”

Pointers:
- Core gate: `src/sir_firewall/`
- Policy and signing: `policy/isc_policy.json`, `policy/isc_policy.signed.json`, `tools/sign_policy.py`
- Suites (domain packs): `tests/domain_packs/`
- ITGL ledger: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
- Signed audit: `proofs/latest-audit.json`, `proofs/latest-audit.html`
- CI entrypoint: `red_team_suite.py`, `tools/generate_certificate.py`
