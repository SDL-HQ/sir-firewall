# SIR – Standards and Governance Alignment

This document explains how SIR’s pre inference governance gate, ISC policy and templates, suite domain packs, and audit artefacts map to common governance and assurance frameworks.
- FYI: ISC (Instruction Structured Container): the structured prompt envelope that must pass policy enforcement before inference.

## 1. Core architecture

**Component:** SIR pre inference governance gate (`src/sir_firewall/`)

- **What it does:** Enforces policy on a structured ISC envelope before any prompt is sent to the model.
- **Key properties:**
  - Deterministic, rules-based execution in Python: no probabilistic classification, no learned inference, and no model in the gate decision path. Deterministic approximations may be used for bounded checks such as payload-size estimation.
  - Fail closed on malformed ISC or disallowed templates.
  - Normalisation and deterministic jailbreak-pattern checks driven by runtime policy and rule code.
  - Separately versioned benchmark suites provide prompts and expected outcomes used to evaluate that runtime behavior.
  - Produces evidence artefacts suitable for audit.

## Framework relevance boundary

The mappings below are untested architectural relevance notes only. They identify SIR artefacts that a qualified reviewer may consider during a framework assessment. They do not establish framework coverage, conformity, compliance, or certification, and this repository does not map them to specific editions, articles, controls, or clauses.

**Standards relevance:**
- **EU AI Act relevance:** robustness, monitoring, and auditability reviews may consider the gate's pre-inference controls and generated evidence.
- **NIST AI RMF relevance:** Govern- and Measure-oriented reviews may consider the gate as a measurable pre-inference control surface.
- **ISO/IEC 42001 relevance:** AI-management-system reviews may consider the gate's operational controls and evidence.

## 2. Policy and templates (ISC policy)

**Component:** ISC runtime policy and independently verifiable signed policy record
- Runtime policy source: `policy/isc_policy.json`
- Signed policy record: `policy/isc_policy.signed.json`
- Signing tool: `tools/sign_policy.py`
- Independent verification tool: `tools/verify_policy.py`

- **Runtime behavior:** The gate loads `policy/isc_policy.json` and enforces its allowed ISC templates, flags, and constraints deterministically before inference.
- **Signed-record behavior:** `policy/isc_policy.signed.json` records a signed copy and hash of an approved policy state. It can be verified independently with `tools/verify_policy.py`.
- **Correspondence check:** Because the certificate's `policy_hash` and the signed record's `payload_hash` use the same canonicalized policy bytes, an auditor can compare those digests to establish that they describe the same `policy/isc_policy.json` state.
- **Boundary:** Runtime policy loading does not verify `policy/isc_policy.signed.json` and is not cryptographically bound to that signed record before enforcement.

**Standards relevance:**
- **ISO/IEC 42001 relevance:** reviews of controlled documentation and change management may consider the runtime policy and independently verifiable signed policy record, subject to the runtime-binding limitation stated above.
- **Assurance and audit:** the signed policy record provides independently verifiable provenance for an approved policy state; digest comparison can link that record to certificate evidence without making runtime enforcement perform the verification.

## 3. Suite domain packs (test suites)

**Component:** Suite CSV files (domain packs)
- Location: `tests/domain_packs/`
- Example: `tests/domain_packs/generic_safety.csv`
- Validator: `tools/validate_domain_pack.py`
- Runner: `red_team_suite.py`

- **What they do:** Define prompts, expected outcomes, and categories for repeatable evaluation runs.
- **Why it matters:** Provides stable, versionable inputs for regression testing and audit evidence.

**Standards hooks:**
- **NIST AI RMF relevance:** Measure-oriented reviews may consider the versioned suites as repeatable evaluation inputs and evidence-generation fixtures.
- **EU AI Act relevance:** reviews of testing and oversight evidence may consider the versioned suites and their run artefacts.

## 4. ITGL ledger (hash chained run log)

**Component:** ITGL ledger
- Ledger: `proofs/itgl_ledger.jsonl`
- Final hash: `proofs/itgl_final_hash.txt`
- Verifier: `tools/verify_itgl.py`

Each run writes one ledger row per prompt, recording the governance decision,
the expected outcome, a hash of the prompt, the domain pack and template in
force, the suite path, and, for a pass, which rule families were evaluated and
found clean. Each row carries the gate's terminal hash for that prompt, and the
rows are chained.

**What the chain establishes.** Order and completeness. The chain is computed as
`ledger_hash = sha256(prev_hash + final_hash)`, starting from `GENESIS` and
regenerated per run, so no row can be removed, inserted or reordered without
the chain failing. `tools/verify_itgl.py` checks this offline.

**What the chain does not establish.** The chain covers the per-prompt terminal
hash and the link to the previous row. It does not cover the remaining row
fields, so it is not by itself evidence that a row's recorded decision is the
decision the gate made. Row contents are made tamper-evident by a different
mechanism: each run archive's `manifest.json` carries a SHA-256 of the ledger
file, and `archive_receipt.json` signs that manifest.
`tools/verify_archive_receipt.py` is the check that establishes the ledger file
is byte-identical to the one that was signed, and it must be run for that
property to hold.

**What is not published.** The gate's internal step trace is held in process and
is not written to the archive. Only the terminal hash per prompt is published.
That hash incorporates a capture timestamp, so it is a commitment rather than a
value a third party can recompute. Reconstruction of a run's internal decision
steps from published artefacts is therefore not possible.

**Standards hooks:**
- **EU AI Act relevance:** reviews of logging and auditability may consider the per-prompt ledger, its ordering and completeness property, and the signed archive receipt that covers the ledger file.
- **NIST AI RMF relevance:** Measure-oriented reviews may consider the ITGL ledger as per-prompt outcome evidence for individual runs.
- **Assurance and insurance:** supports independent offline verification that a published run's ledger is complete, correctly ordered, and unchanged since signing, and that the certificate's terminal hash and row count bind to it.

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
- **ISO/IEC 42001 relevance:** reviews of monitoring and control operation may consider signed certificates and per-run proof artefacts.
- **NIST AI RMF relevance:** Govern- and Measure-oriented reviews may consider the machine-verifiable certificate and archive artefacts.
- **Insurability and assurance:** provides a stable evidence object that binds configuration and results.

## 6. How to cite SIR in governance documents

When describing SIR in internal policies, you can refer to it as:

> “A deterministic pre inference governance gate (SIR) that enforces a runtime ISC policy, publishes an independently verifiable signed policy record, and records results into a hash chained ITGL ledger. CI runs publish signed audit certificates and per run archives that can be verified offline.”

Pointers:
- Core gate: `src/sir_firewall/`
- Policy and signing: `policy/isc_policy.json`, `policy/isc_policy.signed.json`, `tools/sign_policy.py`
- Suites (domain packs): `tests/domain_packs/`
- ITGL ledger: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
- Signed audit: `proofs/latest-audit.json`, `proofs/latest-audit.html`
- CI entrypoint: `red_team_suite.py`, `tools/generate_certificate.py`
