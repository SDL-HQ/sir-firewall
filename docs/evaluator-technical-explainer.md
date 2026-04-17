# SIR Evaluator Technical Explainer

This document is a technical explainer for evaluators, auditors, governance/risk reviewers, and technical readers.

It defines what current SIR does, what evidence it produces, what claims are in scope, what claims are out of scope, and how to verify SIR evidence offline.

## Evaluator path (start here)

Use this document as the **single primary evaluator entry point**.

For a strictly procedural single-path pilot flow, use `docs/minimal-pilot-runbook.md`.

Read and verify in this order:

1. **Scope and boundary** in this document (`What SIR is`, `What SIR does not prove`, `Current gate capability boundary`).
2. **Truth surfaces and interpretation rules** in this document (`What SIR produces`, `Benchmark and proof interpretation semantics`).
3. **Offline verification steps** in this document (`Offline verification` section below).
4. **Supporting context only if needed**:
   - `docs/assurance-kit.md` for operator-oriented walkthrough language.
   - `docs/compliance-evidence-map.md` for packaging/inventory convenience.
   - `docs/engineer-guide.md` for local engineering operations.

Source-of-truth posture for evaluator decisions:

- Treat evidence artifacts and their verification outputs as source of truth.
- Treat explanatory docs (including this explainer) as interpretation context over those existing evidence surfaces.
- Do not treat any explanatory doc as a new proof artifact or independent truth endpoint.

## Product definition

SIR is a deterministic pre-inference governance gate that produces independently verifiable evidence about model-facing request paths.

## What SIR is

Current SIR is:

- text-first
- request-level
- deterministic pre-inference gating
- structured-envelope aware around that request path
- pack/scenario evaluation against that path
- proof/archive producing around gate behavior

Operationally, SIR evaluates a request path before model inference and produces run evidence and proof artefacts tied to that evaluated path.

## What SIR produces (truth surfaces vs context)

SIR produces evidence artefacts, including:

- run-level evidence (`proofs/run_summary.json`, `proofs/latest-attempts.log`)
- integrity chain artefacts (`proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`)
- signed certificate pointer for latest passing audit (`proofs/latest-audit.json`, `proofs/latest-audit.html`)
- latest run status surface (`docs/latest-run.json`, served as `/latest-run.json`) with PASS/FAIL/INCONCLUSIVE truth
- per-run archive evidence (`proofs/runs/<run_id>/...`) with manifest, audit snapshot, and archive receipt
- benchmark index mapping (`proofs/runs/benchmark_index.v1.json`) as evidence-linked comparison rows

Public Pages and published GitHub artefacts are the authoritative public truth surfaces for shared evidence review.
Explanatory documentation describes how to read those surfaces; it does not replace them.

## What SIR proves

SIR proves deterministic gate behavior for the evaluated request path under the specific run context.

Concretely, SIR evidence can demonstrate:

- what policy/pack context was exercised
- what proof class was executed (`FIREWALL_ONLY_AUDIT`, `LIVE_GATING_CHECK`, `SCENARIO_AUDIT`)
- whether the evaluated path was blocked or passed at the gate
- what run artefacts and hashes were produced
- whether certificate and archive signatures verify against the provided/public keys

This is path-bounded evidence, not a global claim over all system behavior.

## What SIR does not prove

SIR does not prove model alignment, complete deployment safety, or organizational compliance by itself.

Current SIR does **not** claim:

- native multimodal gating
- deep stateful conversational governance
- native tool/function-call governance
- full structured enterprise action-graph governance
- internal model reasoning visibility
- post-inference model behavior governance
- full deployment-surface coverage

## Current gate capability boundary

The current gate boundary is deterministic pre-inference governance for a model-facing request path that SIR actually intercepts and evaluates.

Boundary semantics:

- the claim applies to the exercised SIR request path
- proof classes are separate interpretation classes (not interchangeable)
- latest pass and latest run are intentionally separate truth concepts
- benchmark rows are evidence-linked comparison rows, not scores or rankings

## Residual risk and failure semantics outside the gate

### If SIR blocks

- The evaluated request path is stopped before model inference for that request.
- This block result does not imply governance of other non-intercepted paths.

### If runs are malformed, invalid, or inconclusive

- Treat outcome as non-passing.
- Use `latest-run.json` and run archive artefacts to inspect failure state.
- Latest passing proof pointer (`latest-audit.*`) remains separate from latest run truth.

### If SIR is bypassed

- No SIR governance claim applies to bypassed model-facing traffic.
- Evidence still describes the runs that did execute through SIR.

### If SIR is not actually in front of the model path

- SIR proofs attest only to exercised SIR paths, not to ungoverned alternate paths.
- Residual risk remains for traffic that can reach models without passing through SIR.

### What evidence survives failures

- Failure/inconclusive outcomes remain represented in run truth surfaces and archives.
- Archive entries preserve per-run artefacts for both passing and non-passing runs.

### Residual risk outside current boundary

Residual risk remains for:

- modalities not currently gated natively
- deep multi-turn conversational state not governed by current request-level boundary
- native tool/action graph execution not governed by current gate
- post-inference behavior and downstream side effects
- any deployment path where SIR is absent, bypassable, or not enforced in front of model inference

## Benchmark and proof interpretation semantics

Use these interpretation rules:

- treat `latest-audit.*` as latest passing proof (last known good)
- treat `latest-run.json` as most recent run outcome (including FAIL/INCONCLUSIVE)
- treat run archive as the per-run evidence record for both passes and failures
- treat gate outcomes (`PASS`/`BLOCK`) as separate from run/publication status (`PASS`/`FAIL`/`INCONCLUSIVE`)
- treat latest-audit/latest-run/archive surfaces as strict acceptance-oriented audit truth; treat benchmark rows as exploratory comparison evidence
- treat benchmark index rows as attributable evidence-linked comparison rows only
- do not reinterpret benchmark index as score/ranking output
- maintain proof-class separation when comparing rows

Coverage taxonomy note (v1):

- Pack/scenario taxonomy labels are coverage readability labels only.
- Taxonomy mapping is maintained at pack/scenario level in `spec/packs/PACKS.md`.
- Taxonomy labels do not modify gate outcomes (`PASS`/`BLOCK`).
- Taxonomy labels do not modify run/publication status (`PASS`/`FAIL`/`INCONCLUSIVE`).
- Taxonomy mapping is not a row-level completeness claim and is not an analytics surface.

## Offline verification (linear evaluator flow)

Run these in order.

### 1) Verify published certificate offline

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Expected successful verification output confirms payload-hash match and signature validity against resolved public key material.
This verification proves payload integrity + signature validity only; it does not prove policy correctness, model safety, deployment completeness, or broader trust guarantees.

### 2) Validate certificate contract (optional strictness check)

```bash
python3 tools/validate_certificate_contract.py proofs/latest-audit.json
```

### 3) Verify local/published certificate via CLI

```bash
sir verify cert proofs/latest-audit.json
```

For non-authoritative local/dev keys, verify with explicit matching key:

```bash
sir verify cert proofs/latest-audit.json --key <pubkey.pem>
```

### 4) Verify archive receipt for a run bundle

```bash
sir verify archive proofs/runs/<run_id>/
```

If archive signing key is non-authoritative local/dev and not in default registry, pass explicit matching public key.

### 5) Verify ITGL chain for run integrity

```bash
python3 tools/verify_itgl.py
```

## Authoritative vs local trust posture

- Public Pages and published GitHub artefacts are the authoritative shared truth surfaces for public evaluation.
- Local/dev verification remains useful for reproducibility and technical validation but is distinct from SDL/public-authoritative trust semantics.

## Supporting-context docs (consult only if needed)

- `docs/assurance-kit.md`: compact operator/evaluator walkthrough aligned to the same evidence semantics.
- `docs/compliance-evidence-map.md`: artifact inventory and packaging helper mapping.
- `docs/engineer-guide.md`: local run/publish/serve mechanics for engineering workflows.

## Scope discipline for D8

This explainer defines evaluator-facing semantics only.
It does not introduce new proof classes, workflows, benchmark design, or product-surface expansion.

### D11 clarification on structured evidence surfacing

D11 reviewed whether benchmark evidence should expose extra structured metadata now.

Current decision:

- No new benchmark scoring or analytics layer.
- No new independent truth surface.
- Continue using benchmark rows as attributable evidence records only.

Evaluator-readable checks that are in scope now (using existing fields):

- For a fixed `row_identity`, inspect repeated PASS/FAIL/INCONCLUSIVE outcomes.
- For comparable repeated rows, inspect whether `comparison.trust_fingerprint` remains stable or changes.
- For comparable repeated rows, inspect whether `comparison.itgl_final_hash` remains stable or changes.

Checks explicitly out of scope now:

- inferred risk scoring from distributions
- rule/category heatmaps
- trend dashboards or coverage dashboards
- threat-intelligence style interpretation from benchmark metadata
