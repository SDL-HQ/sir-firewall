# SIR External Technical Review Preparation

This document prepares SIR for independent technical scrutiny.

This is not the external review itself.
It defines what should be reviewed, which artefacts are canonical, and which claims are in and out of scope for review.

## Purpose and scope of this preparation

Use this document to give an external technical reviewer a clean, bounded path through the current SIR product state.

Reviewer objective for this round:

- evaluate whether SIR's current technical claims are precise and supported by artefacts
- evaluate whether evidence and verification surfaces are coherent and independently checkable
- evaluate whether benchmark and proof semantics are interpretable without private context

This D9 preparation does **not** ask a reviewer to certify the product, certify compliance, or validate claims SIR does not make.

## What the reviewer should review

A reviewer should assess the following technical areas.

1. Current gate capability boundary
   - deterministic pre-inference governance gate behavior
   - explicit boundaries (text-first, request-level) and non-claims
   - residual-risk semantics for bypassed or out-of-bound paths

2. Proof and archive surfaces
   - latest-pass vs latest-run distinction
   - per-run archive completeness (pass and non-pass runs)
   - append-only public evidence history posture of `proofs/runs/` (as bounded in `RETENTION.md`)
   - certificate and archive signature verification posture

3. Benchmark contract and first benchmark cycle evidence
   - benchmark-cycle v1 contract discipline
   - row comparability semantics (`row_identity`, proof-class separation)
   - D5 first-cycle execution reality, including blocked live sentinel row

4. Verification flow quality
   - offline verification path for certificates, archive receipts, and ITGL
   - trust-source clarity (authoritative SDL/public vs local/dev)

5. Trust semantics and key governance readiness
   - current trust anchors and authority boundaries
   - readiness conditions for future `CRYPTO_ENFORCED` enablement (not enablement itself)

6. Documentation coherence
   - consistency of claims and boundaries across canonical docs
   - ability to complete technical review without repo archaeology

## Canonical reviewer artefact map

Review in this order.

1. Product and public trust-surface overview
   - `README.md`

2. Canonical evaluation, scope, and verification semantics
   - `docs/assurance-kit.md`

3. Evaluator-facing boundary and residual-risk explainer
   - `docs/evaluator-technical-explainer.md`

4. Engineering execution and local verification flows
   - `docs/engineer-guide.md`

5. Benchmark contract (locked v1)
   - `docs/benchmark-cycle.v1.md`

6. First benchmark-cycle execution note (D5)
   - `docs/d5-benchmark-first-cycle-review.md`

7. Key authority and trust-readiness semantics
   - `docs/key-governance-readiness.md`

8. Retention and durability semantics
   - `RETENTION.md`

9. Canonical technical truth surfaces and verification tools
   - public Pages surfaces referenced in `README.md` (`latest-audit.*`, `latest-run.json`, `runs/index.html`)
   - certificate contract: `spec/evidence_contract.v1.json`
   - certificate verification: `tools/verify_certificate.py`
   - archive receipt verification: `tools/verify_archive_receipt.py`
   - ITGL verification: `tools/verify_itgl.py`

## Claims in scope for external technical review

The reviewer is being asked to evaluate whether current bounded claims are technically supported.

In-scope claim categories:

- SIR is a deterministic pre-inference governance gate on the exercised request path.
- SIR evidence surfaces and artefacts are coherent and interpretable.
- Offline verification paths can validate certificate/archive integrity using published or explicitly supplied keys.
- Benchmark artefacts are usable as attributable evidence rows under the v1 comparability contract.
- Distinction between authoritative SDL/public trust and local/dev trust is explicit and consistent.

## Claims explicitly out of scope for this review

The reviewer is **not** being asked to validate any of the following:

- independent validation merely because benchmark evidence is self-produced
- model alignment or broad model safety
- multimodal, deep conversational-state, native tool/function-call, or post-inference governance claims
- compliance certification, insurer approval, or regulatory certification
- workflow redesign, benchmark redesign, or new proof-surface creation

## Reviewer output expectations

A useful external technical review output should include:

- confirmation (or rejection) that claim boundaries are explicit and technically matched to artefacts
- confirmation (or rejection) that verification and trust semantics are reproducible from canonical surfaces
- identified ambiguity, inconsistency, or overclaim risk in current docs/evidence semantics
- concrete corrective recommendations with file-level pointers

## Preparation quality checklist (D9)

This preparation is complete when all are true:

- reviewer path is single-entry and bounded (this doc)
- canonical artefacts are listed and sufficient for technical scrutiny
- in-scope and out-of-scope claims are explicit
- no external-validation language is implied
- no product-surface expansion is introduced by this preparation step
