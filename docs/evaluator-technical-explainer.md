# SIR Evaluator Technical Explainer

This document is a technical explainer for evaluators, auditors, governance/risk reviewers, and technical readers.

It defines what current SIR does, what evidence it produces, what claims are in scope, what claims are out of scope, and how to verify a locally available evidence bundle without network access.

## Evaluator path

The single review order is: read `README.md`, use this document for boundary and interpretation detail, and then follow `docs/minimal-pilot-runbook.md` for the worked verification procedure.

Read in this order when interpretation detail is needed:

1. **Scope and boundary** in this document (`What SIR is`, `What SIR does not prove`, `Current gate capability boundary`).
2. **Truth surfaces and interpretation rules** in this document (`What SIR produces`, `Benchmark and proof interpretation semantics`).
3. **Verification model** in this document (`Archived-run verification` section below), followed by the worked commands in `docs/minimal-pilot-runbook.md`.
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
- pack/scenario evaluation against that path
- proof/archive producing around gate behavior

SIR validates bounded structured request and tool-result inputs at the request boundary; it does not govern tool execution, multi-step action graphs, or post-inference behaviour.

Operationally, SIR evaluates a request path before model inference and produces run evidence and proof artefacts tied to that evaluated path.

## What SIR produces (truth surfaces vs context)

SIR produces evidence artefacts, including:

- mutable root compatibility copies (`proofs/run_summary.json`, `proofs/latest-attempts.log`, `proofs/itgl_ledger.jsonl`, and `proofs/itgl_final_hash.txt`), which are useful for current local tooling but are not claim-level evidence; same-named files beneath a specific `docs/runs/<run_id>/proofs/` or `proofs/runs/<run_id>/proofs/` directory are distinct, immutable per-run archive members
- mutable latest-pass pointers (`proofs/latest-audit.json`, `proofs/latest-audit.html`)
- current status pointer (`docs/latest-run.json`, served as `/latest-run.json`) with PASS/FAIL/INCONCLUSIVE status
- per-run archive evidence (`docs/runs/<run_id>/...` and its `proofs/runs/<run_id>/...` source) with manifest, audit snapshot, identity-matched ledger, and archive receipt; the selected per-run bundle is the claim-level source
- benchmark index mapping (`docs/runs/benchmark_index.v2.json`, served as `/runs/benchmark_index.v2.json`) as evidence-linked comparison rows

Public Pages and published GitHub artefacts distribute shared evidence for review. Mutable pointers locate candidates; the selected per-run bundle is the claim-level source.
Explanatory documentation describes how to read those surfaces; it does not replace them.

## What SIR proves

SIR evidence attests to the recorded deterministic gate decision for the evaluated request path under the specific run context. That gate decision—not any model response—is reproducible given the same request inputs and the configuration in the repository at the recorded `commit_sha`; public benchmark inputs are available in that repository revision, while production inputs must be supplied by the operator.

Concretely, SIR evidence can demonstrate:

- what policy/pack context was exercised
- what proof class was executed (`FIREWALL_ONLY_AUDIT`, `LIVE_GATING_CHECK`, `SCENARIO_AUDIT`)
- whether the evaluated path was blocked or passed at the gate
- what run artefacts and hashes were produced
- whether certificate and archive signatures verify against the provided/public keys

This is path-bounded evidence, not a global claim over all system behavior.

## What SIR does not prove

SIR does not prove model alignment, complete deployment safety, or organizational compliance by itself.

Certificate signature verification establishes payload integrity and signature validity; it does not independently establish that the gate executed as recorded.

Current SIR does **not** claim:

- native multimodal gating
- deep stateful conversational governance
- internal model reasoning visibility
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
- Use the `latest-run.json` current status pointer to locate the run, then inspect its archived bundle.
- The mutable latest-passing pointer (`latest-audit.*`) remains separate from the current-run pointer.

### If SIR is bypassed

- No SIR governance claim applies to bypassed model-facing traffic.
- Evidence still describes the runs that did execute through SIR.

### If SIR is not actually in front of the model path

- SIR proofs attest only to exercised SIR paths, not to ungoverned alternate paths.
- Residual risk remains for traffic that can reach models without passing through SIR.

### What evidence survives failures

- Failure/inconclusive outcomes remain represented in per-run archives and can be located through current pointers.
- Archive entries preserve per-run artefacts for both passing and non-passing runs.

### Residual risk outside current boundary

Residual risk remains for:

- modalities not currently gated natively
- deep multi-turn conversational state not governed by current request-level boundary
- any deployment path where SIR is absent, bypassable, or not enforced in front of model inference

## Benchmark and proof interpretation semantics

Use these interpretation rules:

- treat `latest-audit.*` as a mutable pointer to the latest passing proof (last known good), not as an immutable claim-level record
- treat `latest-live-audit.*` as a mutable pointer to the latest qualifying live audit, not as an immutable claim-level record
- treat `latest-run.json` as the current most-recent-run status pointer (including FAIL/INCONCLUSIVE), not as claim-level evidence
- treat the selected per-run archive bundle as the claim-level evidence record for both passes and failures
- treat gate request statuses (`PASS`/`BLOCKED`) as separate from run/publication status (`PASS`/`FAIL`/`INCONCLUSIVE`)
- use latest pointers to locate candidates, but verify claims from an explicitly selected archive bundle; treat benchmark rows as exploratory comparison evidence
- treat benchmark index rows as attributable evidence-linked comparison rows only
- do not reinterpret benchmark index as score/ranking output
- maintain proof-class separation when comparing rows

Coverage taxonomy note (v1):

- Pack/scenario taxonomy labels are coverage readability labels only.
- Taxonomy mapping is maintained at pack/scenario level in `spec/packs/PACKS.md`.
- Taxonomy labels do not modify gate request statuses (`PASS`/`BLOCKED`).
- Taxonomy labels do not modify run/publication status (`PASS`/`FAIL`/`INCONCLUSIVE`).
- Taxonomy mapping is not a row-level completeness claim and is not an analytics surface.

## Archived-run verification

Acquisition and verification are separate. Use the run archive to choose one locally available bundle whose `audit.json` records `sir_firewall_version` 2.3.4 or later; do not choose evidence from a mutable `latest-*` pointer. Retrieving or cloning the bundle requires network access, but the following verification needs no network once the repository and dependencies are locally available.

The worked bundle is `20260921-135018-029319-gh35607761858-f3dd66376a01`. Both checks below use that one directory. `--require-registry` fails closed if its `signing_key_id` cannot be resolved in the repository key registry, rather than silently falling back to a default public key.

The archive receipt verifier checks every file named by `manifest.json`, not only the certificate and ledger. This example therefore requires all five listed files: `audit.json`, `proofs/itgl_final_hash.txt`, `proofs/itgl_ledger.jsonl`, `proofs/latest-attempts.log`, and `proofs/run_summary.json`. A `file listed in manifest is missing` error identifies an incomplete local download; by itself, it does not identify broken archived evidence.

```bash
RUN_ID=20260921-135018-029319-gh35607761858-f3dd66376a01
python3 tools/verify_certificate.py "docs/runs/$RUN_ID/audit.json" --ledger "docs/runs/$RUN_ID/proofs/itgl_ledger.jsonl" --require-registry
python3 tools/verify_archive_receipt.py "docs/runs/$RUN_ID" --require-registry
```

Actual output:

```text
OK: payload_hash and signature verify against key registry spec/pubkeys/key_registry.v1.json entry signing_key_id=default; ledger binding verifies signed itgl_final_hash=sha256:ae9233eec1ae44d9ca20661bc5f460979fd487d1498f79583413037e5200d7ba equals the ledger terminal hash from docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01/proofs/itgl_ledger.jsonl, and signed itgl_row_count=150 equals prompts_tested=150.
OK: archive receipt verified for docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01
```

Record three distinct results:

1. **Signature valid:** the certificate payload hash and signature verify.
2. **Ledger binding valid:** the certificate's signed terminal hash and row count match that same archived run's chain-valid ledger.
3. **Authoritative SDL trust established:** for this bundle, both verifiers resolved `signing_key_id=default` through the approved repository registry `spec/pubkeys/key_registry.v1.json`, and `--require-registry` prevented public-key fallback. If registry resolution does not succeed, record **authoritative SDL trust not established**, even if a signature verifies against an explicitly supplied local/dev key.

The selected certificate records `AUDIT FAILED`, with 26 of 150 prompts leaked. It is expected and intended that signature validity, ledger-binding validity, and authoritative SDL trust can all be established for a failed audit: verification establishes what the certificate is and which archived ledger it names, not that the run satisfied its audit pass criterion.

These results do not prove policy correctness, run-accounting correctness, model safety, deployment completeness, or organizational trust beyond the approved signing-key provenance.

For certificates earlier than SIR 2.3.4, signature-only verification is the only available form because those certificates do not bind an identity-matched ledger hash and row count. That is a historical compatibility path, not the current verification default.

## Authoritative vs local trust posture

- Public Pages and published GitHub artefacts distribute shared evidence for public evaluation; authoritative trust is a separately recorded verification result, and claim-level evidence comes from the selected per-run bundle.
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
