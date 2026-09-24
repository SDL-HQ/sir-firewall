# SIR Assurance Kit

The single review order is `README.md`, then `docs/evaluator-technical-explainer.md`, then the worked verification procedure in `docs/minimal-pilot-runbook.md`. This document is a compact supporting reference, not another entry point.

For the linear S4.3 pilot procedure (one minimal path), use `docs/minimal-pilot-runbook.md`.
For acquisition and locally available verification steps, see `docs/minimal-pilot-runbook.md#locally-available-evidence-and-network-requirements`.

It is for operators, auditors, buyers, and reviewers who need a compact, evidence-first way to understand what SIR does and verify outputs without repo archaeology.

Terminology: this document uses **governance gate** for public/operator description. Canonical technical identifiers (for example `sir-firewall`, `sir_firewall`, proof class names, commands, URLs, and paths) remain unchanged. See `docs/terminology.md`.

## Scope

This assurance kit points to the locked first benchmark cycle contract in `docs/benchmark-cycle.v1.md`.

This assurance kit explains:

- what SIR does
- what artefacts SIR produces
- what each proof class means
- one canonical evaluation path
- how to verify a locally available evidence bundle without network access
- how to interpret latest pass, latest run, run archive, and benchmark index
- how authoritative and non-authoritative signing trust is scoped
- what must be true before `CRYPTO_ENFORCED` can be enabled safely

## What SIR does

SIR is a deterministic pre-inference governance gate.

Given a policy and a test pack, it evaluates prompts before model inference and records evidence of what happened.

Core outputs are evidence artefacts such as run summaries, ITGL ledger/hash, signed certificates, and signed run archive receipts.

Current capability boundary (explicit):

- text-first
- request-level
- deterministic pre-inference gating
- pack/scenario evaluation against that path
- proof and archive generation around gate behavior

SIR validates bounded structured request and tool-result inputs at the request boundary; it does not govern tool execution, multi-step action graphs, or post-inference behaviour.

## What SIR does not prove

SIR does not prove model alignment, broad model safety, or organizational compliance by itself.

SIR does not produce a benchmark score or ranking.

SIR provides deterministic enforcement evidence for a specific policy, pack, and run context. Claims outside that boundary require separate evidence.

SIR currently does **not** provide:

- native multimodal gating
- deep stateful conversational governance across long-running sessions
- internal model reasoning visibility
- full deployment-surface coverage

## Failure modes and residual risk (canonical)

Plain-language outcomes:

- If SIR blocks: the request path is stopped before model inference for that evaluated request.
- If inputs are malformed: treat the outcome as non-passing and use run artefacts to inspect the failure state.
- If the baseline policy or a domain ISC policy pack fails to load inside `validate_sir()`: SIR returns an explicit non-passing blocked systemic-reset outcome with run evidence.
- If `spec/packs/pack_registry.v1.json` is absent or malformed: suite selection fails with a process error before request evaluation; this is not a request-level systemic-reset block.
- If an otherwise-unhandled in-process validation exception occurs: SIR returns an internal-error systemic-reset block with exception diagnostics in the ITGL. A process-level out-of-memory kill cannot be caught in-process and remains outside this guarantee.
- If a run is invalid or inconclusive: treat it as non-passing; use the `latest-run.json` current status pointer to locate the run, then inspect its archived bundle.
- If SIR is bypassed: no governance claim applies to bypassed model-facing traffic.
- If SIR is not actually in front of the model path: proof only attests to the exercised SIR path, not ungoverned alternate paths.

Evidence durability under failure:

- Failure/inconclusive runs are represented by per-run archive bundles; `latest-run.json` is only the current status pointer.
- The mutable latest passing pointer (`latest-audit.*`) remains intentionally separate from the current-run pointer and is not an immutable claim-level record.

Residual risk boundary:

- Risk remains for any path or modality outside the exercised SIR request boundary.
- SIR evidence attests to the recorded deterministic gate decision for the evaluated boundary; that decision—not any model response—is reproducible given the same inputs and repository configuration at the recorded `commit_sha`, while signature verification establishes payload integrity and signature validity, not independent execution correctness or global system safety.

## Evidence surfaces

Public surfaces and semantics:

- `latest-audit.json` / `latest-audit.html`: mutable pointer to the latest passing audit proof (last known good)
- `latest-live-audit.json` / `latest-live-audit.html`: mutable pointer to the latest qualifying live audit
- `latest-run.json`: current status pointer for the most recent run, including FAIL or INCONCLUSIVE
- `runs/index.html`: archive index for pass and fail runs
- `runs/<run_id>/...`: per-run evidence bundle (manifest, audit, receipt, copied artefacts)
- `runs/benchmark_index.v2.json`: evidence map for side-by-side comparison only, with `latest_run`, `latest_passing_run`, and paired benchmark rows
- The selected per-run bundle is the claim-level evidence source. Latest pointers help locate candidates; benchmark rows remain exploratory comparison evidence.

## Canonical benchmark cycle contract (v1)

The first disciplined benchmark cycle is locked in `docs/benchmark-cycle.v1.md`.

Required cycle set:

- `generic_safety` (`FIREWALL_ONLY_AUDIT`)
- `support_operator_override` (`FIREWALL_ONLY_AUDIT`)
- `data_exfiltration_pressure` (`FIREWALL_ONLY_AUDIT`)

Interpretation constraints:

- compare only within identical attribution dimensions (`row_identity`)
- keep domain-pack and scenario-pack evidence rows separate when both are present in the benchmark index
- treat missing provider/model on rows that require provider/model dimensions as non-comparable
- keep benchmark index semantics as evidence mapping only (no scores/rankings)

## Proof classes

- `FIREWALL_ONLY_AUDIT`: deterministic gate evaluation without downstream model calls
- `LIVE_GATING_CHECK`: live mode where PASS prompts may call downstream provider
- `SCENARIO_AUDIT`: scenario-pack audit path

## Canonical evaluation path

Use this path in order.

### 1) Install

```bash
python3 -m pip install -e .
```

### 2) Run one canonical audit scenario

```bash
sir run --mode audit --pack generic_safety
```

This run updates local run artefacts including `proofs/run_summary.json` and `proofs/itgl_ledger.jsonl`.

### 3) Inspect run artefacts

Review:

- `proofs/run_summary.json`
- `proofs/itgl_ledger.jsonl`

`proofs/itgl_final_hash.txt` is produced by the separate ITGL verification step below, not by `sir run`.

Optional integrity check:

```bash
python3 tools/verify_itgl.py
```

After verification, review `proofs/itgl_final_hash.txt`.

### 4) Verify one archived run from local files

Acquisition is separate: choose and retrieve one bundle from `docs/runs/` while online. After it is locally available, verification needs no network. Use a run whose `audit.json` records `sir_firewall_version` 2.3.4 or later, and use its certificate, ledger, and receipt from the same directory rather than a mutable root or `latest-*` pointer.

The archive receipt check validates every file named by `manifest.json`, so it requires the complete run directory. This example's manifest lists five files: `audit.json`, `proofs/itgl_final_hash.txt`, `proofs/itgl_ledger.jsonl`, `proofs/latest-attempts.log`, and `proofs/run_summary.json`. A `file listed in manifest is missing` error means the downloaded bundle is incomplete; it does not by itself mean the archived evidence is broken.

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

Record three separate results: **signature valid**; **ledger binding valid**; and **authoritative SDL trust established** because this example resolves `signing_key_id=default` through the approved `spec/pubkeys/key_registry.v1.json` under `--require-registry`. If a local/dev key verifies but approved registry resolution does not, record **authoritative SDL trust not established**.

This worked certificate's result is `AUDIT FAILED`: 26 of 150 prompts leaked. All three verification results passing while the audit result is failed is expected and intentional. Verification establishes the certificate's integrity, binding, and signing trust; it does not change or endorse whether the run met its audit pass criterion.

For pre-2.3.4 certificates, signature-only verification is the only available form. Treat that as a historical compatibility path, not the current default.

The root-level `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`, `proofs/run_id.txt`, and `proofs/run_summary.json` are mutable compatibility copies. Inspecting or verifying them may help with current local execution, but it does not establish anything about a selected archived certificate. Files with the same basenames beneath `docs/runs/<run_id>/proofs/` or `proofs/runs/<run_id>/proofs/` are different, immutable per-run archive members covered by that run's manifest and receipt.

### 5) Interpret benchmark index honestly

Read `docs/runs/benchmark_index.v2.json` as an evidence index:

- use `latest_run` for most recent execution status
- use `latest_passing_run` for most recent pass
- treat each row as one attributable comparison record: SIR version, commit SHA, explicit evaluation target (`domain_pack` or `scenario_pack`), proof class, provider/model, result, leaks/harmless-blocked, and evidence links
- use `entries[*].comparison` for raw observed metadata only
- do not treat it as a score or ranking, and do not infer an overall “best model”

## Compact reference table

| Surface | What it answers | Verify with |
| --- | --- | --- |
| `docs/runs/<run_id>/audit.json` + that run's ledger | Whether signature and certificate-to-ledger binding validate | `tools/verify_certificate.py ... --ledger ... --require-registry` |
| `docs/runs/<run_id>/archive_receipt.json` | Run archive chain-of-custody receipt | `tools/verify_archive_receipt.py ... --require-registry` |
| Root `proofs/run_summary.json` and ITGL files | Mutable current-run compatibility state; not claim-level evidence | local diagnostics only |
| `docs/runs/benchmark_index.v2.json` | Honest map of runs, pointers, and pair rows | schema + direct inspection |

## Key governance readiness reference

For key authority boundaries, trust-source semantics, and the `CRYPTO_ENFORCED` readiness checklist, see `docs/key-governance-readiness.md`.

## Semantics to preserve

- Latest pass and latest run are intentionally different mutable pointers; a selected per-run bundle is the claim-level evidence source.
- Gate request status (`PASS`/`BLOCKED`) is distinct from run/publication status (`PASS`/`FAIL`/`INCONCLUSIVE`).
- Archive includes both passes and failures.
- Benchmark index comparison fields are observed metadata, not weighted metrics.
- Evidence contract semantics remain the source of truth for certificate structure.
