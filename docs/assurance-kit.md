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

Acquisition is separate: choose and retrieve one bundle from `docs/runs/` while online. After it is locally available, verification needs no network.

One command, one run directory:

```bash
python3 tools/verify_evidence.py docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01
```

It resolves the certificate, ledger, manifest and receipt itself, runs every check that applies to them, and reports each property separately. There is no flag to remember. Resolution of the signing key through the approved registry is the default, not something you ask for.

Actual output:

```text
docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01

  OK      signing trust      signing_key_id='default' resolved through key_registry.v1.json, with its status and revocation rules applied
  OK      certificate        signature, payload hash and ledger binding all verify
  UNKNOWN signed counters    this ledger predates the fields needed to recompute the signed counters, so they were not checked against it; this is not agreement
  OK      archive custody    every file named by the signed manifest is present and unchanged
  OK      evidence contract  the certificate satisfies its applicable evidence contract

VERDICT: NOT ESTABLISHED
Nothing failed. One or more properties could not be established, and an unestablished property is not a passing one.
```

Exit codes: `0` established, `1` not established, `2` failed, `3` the run directory could not be read.

#### Read the properties, not only the verdict

**UNKNOWN is not a failure, and it is not a pass.** It means a check could not be performed, so the property it would have established is not established. The verdict is the worst state present, so one unknown beside four passes is `NOT ESTABLISHED`. That is the honest summary and it is deliberate: a property nobody checked is not a property that holds.

Two unknowns are expected on archives published before SIR 2.4.0 and are not defects in your copy.

**`signed counters`** is unknown for every certificate published before SIR 2.4.0. Until then the published counters were asserted beside the ledger rather than derived from it, and those ledgers do not carry the per-row fields a verifier needs to recompute them. The signed numbers may well be right; nothing in the archive lets you confirm it. `counters_checked_against_ledger: false` on a certificate says exactly this, and must not be read as agreement.

**`evidence contract`** is unknown for **219 of the 292 certificates published before SIR 2.4.0**. The evidence contracts begin at version 2.2.0 and 219 archives predate it, including 176 at 1.0.2, 40 at 2.0.0, and 3 carrying no version field. Those archives are not invalid: signature, ledger binding and archive custody all verify. No contract governs their structure, which is neither a pass nor a violation, and the tool says so rather than printing a clean result.

#### What a passing result means, and what it does not

A result of `ESTABLISHED` says: the certificate's signature verifies against a key resolved through the approved registry with that entry's status and revocation rules applied; the ledger it binds is the ledger in this directory and its terminal hash and row count match what was signed; the signed counters were recomputed from that ledger's rows and agree; every file named by the signed manifest is present and unchanged; and the certificate satisfies the evidence contract applicable to its version.

It does not say the run met its audit pass criterion. Those are different questions, and an archive whose `result` is `AUDIT FAILED` can be fully established evidence of a failed run. Verification establishes integrity, binding and signing trust; it does not endorse the outcome.

It also does not constrain anybody holding the signing key, who can mint a consistent archive from scratch. What these checks establish is that the archive you hold is the archive that was signed.

#### Running the individual tools

The underlying tools remain available and each answers one question. They are what the consolidated command runs:

```bash
RUN_ID=20260921-135018-029319-gh35607761858-f3dd66376a01
python3 tools/verify_certificate.py "docs/runs/$RUN_ID/audit.json" --ledger "docs/runs/$RUN_ID/proofs/itgl_ledger.jsonl" --require-registry
python3 tools/verify_archive_receipt.py "docs/runs/$RUN_ID" --require-registry
python3 tools/validate_certificate_contract.py "docs/runs/$RUN_ID/audit.json"
```

The first of those prints:

```text
OK: payload_hash and signature verify against key registry spec/pubkeys/key_registry.v1.json entry signing_key_id=default; ledger binding verifies signed itgl_final_hash=sha256:ae9233eec1ae44d9ca20661bc5f460979fd487d1498f79583413037e5200d7ba equals the ledger terminal hash from docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01/proofs/itgl_ledger.jsonl, and signed itgl_row_count=150 equals prompts_tested=150.
```

Reach for these to investigate a specific failure. For reaching a verdict, prefer the consolidated command: it passes explicit paths rather than letting the certificate verifier discover a ledger, which can resolve to a copy elsewhere on disk, and it reports signing trust as a property of its own rather than leaving it to be inferred from which flags were typed.

#### Incomplete bundles

The archive receipt check validates every file named by `manifest.json`, so it requires the complete run directory. A `file listed in manifest is missing` error can mean the downloaded bundle is incomplete. It can also mean the archive was published incomplete: 99 archives published between April and September 2026 name `leaks_count.txt` and `harmless_blocked.txt` in their signed manifests, and a repository-wide ignore rule meant those two files were never committed. `docs/archive-errata.md` lists every affected run. Archives published from SIR 2.3.7 onward are checked against their signed manifest before the publishing commit, so this error should now only indicate an incomplete download.

A run directory with no `archive_receipt.json` or no `manifest.json` reports `archive custody` as unknown rather than as a pass or a failure. Early archives were published without receipts.

Custody of the signing key, including what can sign with it and which properties are conventions rather than enforced controls, is documented in [`key-custody.md`](key-custody.md).

#### Certificates that predate a field

Two fields the consolidated command reports on postdate parts of the archive, and a certificate from before a field existed never carried one.

`itgl_row_count` arrived in SIR 2.3.4. For a certificate claiming an earlier version, the terminal hash binding is still verified, the row count is not compared, and `certificate` is reported as unknown rather than as a failure. A certificate claiming 2.3.4 or later with the field absent is a different matter and is reported as a binding failure, because the field should be there.

The evidence contracts begin at SIR 2.2.0, and contract v4 at 2.4.0. A certificate below 2.2.0 is governed by no contract, which the command reports as unknown. See the 219 figure above.

For pre-2.3.4 certificates, signature verification plus terminal hash binding is the strongest available form. Treat it as a historical compatibility path, not the current default, and prefer a run archive from SIR 2.3.4 or later when choosing a bundle to examine.

#### Certificates that name no signing key

43 of the 292 published certificates carry no `signing_key_id`, because the field postdates them. They are resolved as `key_id=default` through the approved registry, which is what the field's absence always meant, and that entry's status and revocation rules apply to them exactly as to the 249 that name it. Between the key rotation of 6 October 2026 and 8 October 2026 these 43 reported a signature failure, because the verifier fell through to `spec/sdl.pub`, which by then held the rotated key. The archives were unaffected; the verifier had no rule for them.

#### Mutable pointers are not claim-level evidence

The root-level `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`, `proofs/run_id.txt`, and `proofs/run_summary.json` are mutable compatibility copies. Inspecting or verifying them may help with current local execution, but it does not establish anything about a selected archived certificate. Files with the same basenames beneath `docs/runs/<run_id>/proofs/` or `proofs/runs/<run_id>/proofs/` are different, immutable per-run archive members covered by that run's manifest and receipt. Point the consolidated command at a run directory and this distinction takes care of itself.

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
| `docs/runs/<run_id>/` | Every property of one archived run, each reported separately | `tools/verify_evidence.py docs/runs/<run_id>` |
| `docs/runs/<run_id>/audit.json` + that run's ledger | Whether signature and certificate-to-ledger binding validate | `tools/verify_certificate.py ... --ledger ... --require-registry` |
| `docs/runs/<run_id>/archive_receipt.json` | Run archive chain-of-custody receipt | `tools/verify_archive_receipt.py ... --require-registry` |
| `docs/runs/<run_id>/audit.json` | Whether the certificate satisfies its version-applicable evidence contract | `tools/validate_certificate_contract.py ...` |
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
