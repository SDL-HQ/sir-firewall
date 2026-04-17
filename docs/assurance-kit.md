# SIR Assurance Kit

For evaluator review order, start with `docs/evaluator-technical-explainer.md` (primary evaluator entry point). This document is a compact supporting walkthrough.

For the linear S4.3 pilot procedure (one minimal path), use `docs/minimal-pilot-runbook.md`.

It is for operators, auditors, buyers, and reviewers who need a compact, evidence-first way to understand what SIR does and verify outputs without repo archaeology.

Terminology: this document uses **governance gate** for public/operator description. Canonical technical identifiers (for example `sir-firewall`, `sir_firewall`, proof class names, commands, URLs, and paths) remain unchanged. See `docs/terminology.md`.

## Scope

This assurance kit points to the locked first benchmark cycle contract in `docs/benchmark-cycle.v1.md`.

This assurance kit explains:

- what SIR does
- what artefacts SIR produces
- what each proof class means
- one canonical evaluation path
- how to verify evidence offline
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
- structured envelope handling around that request path
- pack/scenario evaluation against that path
- proof and archive generation around gate behavior

## What SIR does not prove

SIR does not prove model alignment, broad model safety, or organizational compliance by itself.

SIR does not produce a benchmark score or ranking.

SIR provides deterministic enforcement evidence for a specific policy, pack, and run context. Claims outside that boundary require separate evidence.

SIR currently does **not** provide:

- native multimodal gating
- deep stateful conversational governance across long-running sessions
- native tool/function-call governance across external action graphs
- full structured enterprise action-graph governance
- internal model reasoning visibility
- post-inference model behavior governance
- full deployment-surface coverage

## Failure modes and residual risk (canonical)

Plain-language outcomes:

- If SIR blocks: the request path is stopped before model inference for that evaluated request.
- If inputs are malformed: treat the outcome as non-passing and use run artefacts to inspect the failure state.
- If registry or policy load paths fail: SIR returns an explicit non-passing blocked systemic-reset outcome with run evidence.
- If a run is invalid or inconclusive: treat it as non-passing; use `latest-run.json` plus archived run artefacts to inspect failure state.
- If SIR is bypassed: no governance claim applies to bypassed model-facing traffic.
- If SIR is not actually in front of the model path: proof only attests to the exercised SIR path, not ungoverned alternate paths.

Evidence durability under failure:

- Failure/inconclusive runs are still represented in run-level evidence surfaces (`latest-run.json` and run archive entries).
- Latest passing pointer (`latest-audit.*`) remains intentionally separate from latest run truth.

Residual risk boundary:

- Risk remains for any path, modality, tool/action chain, or post-inference behavior outside the exercised SIR request path.
- SIR evidence proves deterministic gate behavior for the evaluated boundary; it does not prove global system safety.

## Evidence surfaces

Public surfaces and semantics:

- `latest-audit.json` / `latest-audit.html`: latest passing audit proof (last known good)
- `latest-run.json`: most recent run outcome, including FAIL or INCONCLUSIVE
- `runs/index.html`: archive index for pass and fail runs
- `runs/<run_id>/...`: per-run evidence bundle (manifest, audit, receipt, copied artefacts)
- `runs/benchmark_index.v1.json`: evidence map for side-by-side comparison only, with `latest_run` and `latest_passing_run`
- Acceptance-oriented audit surfaces are `latest-audit.*`, `latest-run.json`, and run archives; benchmark rows remain exploratory comparison evidence.

## Canonical benchmark cycle contract (v1)

The first disciplined benchmark cycle is locked in `docs/benchmark-cycle.v1.md`.

Required cycle set:

- `generic_safety` (`FIREWALL_ONLY_AUDIT`)
- `account_recovery_fraud` (`FIREWALL_ONLY_AUDIT`)
- `scenario_injection_chain` (`SCENARIO_AUDIT`)
- `generic_safety` (`LIVE_GATING_CHECK` live sentinel)

Interpretation constraints:

- compare only within identical attribution dimensions (`row_identity`)
- keep domain-pack and scenario-pack evidence rows separate
- treat missing provider/model on live rows as non-comparable
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

This run updates local run artefacts (for example `proofs/run_summary.json`, `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`).

### 3) Inspect run artefacts

Review:

- `proofs/run_summary.json`
- `proofs/itgl_ledger.jsonl`
- `proofs/itgl_final_hash.txt`

Optional integrity check:

```bash
python3 tools/verify_itgl.py
```

### 4) Verify certificate offline

Use one of the two truthful paths below.

Path A. Verify published SDL-signed certificate:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Path B. Verify an SDL/public certificate from local disk using default trust anchors:

```bash
sir verify cert proofs/latest-audit.json
```

Path C. Verify a local/non-authoritative certificate using its matching public key:

```bash
sir verify cert proofs/latest-audit.json --key <pubkey.pem>
```

Note: certificate generation is a separate step and is not automatic from `sir run`. Local/non-authoritative certificates may not validate against default trust anchors unless `--key` (or a matching key registry) is provided.
Local generation aims to preserve attribution fields (for example `sir_firewall_version` and `commit_sha`) where possible, while leaving CI-only fields (for example `ci_run_url`) explicitly local/empty when CI context is absent.
Certificate verification proves payload integrity + signature validity against resolved public key material only. It does not prove policy correctness, model safety, or broader trust guarantees.

### 5) Verify archived run receipt offline

If you have a run archive directory with `archive_receipt.json`:

```bash
sir verify archive proofs/runs/<run_id>/
```

Note: archive publication is a separate step (for example via `tools/publish_run.py`) and requires signing key material.
If a local/dev archive was signed with an ephemeral key and its `signing_key_id` does not resolve in the default key registry, pass an explicit matching public key (`--key` / `--pubkey`) for local signature verification. This verifies signature integrity but does not upgrade the proof to SDL/public-authoritative trust semantics.

### 6) Interpret benchmark index honestly

Read `proofs/runs/benchmark_index.v1.json` as an evidence index:

- use `latest_run` for most recent execution status
- use `latest_passing_run` for most recent pass
- treat each row as one attributable comparison record: SIR version, commit SHA, explicit evaluation target (`domain_pack` or `scenario_pack`), proof class, provider/model, result, leaks/harmless-blocked, and evidence links
- use `entries[*].comparison` for raw observed metadata only
- do not treat it as a score or ranking, and do not infer an overall “best model”

## Compact reference table

| Surface | What it answers | Verify with |
| --- | --- | --- |
| `proofs/run_summary.json` | What happened in this local run | direct file inspection |
| `proofs/itgl_ledger.jsonl` + `proofs/itgl_final_hash.txt` | Integrity chain for run log | `python3 tools/verify_itgl.py` |
| `proofs/latest-audit.json` | Signed certificate payload | `sir verify cert ...` or `python3 tools/verify_certificate.py ...` |
| `proofs/runs/<run_id>/archive_receipt.json` | Run archive chain-of-custody receipt | `sir verify archive proofs/runs/<run_id>/` |
| `proofs/runs/benchmark_index.v1.json` | Honest map of runs and pointers | schema + direct inspection |

## Key governance readiness reference

For key authority boundaries, trust-source semantics, and the `CRYPTO_ENFORCED` readiness checklist, see `docs/key-governance-readiness.md`.

## Semantics to preserve

- Latest pass and latest run are intentionally different concepts.
- Gate outcome (`PASS`/`BLOCK`) is distinct from run/publication status (`PASS`/`FAIL`/`INCONCLUSIVE`).
- Archive includes both passes and failures.
- Benchmark index comparison fields are observed metadata, not weighted metrics.
- Evidence contract semantics remain the source of truth for certificate structure.
