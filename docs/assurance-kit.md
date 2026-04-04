# SIR Assurance Kit

This document is the canonical evaluation and verification path for SIR.

It is for operators, auditors, buyers, and reviewers who need a compact, evidence-first way to understand what SIR does and verify outputs without repo archaeology.

## Scope

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

## What SIR does not prove

SIR does not prove model alignment, broad model safety, or organizational compliance by itself.

SIR does not produce a benchmark score or ranking.

SIR provides deterministic enforcement evidence for a specific policy, pack, and run context. Claims outside that boundary require separate evidence.

## Evidence surfaces

Public surfaces and semantics:

- `latest-audit.json` / `latest-audit.html`: latest passing audit proof (last known good)
- `latest-run.json`: most recent run outcome, including FAIL or INCONCLUSIVE
- `runs/index.html`: archive index for pass and fail runs
- `runs/<run_id>/...`: per-run evidence bundle (manifest, audit, receipt, copied artefacts)
- `runs/benchmark_index.v1.json`: evidence map for side-by-side comparison only, with `latest_run` and `latest_passing_run`

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

Path B. Verify a local certificate if one has already been generated separately:

```bash
sir verify cert proofs/latest-audit.json
```

Note: certificate generation is a separate step and is not automatic from `sir run`.

### 5) Verify archived run receipt offline

If you have a run archive directory with `archive_receipt.json`:

```bash
sir verify archive proofs/runs/<run_id>/
```

Note: archive publication is a separate step (for example via `tools/publish_run.py`) and requires signing key material.

### 6) Interpret benchmark index honestly

Read `proofs/runs/benchmark_index.v1.json` as an evidence index:

- use `latest_run` for most recent execution status
- use `latest_passing_run` for most recent pass
- use `entries[*].comparison` for raw observed metadata only
- do not treat it as a score or ranking

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
- Archive includes both passes and failures.
- Benchmark index comparison fields are observed metadata, not weighted metrics.
- Evidence contract semantics remain the source of truth for certificate structure.
