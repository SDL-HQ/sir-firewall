# S4.3 Minimal Pilot Runbook

This runbook defines one minimal, repeatable pilot/evaluation path.

Use it when a reviewer/operator needs a linear procedure without extra interpretation layers.

## Scope and truth posture

- This runbook is procedural guidance over existing SIR evidence surfaces.
- It does not create a new proof artifact, status surface, or assurance layer.
- Source-of-truth surfaces in this flow are:
  - `proofs/latest-audit.json` (latest passing proof)
  - `docs/latest-run.json` (most recent run/publication status)
  - `proofs/run_summary.json`, `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt` (local run evidence)
  - `proofs/runs/<run_id>/archive_receipt.json` + `manifest.json` (archived run evidence)
- Supporting context only: evaluator/assurance/engineer docs.

Semantics to keep explicit during review:

- Gate outcome is `PASS` / `BLOCK`.
- Run/publication status is `PASS` / `FAIL` / `INCONCLUSIVE`.
- `latest-audit.*` (latest passing proof) and `latest-run.json` (most recent run status) are intentionally different surfaces.

## Prerequisites

1. Python 3.11+ is available.
2. Repository is checked out locally.
3. SIR CLI is available:

```bash
python3 -m pip install -e .
```

## Minimal pilot flow (single path)

### 1) Verify latest passing proof offline first

Action/command:

```bash
python3 tools/verify_certificate.py proofs/latest-audit.json
```

Artifact to inspect:

- `proofs/latest-audit.json`
- verifier terminal output

What to look for:

- Signature verification succeeds against resolved key material.
- Payload hash verification succeeds.
- Treat this as cryptographic integrity proof only.

### 2) Check most recent run/publication status

Action/command:

```bash
python3 -m json.tool docs/latest-run.json
```

Artifact to inspect:

- `docs/latest-run.json`

What to look for:

- Most recent run status (`PASS` / `FAIL` / `INCONCLUSIVE`).
- Keep this separate from Step 1 latest-pass proof semantics.

### 3) Execute one local deterministic audit run

Action/command:

```bash
sir run --mode audit --pack generic_safety
```

Artifact to inspect:

- `proofs/run_summary.json`

What to look for:

- Run completed and summary was written.
- `proof_class` is audit class (`FIREWALL_ONLY_AUDIT`).
- Gate behavior is explicit in run evidence (`PASS`/`BLOCK` at request level).

### 4) Verify local run integrity chain

Action/command:

```bash
python3 tools/verify_itgl.py
```

Artifact to inspect:

- `proofs/itgl_ledger.jsonl`
- `proofs/itgl_final_hash.txt`
- verifier terminal output

What to look for:

- ITGL verification passes for the current ledger/final hash pair.
- Ledger and final hash are present and internally consistent.

### 5) Verify one archived run receipt

Action/command:

```bash
RUN_DIR="$(ls -dt proofs/runs/*/ | head -n 1)"
sir verify archive "$RUN_DIR"
```

Artifact to inspect:

- `proofs/runs/<run_id>/archive_receipt.json`
- `proofs/runs/<run_id>/manifest.json`
- archive verification terminal output

What to look for:

- Archive receipt signature/integrity verification succeeds.
- Manifest-linked archive evidence is readable for that run.

## Tiny troubleshooting note

If `sir` is not found, reinstall editable package in the current environment:

```bash
python3 -m pip install -e .
```
