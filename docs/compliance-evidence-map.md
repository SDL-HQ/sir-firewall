# SIR B9 Evidence Packaging Map

This document defines a narrow technical/compliance review convenience path.

It maps existing SIR artifacts to reviewer checks and defines a local packaging helper that copies those same artifacts into one folder.

Evaluator entry point: start with `docs/evaluator-technical-explainer.md` for primary review and verification order, then use this map as supporting inventory context.

This package is a **review package** only. It is not a new proof artifact or assurance layer.

## Scope and non-claims

This package is a convenience export of existing repository artifacts.

It does **not**:

- create new proof material
- create new run results
- create a new public trust surface
- certify compliance
- imply certification, approval, or regulatory status

SIR semantics remain unchanged:

- Gate outcome: `PASS` / `BLOCK`
- Run/publication status: `PASS` / `FAIL` / `INCONCLUSIVE`

## Review order (repeatable)

Read in this order to minimize confusion:

1. Scope and claim boundaries.
2. Latest-pass vs latest-run status surfaces.
3. Run history and per-run archive evidence.
4. Benchmark interpretation discipline.
5. Offline verification contracts and tools.
6. Packaging/export helper behavior.

## Bundle inventory with artifact role and review question

The entries below classify each included artifact as:

- **Source of truth**: authoritative evidence/contract surface.
- **Supporting context**: explanatory or operational context for reading source-of-truth artifacts.

| Artifact | Role | Reviewer question |
| --- | --- | --- |
| `README.md` | Supporting context | Is the top-level product boundary consistent with evaluator docs? |
| `docs/assurance-kit.md` | Supporting context | Is the canonical evaluation/verification path clear and bounded? |
| `docs/evaluator-technical-explainer.md` | Supporting context | Are in-scope claims and out-of-scope claims explicit and consistent? |
| `RETENTION.md` | Supporting context | Are retention boundaries and durability expectations explicit? |
| `docs/external-technical-review-prep.md` | Supporting context | Is external review framed as technical verification, not certification? |
| `docs/benchmark-cycle.v1.md` | Source of truth | Is benchmark-cycle interpretation contract explicit and score-free? |
| `docs/d5-benchmark-first-cycle-review.md` | Supporting context | Does benchmark review narrative stay within contract semantics? |
| `proofs/latest-audit.json` | Source of truth | What is the latest passing proof payload (last known good)? |
| `proofs/latest-audit.html` | Supporting context | Is there a human-readable rendering of the latest passing proof? |
| `docs/latest-run.json` | Source of truth | What is the most recent run status (`PASS`/`FAIL`/`INCONCLUSIVE`)? |
| `proofs/runs/index.json` | Source of truth | Are run archive entries present for pass and non-pass runs? |
| `proofs/runs/index.html` | Supporting context | Is there a human-readable run index view matching `index.json`? |
| `proofs/runs/<run_id>/` (optional via `--run-id`) | Source of truth | Can a specific run be inspected via `manifest.json`, `audit.json`, and `archive_receipt.json`? |
| `spec/evidence_contract.v1.json` | Source of truth | Do certificate structures align with the declared evidence contract? |
| `tools/verify_certificate.py` | Supporting context | Can certificate signature/integrity checks be reproduced offline? |
| `tools/verify_archive_receipt.py` | Supporting context | Can archive receipt/manifest integrity checks be reproduced offline? |
| `tools/verify_itgl.py` | Supporting context | Can ITGL chain integrity checks be reproduced offline? |

## Local packaging helper (B9)

Use `tools/export_review_bundle.py` to copy the mapped artifacts into a local review folder.

Properties:

- deterministic: explicit source path list only
- bounded: no smart discovery, scoring, or aggregation
- convenience only: copied artifacts retain original relative paths

Example:

```bash
python3 tools/export_review_bundle.py --out /tmp/sir-review-bundle
python3 tools/export_review_bundle.py --out /tmp/sir-review-bundle --run-id 20260416-003923-000000-ef03803fc756 --force
```

If `--run-id` is provided, the exporter copies `proofs/runs/<run_id>/` exactly as-is.

## Reviewer guidance

Treat the bundle as a transport copy of existing evidence for reviewer convenience.

Do not treat the bundle itself as:

- a new proof artifact
- a new assurance layer
- a replacement for original source-of-truth artifacts and their documented verification procedures

Authoritative interpretation remains anchored to the original canonical files and verification procedures already documented in this repository.
