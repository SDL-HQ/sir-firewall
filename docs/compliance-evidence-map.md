# SIR B9 Evidence Packaging Map

This document defines a narrow technical/compliance review convenience path.

It maps existing SIR artifacts to reviewer checks and defines a local packaging helper that copies those same artifacts into one folder.

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

## Canonical evidence map (artifact -> reviewer question)

1. Product boundary and claim limits
   - `README.md`
   - `docs/assurance-kit.md`
   - `docs/evaluator-technical-explainer.md`
   - reviewer question: are boundaries and non-claims explicit and consistent?

2. Retention and durability boundaries
   - `RETENTION.md`
   - reviewer question: what is retained now, what is public vs local, and what is future-only hardening?

3. External technical review scope
   - `docs/external-technical-review-prep.md`
   - reviewer question: is review scope bounded to technical verification rather than certification?

4. Benchmark contract and interpretation discipline
   - `docs/benchmark-cycle.v1.md`
   - `docs/d5-benchmark-first-cycle-review.md`
   - reviewer question: are benchmark rows attributable, comparable, and free from score/ranking semantics?

5. Latest pass pointer and latest run pointer (distinct surfaces)
   - `proofs/latest-audit.json`
   - `proofs/latest-audit.html`
   - `docs/latest-run.json`
   - reviewer question: are latest-pass and latest-run semantics explicitly separate?

6. Run history and per-run archive completeness
   - `proofs/runs/index.json`
   - `proofs/runs/index.html`
   - optional specific run folder: `proofs/runs/<run_id>/`
   - reviewer question: can per-run evidence be inspected and verified with manifest/receipt/audit files?

7. Verification contracts and offline verification tools
   - `spec/evidence_contract.v1.json`
   - `tools/verify_certificate.py`
   - `tools/verify_archive_receipt.py`
   - `tools/verify_itgl.py`
   - reviewer question: can integrity checks be reproduced offline from repository artifacts?

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

Treat the bundle as a transport copy of existing evidence.

Authoritative interpretation remains anchored to the original canonical files and verification procedures already documented in this repository.
