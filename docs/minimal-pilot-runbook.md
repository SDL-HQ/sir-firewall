# S4.3 Minimal Pilot Runbook

This runbook defines one minimal, repeatable pilot/evaluation path.

Use it when a reviewer/operator needs a linear procedure without extra interpretation layers. Follow the single review order: `README.md`, then `docs/evaluator-technical-explainer.md`, then this worked verification guide.

## Scope and truth posture

- This runbook is procedural guidance over existing SIR evidence surfaces.
- It does not create a new proof artifact, status surface, or assurance layer.
- Evidence surfaces in this flow are:
  - `proofs/latest-audit.json` and `docs/latest-audit.json` (mutable latest-passing pointers)
  - `docs/latest-live-audit.json` (mutable latest-qualifying-live-audit pointer)
  - `docs/latest-run.json` (current most-recent-run status pointer)
  - `docs/runs/<run_id>/` (selected claim-level bundle containing the certificate, identity-matched ledger, manifest, and archive receipt)
  - root-level `proofs/run_summary.json`, `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`, and `proofs/run_id.txt` (mutable compatibility copies for local tooling, not evidence for a particular archived claim); same-named files inside `docs/runs/<run_id>/proofs/` or `proofs/runs/<run_id>/proofs/` are distinct, immutable members of that run's archived bundle
- Supporting context only: evaluator/assurance/engineer docs.

Semantics to keep explicit during review:

- Gate request status is `PASS` / `BLOCKED`.
- Run/publication status is `PASS` / `FAIL` / `INCONCLUSIVE`.
- `latest-audit.*` (latest passing pointer) and `latest-run.json` (current run-status pointer) are intentionally different mutable surfaces.
- Pair view (`docs/runs/index.html` paired table) is a deterministic comparison projection over archived run evidence.
- The selected per-run bundle (`docs/runs/<run_id>/...`, mirrored from `proofs/runs/<run_id>/...`) is the claim-level source.

SIR validates bounded structured request and tool-result inputs at the request boundary; it does not govern tool execution, multi-step action graphs, or post-inference behaviour.

## Prerequisites

The `sir` console command requires an editable installation of a complete repository checkout. See the installation support boundary in `README.md` before installing or moving a checkout.

1. Python 3.11+ is available.
2. Repository is checked out locally.
3. SIR CLI is available:

```bash
python3 -m pip install -e .
```

## Locally available evidence and network requirements

Acquisition and verification are separate. Cloning the repository or retrieving an archive bundle requires network access. Once a complete checkout, dependencies, and a selected bundle are locally available, the verification commands in the worked flow require no network.

### Offline-capable commands (when run from a local checkout)

- Audit run (deterministic gate, no provider calls):

```bash
sir run --mode audit --pack generic_safety
```

- Archived-run verification is shown as one certificate-plus-ledger check and one receipt check in Step 1. Do not select the newest directory implicitly and do not combine a certificate from one surface with a root compatibility ledger.

### Network requirement by step

- `sir run --mode audit --pack ...`: does not require network for runtime evaluation.
- `tools/verify_certificate.py` against a local certificate and that run's local ledger: does not require network.
- `tools/verify_archive_receipt.py` against the same local run directory: does not require network.
- Any command that fetches remote artefacts (for example `curl` from GitHub) requires network.
- Initial dependency installation may require network depending on local environment state.

### Local/dev key verification boundary

- Local or dev certificates and archive receipts may be signed by non-authoritative keys.
- Verification against an explicitly supplied matching local/dev public key can establish signature validity, but it does not establish authoritative SDL trust.
- Where authoritative trust is claimed, use `--require-registry` as in Step 1 so an unreadable or missing registry cannot fall back to a default public key.

### What verification proves and does not prove

- Record signature validity, ledger-binding validity, and authoritative SDL trust as three distinct results.
- Verification does not prove policy correctness, model safety, deployment completeness, or broader organizational trust posture.

## Minimal pilot flow (single path)

For manual GitHub Actions dispatch (`SIR Real Governance Audit`), use these exact workflow inputs:

- `operation`: `run` = single run, `benchmark` = paired ungated vs gated
- `mode`: `audit` = deterministic/no provider calls, `live` = provider-call path
- `pack`: one of the workflow-allowlisted IDs: `generic_safety`, `support_operator_override`, `data_exfiltration_pressure`, or `eu_ai_act_compliance_pressure`. Workflow selection is validated fail-closed before execution.
- `provider`: provider id (`xai` or `openai`)
- `model`: exact model id for selected provider (for example `grok-4.3`)

Local `sir run --pack` has a wider pack-selection surface than workflow dispatch and resolves `<pack_id>` against `spec/packs/pack_registry.v1.json`.

For local CLI operation, use:

- audit run: `sir run --mode audit --pack <pack_id>`
- benchmark pair run: `sir benchmark run --mode audit|live --pack <pack_id> --provider <provider> --model <model> [--pair-key <key>]`

### 1) Verify one locally available archived run

Action/command:

Select one bundle from the run archive rather than from a mutable latest pointer. The worked example is a SIR 2.3.4 bundle, and every path below remains inside that same run directory.

The receipt verifier validates every file listed in the run's `manifest.json`, so download the complete directory rather than only `audit.json` and the ledger. For this example the five manifest-listed files are `audit.json`, `proofs/itgl_final_hash.txt`, `proofs/itgl_ledger.jsonl`, `proofs/latest-attempts.log`, and `proofs/run_summary.json`. If verification reports `file listed in manifest is missing`, the local bundle is incomplete; that message alone does not mean the archived evidence is broken.

```bash
RUN_ID=20260921-135018-029319-gh35607761858-f3dd66376a01
python3 tools/verify_certificate.py "docs/runs/$RUN_ID/audit.json" --ledger "docs/runs/$RUN_ID/proofs/itgl_ledger.jsonl" --require-registry
python3 tools/verify_archive_receipt.py "docs/runs/$RUN_ID" --require-registry
```

Actual output:

```text
OK: payload_hash and signature verify against key registry spec/pubkeys/key_registry.v1.json entry signing_key_id=default; ledger binding verifies signed itgl_final_hash=sha256:ae9233eec1ae44d9ca20661bc5f460979fd487d1498f79583413037e5200d7ba equals the supplied ledger terminal hash, and signed itgl_row_count=150 equals prompts_tested=150.
OK: archive receipt verified for docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01
```

Artifact to inspect:

- `docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01/audit.json`
- `docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01/proofs/itgl_ledger.jsonl`
- `docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01/archive_receipt.json`
- verifier terminal output

What to look for:

- **Signature valid:** the payload hash and certificate signature verify.
- **Ledger binding valid:** the signed terminal hash and row count match this same run's chain-valid ledger.
- **Authoritative SDL trust established:** this example resolves `signing_key_id=default` through approved registry `spec/pubkeys/key_registry.v1.json`, and `--require-registry` prevents fallback. If that resolution fails, report **authoritative SDL trust not established**, even if a local/dev signature is otherwise valid.

The certificate itself records `AUDIT FAILED`, with 26 of 150 prompts leaked. The three verification results passing alongside a failed audit result is expected: verification establishes the certificate's integrity, its binding to this run's ledger, and its signing trust; it does not assert that the run met the audit pass criterion.

For a certificate earlier than SIR 2.3.4, signature-only verification is the only available form. This is a historical compatibility path, not the current default.

### 2) Check most recent run/publication status

Action/command:

```bash
python3 -m json.tool docs/latest-run.json
```

Artifact to inspect:

- `docs/latest-run.json`

What to look for:

- Most recent run status (`PASS` / `FAIL` / `INCONCLUSIVE`).
- Use this pointer to learn current status or locate a candidate only; the selected per-run bundle remains the claim-level source.

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
- Gate behavior is explicit in run evidence (`PASS`/`BLOCKED` at request level).

### 4) Inspect mutable local compatibility state

Action/command:

```bash
python3 tools/verify_itgl.py
```

Artifact to inspect:

- `proofs/itgl_ledger.jsonl`
- `proofs/itgl_final_hash.txt`
- verifier terminal output

What to look for:

- ITGL verification passes for the current mutable ledger/final hash pair.
- This local diagnostic does not establish that any archived certificate names that ledger. Only Step 1 verifies certificate-to-ledger binding for a selected run.

### 5) (Optional) Export local review bundle for handoff

Action/command:

```bash
python3 tools/export_review_bundle.py --out /tmp/sir-review-bundle
```

Artifact to inspect:

- `/tmp/sir-review-bundle/B9_BUNDLE_MANIFEST.txt`

What to look for:

- Export completes with explicit destination path.
- Output directory is a directory path and either empty or `--force` is used.

## Operator/reviewer quick checklist

- Run an audit with `sir run --mode audit --pack <pack_id>` (single-run evidence path).
- Run a benchmark pair with `sir benchmark run ...` only when you need ungated-vs-gated deltas.
- Verify one selected 2.3.4-or-later archive certificate with its own ledger and receipt; record signature validity, ledger-binding validity, and authoritative SDL trust separately.
- Read `docs/latest-run.json` as the current run-status pointer, not as claim-level evidence.
- Read pair rows in `docs/runs/index.html` as interpretation aid; confirm claims from raw run archives.

## Tiny troubleshooting note

If `sir` is not found, reinstall editable package in the current environment:

```bash
python3 -m pip install -e .
```
