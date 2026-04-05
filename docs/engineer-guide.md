# SIR Engineer Guide

This guide is for running SIR locally, generating artefacts, and serving proof pages during development.

For the canonical evaluation and offline verification path, use `docs/assurance-kit.md`.

For the first disciplined benchmark-cycle contract (what to run, required artefacts, and comparability rules), use `docs/benchmark-cycle.v1.md`.

## Runtime requirements

- Python 3.11+
- Git

## Quickstart install paths (canonical)

```bash
# audit mode
python3 -m pip install -e .

# live mode
python3 -m pip install -e ".[live]"

# verify-only (published certificate, no local run)
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

## Local install (Mac/Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .
python3 --version
```

## Local install (Windows PowerShell)

Note: if you run LIVE mode on Windows and `pip install -e ".[live]"` fails due to long paths, run from a short path (e.g. `C:\sir\...`) or enable Windows long path support.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
python --version
```

## Packs and modes (what you can run)

SIR runs packs by `pack_id` from `spec/packs/pack_registry.v1.json`.

Current technical boundary for this guide:

* text-first, request-level deterministic pre-inference gating
* structured envelope handling around that request path
* pack/scenario evaluation for that path
* proof/archive artefact generation around gate behavior

Out of scope here: native multimodal gating, deep stateful conversation governance, native tool/function-call governance, and post-inference behavior governance.

Modes:

* `--mode audit` (default): deterministic gate only, no model calls (`proof_class = FIREWALL_ONLY_AUDIT`)
* `--mode live`: model calls for PASS prompts only (`proof_class = LIVE_GATING_CHECK`)
* Scenario packs use the same runner; pack schema determines behavior (`proof_class = SCENARIO_AUDIT` when applicable)

## Run an audit locally (no model calls)

```bash
sir run --mode audit --pack generic_safety
```

Outputs (local run artefacts):

* `proofs/latest-attempts.log`
* `proofs/run_summary.json`
* `proofs/itgl_ledger.jsonl`
* `proofs/itgl_final_hash.txt`
* `leaks_count.txt`
* `harmless_blocked.txt`

Verify ITGL:

```bash
python3 tools/verify_itgl.py
```

## Run a live gating check (PASS prompts call provider)

LIVE requires:

* installing live extras
* your own provider credentials (SIR does not ship keys)

Install live extras:

```bash
python3 -m pip install -e ".[live]"
```

Set provider credentials (example: xAI):

```bash
export XAI_API_KEY="paste_key_here"
```

Run live:

```bash
sir run --mode live --pack generic_safety
```

The run summary records:

* `provider_call_attempts` (attempted downstream calls, including retries/timeouts)
* `provider_call_successes` / `provider_call_failures`
* `proof_class = LIVE_GATING_CHECK`

## Generate a locally signed certificate (dev/test key)

Certificate generation and run-archive publishing require a signing key in `SDL_PRIVATE_KEY_PEM`.
This is for local/dev proofs. It is not an SDL-signed production proof.

Create a temporary dev key:

```bash
openssl genrsa -out /tmp/sir_dev_priv.pem 2048 >/dev/null 2>&1
export SDL_PRIVATE_KEY_PEM="$(cat /tmp/sir_dev_priv.pem)"
openssl rsa -in /tmp/sir_dev_priv.pem -pubout -out /tmp/sir_dev_pub.pem >/dev/null 2>&1
```

Generate certificate + validate + verify (using your dev pubkey):

```bash
python3 tools/generate_certificate.py
python3 tools/validate_certificate_contract.py proofs/latest-audit.json
python3 tools/verify_certificate.py proofs/latest-audit.json --pubkey /tmp/sir_dev_pub.pem
```

## Publish a local run archive (signed receipt)

Publishing a run archive creates:

* `proofs/runs/<run_id>/manifest.json`
* `proofs/runs/<run_id>/audit.json`
* `proofs/runs/<run_id>/archive_receipt.json` (signed)
* `proofs/runs/benchmark_index.v1.json` (machine-readable benchmark/index summary)

It requires `SDL_PRIVATE_KEY_PEM` to be set.

```bash
python3 tools/publish_run.py --cert proofs/latest-audit.json \
  --copy proofs/itgl_ledger.jsonl \
  --copy proofs/itgl_final_hash.txt \
  --copy proofs/latest-attempts.log \
  --copy proofs/run_summary.json \
  --copy leaks_count.txt \
  --copy harmless_blocked.txt
```

Verify the latest archived run (dev pubkey):

```bash
RUN_DIR="$(ls -dt proofs/runs/* | head -n 1)"
python3 tools/verify_archive_receipt.py "$RUN_DIR" --pubkey /tmp/sir_dev_pub.pem
```

Benchmark/index semantics:

* `proofs/runs/benchmark_index.v1.json` is an evidence map, not a score.
* It records attributable per-run comparison rows: `sir_firewall_version`, `commit_sha`, explicit `evaluation_target` (`domain_pack` or `scenario_pack` + pack identifiers), `proof_class`, `provider`, `model`, `result`, `leaks`, `harmless_blocked`, and evidence links.
* It includes both `latest_run` and `latest_passing_run` pointers so fail/pass truth stays explicit.
* `comparison` is raw run metadata for side-by-side reading only (counts, hashes, and provider call totals), not a ranking model.
* Rows are evidence-linked comparisons only. There is no ranking, no blended domain/scenario row meaning, and no “overall best model” logic.

## Canonical benchmark cycle v1 (D4)

Use `docs/benchmark-cycle.v1.md` for the locked first benchmark set and cycle validity criteria.

Short form of the required set:

* `generic_safety` as `FIREWALL_ONLY_AUDIT`
* `account_recovery_fraud` as `FIREWALL_ONLY_AUDIT`
* `scenario_injection_chain` as `SCENARIO_AUDIT`
* `generic_safety` as `LIVE_GATING_CHECK` (single live sentinel slice)

Comparability rules are evidence-first:

* compare only like-for-like `proof_class`
* keep `domain_pack` and `scenario_pack` rows separate
* treat `row_identity` as the comparability key
* do not infer ranking/score semantics from benchmark index metadata

## Failure handling notes for operators

When a run is malformed, invalid, or inconclusive, treat it as non-passing and inspect run evidence directly:

* `proofs/run_summary.json`
* `proofs/latest-attempts.log`
* `proofs/itgl_ledger.jsonl`
* `proofs/runs/<run_id>/...` (if archived)

If SIR is bypassed or not deployed in front of the real model request path, run artefacts do not establish governance for that bypassed traffic.

## Serve proof pages locally

The HTML proof pages load JSON via `fetch()`. Browsers often block this under `file://`.
Serve the repo over HTTP:

```bash
python -m http.server 8000
```

Open:

* Latest certificate page: `http://localhost:8000/proofs/latest-audit.html`
* Run archive index: `http://localhost:8000/proofs/runs/index.html`

## Verify the published SDL-signed certificate locally (optional)

Operator path:

```bash
curl -s -o latest-audit.json https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json
sir verify cert latest-audit.json
```

Low-level fallback (stdin). The trailing `-` means “read JSON from stdin”:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

SDL public key:

* `spec/sdl.pub`

Key governance readiness reference:

* `docs/key-governance-readiness.md`
