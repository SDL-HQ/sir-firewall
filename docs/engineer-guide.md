# SIR Engineer Guide

This guide is for running SIR locally, generating artefacts, and serving proof pages during development.

For canonical operator/reviewer cold-start execution, use `docs/minimal-pilot-runbook.md`.
For evaluator interpretation and boundary semantics, use `docs/evaluator-technical-explainer.md`.
Use `docs/assurance-kit.md` as a compact supporting walkthrough aligned to the same surfaces.

For the first disciplined benchmark-cycle contract (what to run, required artefacts, and comparability rules), use `docs/benchmark-cycle.v1.md`.

## Runtime requirements

- Python 3.11+
- Git

## Quickstart install paths (canonical)

The `sir` console command requires an editable installation of a complete repository checkout. See the installation support boundary in `README.md` before installing or moving a checkout.

```bash
# audit mode
python3 -m pip install -e .

# live mode
python3 -m pip install -e ".[live]"

# verify-only (published certificate, no local run)
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py - --no-ledger
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

* `--mode audit` (default): deterministic gate-only evaluation (`proof_class = FIREWALL_ONLY_AUDIT`)
* `--mode live`: model calls for PASS prompts only (`proof_class = LIVE_GATING_CHECK`)
* Scenario packs use the same runner; pack schema determines behavior (`proof_class = SCENARIO_AUDIT` when applicable)

## Run an audit locally (--mode audit, gate-only)

```bash
sir run --mode audit --pack generic_safety
```

Outputs (local run artefacts):

* `proofs/latest-attempts.log`
* `proofs/run_summary.json`
* `proofs/itgl_ledger.jsonl`
* `leaks_count.txt`
* `harmless_blocked.txt`

`proofs/run_summary.json` records pack provenance with explicit separation:
* `selected_pack_id` / `selected_pack_version`: input selection intent
* `effective_pack_id`: runtime enforcement pack observed from gate execution
* `pack_id`: runtime pack alias used by downstream cert/archive metadata

`proofs/itgl_final_hash.txt` is not produced by `sir run`. The ITGL verification step below writes it when it is given `--write-hash`, and writes nothing without it.

Verify ITGL, and write the terminal hash for the publishing step further down:

```bash
python3 tools/verify_itgl.py --write-hash proofs/itgl_final_hash.txt
```

## Run a live gating check (PASS prompts call provider)

LIVE requires:

* installing live extras
* your own provider credentials (SIR does not ship keys)

Install live extras:

```bash
python3 -m pip install -e ".[live]"
```

Set provider credentials:

```bash
# xAI
export XAI_API_KEY="paste_key_here"
# OpenAI
export OPENAI_API_KEY="paste_key_here"
```

Run live:

```bash
sir run --mode live --pack generic_safety --provider xai --model grok-4.3
```

If credentials or live dependencies are missing, `sir` fails fast with explicit blocker text (for example missing provider-specific credential env vars such as `XAI_API_KEY` or `OPENAI_API_KEY`, or missing `litellm`) and does not simulate/fallback.

The run summary records:

* `provider_call_attempts` (attempted downstream calls, including retries/timeouts)
* `provider_call_successes` / `provider_call_failures`
* `proof_class = LIVE_GATING_CHECK`

Supported provider/model selection and defaults are documented in `docs/model-selection.md`.

## Integration patterns (existing behavior only)

This section documents current integration usage only. It does not introduce a new runtime feature.

### Python middleware

Minimal pattern:

1. Receive request text or structured payload in middleware before model execution.
2. Call `validate_text(...)` for plain text or `validate_sir(...)` for ISC/structured input.
3. Block and return an application-level refusal on any non-`PASS` result.
4. Call the downstream model only when status is `PASS`.

This is documentation of existing behavior, not a new runtime feature.
Any model path that bypasses SIR is out of claim scope.

### containerised sidecar deployment

Minimal pattern:

1. Route each model-bound request through a local sidecar process that invokes SIR first.
2. Call `validate_text(...)` for plain text or `validate_sir(...)` for ISC/structured input.
3. Block and return a deny response on any non-`PASS` result.
4. Forward to the model service only when status is `PASS`.

This is documentation of existing behavior, not a new runtime feature.
Any model path that bypasses SIR is out of claim scope.

### agentic pipeline pre-call wrapper

Minimal pattern:

1. Receive agent step input before each model call in the pipeline.
2. Call `validate_text(...)` for plain text or `validate_sir(...)` for ISC/structured input.
3. Block and stop the step on any non-`PASS` result.
4. Execute the model call only when status is `PASS`.

This is documentation of existing behavior, not a new runtime feature.
Any model path that bypasses SIR is out of claim scope.

## Generate a locally signed certificate (dev/test key)

Certificate generation and run-archive publishing require a signing key in `SDL_PRIVATE_KEY_PEM`, the id of that key in `SDL_SIGNING_KEY_ID`, and a key registry that enrols it in `SDL_KEY_REGISTRY`.
This is for local/dev proofs. It is not an SDL-signed production proof.

Create a temporary dev key:

```bash
openssl genrsa -out /tmp/sir_dev_priv.pem 2048 >/dev/null 2>&1
export SDL_PRIVATE_KEY_PEM="$(cat /tmp/sir_dev_priv.pem)"
openssl rsa -in /tmp/sir_dev_priv.pem -pubout -out /tmp/sir_dev_pub.pem >/dev/null 2>&1
```

Enrol it in a key registry of your own and name it. A signer refuses unless the registry entry named by `SDL_SIGNING_KEY_ID` holds the public key belonging to the key in hand, so a dev key is enrolled exactly as a real one is. Without these two variables `generate_certificate.py` stops with `refusing to sign: SDL_SIGNING_KEY_ID is not set`.

```bash
python3 - <<'PY'
import json, pathlib
pathlib.Path("/tmp/sir_dev_key_registry.json").write_text(json.dumps({
    "keys": [{
        "key_id": "dev-local",
        "pubkey_pem": pathlib.Path("/tmp/sir_dev_pub.pem").read_text(),
        "status": "active",
    }]
}), encoding="utf-8")
PY
export SDL_SIGNING_KEY_ID=dev-local
export SDL_KEY_REGISTRY=/tmp/sir_dev_key_registry.json
```

Generate certificate + validate + verify (through your dev registry):

Local generation writes `proofs/local-audit.json` because attributable CI provenance is absent. This is expected. The generator prints `OUTPUT_AUDIT_JSON=proofs/local-audit.json` so you can confirm the selected output path.

```bash
python3 tools/generate_certificate.py
python3 tools/validate_certificate_contract.py proofs/local-audit.json
python3 tools/verify_certificate.py proofs/local-audit.json --key-registry /tmp/sir_dev_key_registry.json
```

The certificate names `dev-local`. The default SDL key registry does not have that key, so verifying against it stops with `signing_key_id not found in key registry: dev-local`, with or without `--pubkey`, at exit 6: the code for a check that could not be performed, because there is no key to check the signature against.

## Publish a local run archive (signed receipt)

Publishing a run archive creates:

* `proofs/runs/<run_id>/manifest.json`
* `proofs/runs/<run_id>/audit.json`
* `proofs/runs/<run_id>/archive_receipt.json` (signed)
* `proofs/runs/benchmark_index.v1.json`, `.v2.json` and `.v3.json` (machine-readable benchmark index summaries; v3 is current and the other two are superseded)

It requires the three variables above, and `proofs/itgl_final_hash.txt` written from this run's ledger by the ITGL step earlier in this guide. `publish_run.py` refuses a hash file left over from another run.

```bash
python3 tools/publish_run.py --cert proofs/local-audit.json \
  --copy proofs/itgl_ledger.jsonl \
  --copy proofs/itgl_final_hash.txt \
  --copy proofs/latest-attempts.log \
  --copy proofs/run_summary.json \
  --copy leaks_count.txt \
  --copy harmless_blocked.txt
```

Verify the latest archived run (through your dev registry):

```bash
RUN_DIR="proofs/runs/$(cat proofs/run_id.txt)"
python3 tools/verify_archive_receipt.py "$RUN_DIR" --key-registry /tmp/sir_dev_key_registry.json
```

The receipt names `dev-local` as the certificate does. Against the default SDL key registry it stops at exit 6 with the same sentence, and passing `--pubkey` does not change that: a receipt is checked against the registry's entry for the key it names and against nothing else. Until 21 November 2026 an explicit `--pubkey` verified it with a warning.

Benchmark/index semantics:

* `proofs/runs/benchmark_index.v3.json` is an evidence map, not a score. It is the current index; `.v1.json` and `.v2.json` remain published and are superseded.
* It records attributable per-run comparison rows: `sir_firewall_version`, `commit_sha`, explicit `evaluation_target` (`domain_pack` or `scenario_pack` + pack identifiers), `proof_class`, `provider`, `model`, `result`, `leaks`, `harmless_blocked`, and evidence links.
* It includes both `latest_run` and `latest_passing_run` pointers so fail/pass truth stays explicit.
* `comparison` is raw run metadata for side-by-side reading only (counts, hashes, and provider call totals), not a ranking model.
* Rows are evidence-linked comparisons only. There is no ranking, no blended domain/scenario row meaning, and no “overall best model” logic.
* Local certificates now attempt best-effort local attribution for `sir_firewall_version` and `commit_sha` (without fabricating CI context). `ci_run_url` remains empty outside CI.

## Canonical benchmark cycle v1

Use `docs/benchmark-cycle.v1.md` for the locked first benchmark set and cycle validity criteria.

Short form of the required set:

* `generic_safety` as `FIREWALL_ONLY_AUDIT`
* `support_operator_override` as `FIREWALL_ONLY_AUDIT`
* `data_exfiltration_pressure` as `FIREWALL_ONLY_AUDIT`
* `structured_account_recovery_benchmark` remains a separate exploratory structured validation surface (not operator `sir run --pack` execution)

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
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py - --no-ledger
```

Verification scope: this command proves payload integrity + signature validity against resolved public key material only (the registry's entry for the `signing_key_id` the certificate names; for a certificate that names none, the registry's implicit entry and then `--pubkey`). It does not prove policy correctness, model safety, or broader trust guarantees.

SDL public key:

* `spec/sdl.pub`

Key governance readiness reference:

* `docs/key-governance-readiness.md`
