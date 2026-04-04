# SIR Engineer Guide

This guide is for running SIR locally, generating artefacts, and serving proof pages during development.

## Runtime requirements

- Python 3.11+
- Git

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

Modes:

* `--mode audit` (default): deterministic gate only, no model calls (`proof_class = FIREWALL_ONLY_AUDIT`)
* `--mode live`: model calls for PASS prompts only (`proof_class = LIVE_GATING_CHECK`)
* Scenario packs use the same runner; pack schema determines behavior (`proof_class = SCENARIO_AUDIT` when applicable)

## Run an audit locally (no model calls)

```bash
python red_team_suite.py --mode audit --pack generic_safety
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
python tools/verify_itgl.py
```

## Run a live gating check (PASS prompts call provider)

LIVE requires:

* installing live extras
* your own provider credentials (SIR does not ship keys)

Install live extras:

```bash
pip install -e ".[live]"
```

Set provider credentials (example: xAI):

```bash
export XAI_API_KEY="paste_key_here"
```

Run live:

```bash
python red_team_suite.py --mode live --pack generic_safety
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
python tools/generate_certificate.py
python tools/validate_certificate_contract.py proofs/latest-audit.json
python tools/verify_certificate.py proofs/latest-audit.json --pubkey /tmp/sir_dev_pub.pem
```

## Publish a local run archive (signed receipt)

Publishing a run archive creates:

* `proofs/runs/<run_id>/manifest.json`
* `proofs/runs/<run_id>/audit.json`
* `proofs/runs/<run_id>/archive_receipt.json` (signed)

It requires `SDL_PRIVATE_KEY_PEM` to be set.

```bash
python tools/publish_run.py --cert proofs/latest-audit.json \
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
python tools/verify_archive_receipt.py "$RUN_DIR" --pubkey /tmp/sir_dev_pub.pem
```

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

Pipe form (stdin). The trailing `-` means “read JSON from stdin”:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Or download then verify:

```bash
curl -s -o latest-audit.json https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json
python3 tools/verify_certificate.py latest-audit.json
python3 tools/validate_certificate_contract.py latest-audit.json
```

SDL public key:

* `spec/sdl.pub`
