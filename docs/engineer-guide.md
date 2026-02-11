# SIR Engineer Guide

This guide is for running SIR locally, generating artefacts, and serving proof pages during development.

## Runtime requirements

Python 3 is required.

## Local install (Mac, Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .
python3 --version
```

## Run the audit locally (one command)

`tools/local_audit.py` runs:

* suite schema validation
* suite execution (default: gate-only, no model calls)
* ITGL verification and export
* optional signing and certificate generation
* run archive publish
* optional local HTTP server (so HTML loads)

### Default (gate-only, no signing)

This produces a local unsigned snapshot:

* `proofs/local-audit.json`
* `proofs/local-audit.html`

```bash
python3 tools/local_audit.py --suite tests/domain_packs/generic_safety.csv
```

### Generate a locally signed certificate (dev or test key, not SDL)

This produces:

* `proofs/latest-audit.json`
* `proofs/latest-audit.html`
* plus `local_keys/local_signing_key*.pem`

Local signing uses a locally generated dev or test key. It does not produce SDL-signed certificates and is not equivalent to published proof.

```bash
python3 tools/local_audit.py --suite tests/domain_packs/generic_safety.csv --sign local
```

Verify the locally signed certificate:

```bash
python3 tools/verify_certificate.py proofs/latest-audit.json --pubkey local_keys/local_signing_key.pub.pem
```

### Serve the HTML locally (avoids `file://` fetch restrictions)

```bash
python3 tools/local_audit.py --suite tests/domain_packs/generic_safety.csv --serve
```

Then open:

* Default (`--sign none`): `http://localhost:8000/proofs/local-audit.html`
* Local-signed (`--sign local`): `http://localhost:8000/proofs/latest-audit.html`
* Run archive index: `http://localhost:8000/proofs/runs/index.html`

## Notes on local HTML viewing

`local-audit.html`, `latest-audit.html`, and `runs/index.html` load JSON via `fetch()`.

If you open them via `file://`, many browsers will block JSON loading. Serve the repo over HTTP instead:

```bash
python3 -m http.server 8000
```

## Where the proof comes from

* Public key for SDL-signed certificates: `spec/sdl.pub`
* Verifier script: `tools/verify_certificate.py`

### Latest PASS proof (repo files)

* Latest PASS pointer certificate: `proofs/latest-audit.json`
* Latest PASS human page backed by JSON: `proofs/latest-audit.html`

### Latest run status (repo file and served URL)

* Repo path: `docs/latest-run.json`
* Served on GitHub Pages as: `/latest-run.json`

Note: On GitHub Pages, the `docs/` folder is the site root, so `docs/latest-run.json` is served as `https://sdl-hq.github.io/sir-firewall/latest-run.json`.

### Run archives (repo files)

* Run archives (passes + failures): `proofs/runs/<run_id>/...`
* Run archive index: `proofs/runs/index.json` and `proofs/runs/index.html`

### ITGL artefacts (repo files)

* ITGL ledger and final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`

## Optional: verify the published SDL-signed certificate locally

If you want to verify the currently published certificate (not a local run), you can do it two ways.

Pipe form (stdin). The trailing `-` means “read JSON from stdin”:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Or download then verify (file path):

```bash
curl -s -o latest-audit.json https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json
python3 tools/verify_certificate.py latest-audit.json
```
