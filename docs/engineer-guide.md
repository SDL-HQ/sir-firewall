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
````

## Run the audit locally (one command)

`tools/local_audit.py` runs:

* suite schema validation
* suite execution (default: gate-only, no model calls)
* ITGL verification and export
* optional signing and certificate generation
* run archive publish
* optional local HTTP server (so HTML loads)

### Default (gate-only, no signing)

This produces a LOCAL UNSIGNED snapshot:

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
* Run archive: `http://localhost:8000/proofs/runs/index.html`

## Notes on local HTML viewing

`local-audit.html`, `latest-audit.html`, and `runs/index.html` load JSON via `fetch()`.
If you open them via `file://`, many browsers will block JSON loading.

Serve the repo over HTTP instead:

```bash
python3 -m http.server 8000
```

## Where the proof comes from

* Public key for SDL-signed certificates: `spec/sdl.pub`
* Verifier script: `tools/verify_certificate.py`
* Latest pointer certificate: `proofs/latest-audit.json`
* Human page backed by JSON: `proofs/latest-audit.html`
* Run archives: `proofs/runs/<run_id>/...`
* ITGL ledger and final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
