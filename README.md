# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · 2025 jailbreak suite on Grok-3 · Cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Every successful CI run executes a **pre-inference audit suite** and updates a **signed audit certificate** in `proofs/latest-audit.json`, together with a public HTML page in `proofs/latest-audit.html`.

Repo: **https://github.com/SDL-HQ/sir-firewall**  
SDL: **https://www.structuraldesignlabs.com · @SDL_HQ**

---

## What SIR Does

SIR is a **pure-rule, pre-inference firewall** that sits in front of an LLM and decides:

- `PASS` → safe to send to the model  
- `BLOCKED` → rejected *before* the model ever sees it

It is designed to resist real-world prompt obfuscation (ROT13, base64, zero-width characters, spacing games, etc.) and is tested against hardened jailbreak suites.

This repo includes:

- The **firewall core** (`src/sir_firewall`)
- **Audit suites** (`tests/` and `tests/domain_packs/`)
- A **CI workflow** that:
  - Runs an audit suite on Grok-3
  - Writes a proof log + summary
  - Generates a **signed JSON certificate** in `proofs/latest-audit.json`
  - Publishes `proofs/latest-audit.html`
- A **verification tool** (`tools/verify_certificate.py`) to check the signature with SDL’s public key (`spec/sdl.pub`)

---

## Verified Proof (One Command)

Verify the latest published audit certificate with **one command**:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 -m tools.verify_certificate
````

Expected output:

```text
OK: Certificate signature valid and payload_hash matches.
```

The HTML summary page is kept in sync:

* [https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html](https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html)

---

## Domain Packs (Suites)

SIR audit suites are just CSV files.

Two supported formats:

### 1) Plain/public suites

Columns:

* `id` (optional)
* `prompt`
* `expected` (`allow` or `block`)
* `note` (optional)
* `category` (optional)

Example: `tests/jailbreak_prompts_public.csv`

### 2) Sensitive/encoded suites

Columns:

* `id`
* `prompt_b64` (base64-encoded UTF-8 prompt)
* `expected` (`allow` or `block`)
* `note` (optional)
* `category` (optional)

Examples live under: `tests/domain_packs/`

The point of `prompt_b64` is simple: the suite is still deterministic and testable, but the raw prompt text isn’t sitting in plaintext in the repo.

---

## Running the Red-Team Audit Locally

CI runs this automatically, but you can run the same harness yourself.

### 1) Set your xAI / Grok API key

LiteLLM will look for the relevant provider key (see LiteLLM docs). For xAI this is commonly:

```bash
export XAI_API_KEY="your_key_here"
```

### 2) Run the suite (default)

```bash
python3 red_team_suite.py
```

### 3) Run a specific domain pack

```bash
python3 red_team_suite.py --suite tests/domain_packs/generic_safety.csv
python3 red_team_suite.py --suite tests/domain_packs/mental_health_clinical.csv
```

Outputs:

* `proofs/latest-attempts.log` (human readable)
* `proofs/run_summary.json` (machine readable)
* `leaks_count.txt` + `harmless_blocked.txt` (back-compat)

---

## Certificate Generation (CI / Signing)

Most users only ever need to **verify** the published certificate, not generate one.

In CI, the signer runs:

```bash
python3 tools/generate_certificate.py
```

It produces:

* `proofs/latest-audit.json`
* `proofs/latest-audit.html`
* `proofs/audit-certificate-<timestamp>.json` (archival)

---

## Files & Layout (Quick Map)

* `.github/workflows/audit-and-sign.yml`
  CI pipeline → runs audit suite, generates+signs cert, updates `latest-audit` files.

* `src/sir_firewall/`
  SIR core logic (normalisation, rule checks, `validate_sir` entry point).

* `red_team_suite.py`
  Audit harness. Reads a suite CSV, runs SIR gating, optionally calls the model for PASS prompts, and writes `proofs/run_summary.json`.

* `tests/jailbreak_prompts_public.csv`
  Public 2025 reference prompts.

* `tests/domain_packs/`
  Additional suites (including base64-encoded packs).

* `proofs/`

  * `latest-audit.json` — current signed certificate
  * `latest-audit.html` — HTML view backed by `latest-audit.json`
  * `template.html` — HTML template used by the signer

* `tools/`

  * `verify_certificate.py` — verifies hash + RSA signature using `spec/sdl.pub`
  * `generate_certificate.py` — CI signer

* `spec/sdl.pub`
  SDL public key used for verifying signatures.

---

## License

MIT Licensed
© 2025 Structural Design Labs
::contentReference[oaicite:0]{index=0}
```
