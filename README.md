# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · 2025 jailbreak suite on Grok-3 · Cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Every successful CI run executes a **pre-inference audit suite** (firewall-only by default) and updates a **signed audit certificate** in `proofs/latest-audit.json`, together with a public HTML page on GitHub Pages backed by the same signed JSON: `proofs/latest-audit.html`.

This repo also emits an **ITGL hash-chained run ledger** (`proofs/itgl_ledger.jsonl`). Its verified final hash (`ITGL_FINAL_HASH`) is embedded into the signed certificate as an additional integrity anchor.

Repo: **https://github.com/SDL-HQ/sir-firewall**  
SDL: **https://www.structuraldesignlabs.com** · <-- updates + live test benchmarks coming Jan/Feb 26 · @SDL_HQ

---

## What SIR Does

SIR is a **pure-rule, pre-inference firewall** that sits in front of an LLM and decides:

- `PASS` → safe to send to the model
- `BLOCKED` → rejected before the model ever sees it

It is designed to resist real-world prompt obfuscation (ROT13, base64, zero-width characters, spacing games, etc.) and is tested against hardened jailbreak suites.

This repo includes:

- The **firewall core** (`src/sir_firewall`)
- **Audit suites** (`tests/` and `tests/domain_packs/`)
- A **CI workflow** that:
  - Runs an audit suite through SIR (firewall-only by default)
  - Writes a proof log + summary
  - Verifies the ITGL hash-chained run ledger
  - Generates a **signed JSON certificate** in `proofs/latest-audit.json`
  - Publishes `proofs/latest-audit.html`
- Verification tools:
  - `tools/verify_certificate.py` (verifies RSA signature with `spec/sdl.pub`)
  - `tools/verify_itgl.py` (verifies `proofs/itgl_ledger.jsonl` and emits `ITGL_FINAL_HASH`)

---

## Verified Proof (One Command)

Verify the latest published audit certificate with one command:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 -m tools.verify_certificate
````

Expected output:

```text
OK: Certificate signature valid and payload_hash matches.
```

The HTML summary page is kept in sync:

[https://sdl-hq.github.io/sir-firewall/latest-audit.html](https://sdl-hq.github.io/sir-firewall/latest-audit.html)

---

## ITGL Ledger Verification (Optional, Stronger Proof)

Each audit run also emits an ITGL hash-chained ledger:

* `proofs/itgl_ledger.jsonl`
* `proofs/itgl_final_hash.txt` (a run-level anchor)
* `itgl_final_hash` is embedded in the signed certificate

Verify the ledger locally:

```bash
python3 tools/verify_itgl.py
```

Expected output:

```text
ITGL_FINAL_HASH=sha256:<...>
ITGL ledger verification OK: 25 entries, final_ledger_hash=<...>
```

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

The point of `prompt_b64` is simple: the suite is still deterministic and testable, but the raw prompt text is not sitting in plaintext in the repo.

---

## Running the Red-Team Audit Locally

CI runs a firewall-only audit automatically. You can run the same harness yourself.

### Firewall-only mode (recommended / matches CI)

```bash
python3 red_team_suite.py --no-model-calls
```

Run a specific domain pack:

```bash
python3 red_team_suite.py --suite tests/domain_packs/generic_safety.csv --no-model-calls
python3 red_team_suite.py --suite tests/domain_packs/mental_health_clinical.csv --no-model-calls
```

Outputs:

* `proofs/latest-attempts.log` (human readable)
* `proofs/run_summary.json` (machine readable; generated during runs)
* `leaks_count.txt` + `harmless_blocked.txt` (back-compat)
* `proofs/itgl_ledger.jsonl` + `proofs/itgl_final_hash.txt` (ITGL run ledger + anchor)

### Optional: live model-call mode (integration testing)

If you want to prove the firewall is actively gating real calls, run without `--no-model-calls`. This is not required for certificate verification and is typically used for manual integration tests only.

LiteLLM will look for the relevant provider key (see LiteLLM docs). For xAI this is commonly:

```bash
export XAI_API_KEY="your_key_here"
python3 red_team_suite.py --suite tests/domain_packs/generic_safety.csv
```

---

## Certificate Generation (CI / Signing)

Most users only ever need to verify the published certificate, not generate one.

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
  CI pipeline runs audit suite through SIR (firewall-only by default), verifies ITGL, generates and signs the certificate, updates the `latest-audit` files.

* `src/sir_firewall/`
  SIR core logic (normalisation, rule checks, `validate_sir` entry point).

* `red_team_suite.py`
  Audit harness. Reads a suite CSV, runs SIR gating, and writes `proofs/run_summary.json`.

* `tests/jailbreak_prompts_public.csv`
  Public 2025 reference prompts.

* `tests/domain_packs/`
  Additional suites (including base64-encoded packs).

* `proofs/`

  * `latest-audit.json` current signed certificate
  * `latest-audit.html` HTML view backed by `latest-audit.json`
  * `template.html` HTML template used by the signer
  * `itgl_ledger.jsonl` per-prompt hash-chained run ledger
  * `itgl_final_hash.txt` run-level ITGL final hash (`sha256:<hex>`)

* `tools/`

  * `verify_certificate.py` verifies hash and RSA signature using `spec/sdl.pub`
  * `verify_itgl.py` verifies ITGL ledger structure and chain integrity
  * `generate_certificate.py` CI signer

* `spec/sdl.pub`
  SDL public key used for verifying signatures.

---

## License

MIT Licensed
© 2025 Structural Design Labs

```
