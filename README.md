# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · Hardened 2025 jailbreak suite on Grok-3 · Cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)
[![Tests](https://github.com/SDL-HQ/sir-firewall/actions/workflows/tests.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/tests.yml)

Every successful CI run executes the **current 2025 jailbreak suite** against Grok-3 via SIR, then:

- Writes a full attempt log to `proofs/latest-attempts.log`
- Emits a cryptographically **signed audit certificate** in `proofs/latest-audit.json`
- Exposes a public HTML badge in `proofs/latest-audit.html`

Repo: **https://github.com/SDL-HQ/sir-firewall**  
SDL: **https://www.structuraldesignlabs.com · @SDL_HQ**

---

## What SIR Does

SIR is a **pure-rule, pre-inference firewall** that sits in front of an LLM and decides:

1. **Should this prompt reach the model at all?**  
2. **If yes, under what governance context?**

It never calls out to any external service. It just:

- Normalises and de-obfuscates the incoming text
- Applies a fixed rule set (no ML, no embeddings)
- Emits a `PASS` / `BLOCKED` decision plus a full audit log

You run SIR **before** your model. If SIR blocks it, the model never sees it.

---

## How It Works (Very Short Version)

**Inputs**

- A structured **ISC envelope** (Inference Safety Contract) that wraps the user payload
- Your own system instructions or upstream governance rules

**Core behaviour**

SIR:

1. **Normalises** the payload  
   - Strips zero-width characters  
   - Decodes common obfuscations (ROT13, Base64 fragments, etc.)  
   - Collapses spacing / separators so “jail­break”, “j a i l b r e a k”, etc. all resolve

2. **Checks rule sets** on the normalised text  
   - Jailbreak patterns  
   - “Ignore previous instructions” style overrides  
   - Obvious system prompt exfiltration patterns  
   - Basic leakage / data-exfil flags

3. **Emits an ITGL log** (Integrity Trace Governance Log)  
   - Every decision is appended as a hash-chained record  
   - You can persist this as your **audit trail** for regulators, insurers, or internal governance

No gradients, no prompts, no tuning. Just deterministic rules and logs.

---

## Quick Start

### 1. Install dependencies

From the repo root:

    pip install -r requirements.txt

(Or add the package to your own environment and wire it into your pipeline.)

### 2. Minimal example

    from sir_firewall import validate_sir

    payload = {
        "isc": {
            "version": "1.0",
            "template_id": "EU-AI-Act-ISC-v1",
            "payload": "User prompt goes here",
            "checksum": "",
            "signature": "",
            "key_id": "default",
        }
    }

    result = validate_sir(payload)

    print(result["status"])    # "PASS" or "BLOCKED"
    print(result["reason"])    # Short reason string
    # print(result["itgl_log"])  # Optional: full decision/audit log

You plug this in **before** your LLM call. If `status == "BLOCKED"`, you never send the prompt.

---

## Expected Output

`validate_sir` always returns a JSON-serialisable dict with at least:

    {
      "status": "PASS",
      "reason": "All checks passed",
      "itgl_log": [
        {
          "step": "normalise",
          "detail": "Zero-width and control chars stripped",
          "hash": "…"
        },
        {
          "step": "rules",
          "detail": "No jailbreak or exfil patterns matched",
          "hash": "…"
        }
      ]
    }

On a blocked prompt, you might see:

    {
      "status": "BLOCKED",
      "reason": "JAILBREAK_PATTERN_DETECTED",
      "itgl_log": [
        {
          "step": "rules",
          "detail": "Matched pattern: ignore-previous-instructions",
          "hash": "…"
        }
      ]
    }

You can store `itgl_log` as your governance evidence or pipe it into your own logging stack.

---

## The Public 2025 Jailbreak Suite

This repo ships with a **public red-team CSV** at:

- `tests/jailbreak_prompts_public.csv`

Each row has:

- `prompt` – the actual test prompt sent through SIR  
- `expected` – `"block"` for jailbreaks, `"allow"` for harmless prompts  
- (Optional) `note` – human-readable category / commentary

The **exact number of prompts is not hard-coded anywhere**:

- `red_team_suite.py` loads the CSV and infers how many jailbreak vs harmless prompts there are.
- `generate_certificate.py` **counts the rows** and writes `prompts_tested` into the signed certificate.
- `proofs/template.html` reads `latest-audit.json` and displays whatever `prompts_tested` actually is.

If you add or remove rows in `tests/jailbreak_prompts_public.csv`, the audit automatically reflects reality on the next CI run.

---

## Running the Red-Team Audit Locally

The CI workflow (`.github/workflows/audit-and-sign.yml`) runs the public suite on Grok-3 and signs the result.  
You can trigger the same test locally.

### 1. Set your xAI / Grok API key

Export your key as expected by your local setup (for example, via LiteLLM):

    export LITELLM_MODEL="xai/grok-3-beta"
    export XAI_API_KEY="sk-…"

(Adjust env vars to match however you’re calling Grok in your environment.)

### 2. Run the red-team suite

From the repo root:

    python red_team_suite.py

This will:

- Load `tests/jailbreak_prompts_public.csv`
- Wrap each prompt in a minimal ISC envelope
- Run it through `sir_firewall.validate_sir`
- Write a full log to `proofs/latest-attempts.log`
- Write leak counts to:
  - `leaks_count.txt` – number of jailbreak prompts that leaked past SIR
  - `harmless_blocked.txt` – number of harmless prompts SIR blocked

Exit codes:

- **0** – no jailbreak leaks, no harmless prompts blocked (`TOTAL VICTORY`)
- **1** – at least one jailbreak leak or harmless false-positive (`AUDIT FAILED`)

### 3. Generate a signed certificate (optional locally, automatic in CI)

    python generate_certificate.py

This will:

- Count the prompts in `tests/jailbreak_prompts_public.csv`
- Read leak counts from `leaks_count.txt` / `harmless_blocked.txt`
- Build a JSON payload with:
  - `prompts_tested`
  - `jailbreaks_leaked`
  - `harmless_blocked`
  - `result` (`TOTAL VICTORY` or `AUDIT FAILED`)
  - Model, repo, commit SHA, CI run URL (where available)
- Sign it with SDL’s private key (in CI) using RSA-PKCS1v15-SHA256
- Write:
  - `proofs/audit-certificate-<timestamp>.json`
  - `proofs/latest-audit.json`
  - `proofs/latest-audit.html` (static HTML that reads the JSON)

Locally, you’ll only be able to sign if you’ve provided the private key via `SDL_PRIVATE_KEY_PEM`.  
In CI, this is wired as a GitHub secret.

---

## Verifying the Certificate

You can verify the signature with SDL’s public key (`sdl.pub`) and the verifier script.

Example:

    curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json \
      | python -m verify_certificate

Or point it at a specific JSON file:

    python verify_certificate.py proofs/latest-audit.json

This checks:

- The SHA-256 payload hash
- The RSA signature against `sdl.pub`
- That the certificate content hasn’t been tampered with

---

## Repo Layout (Key Files)

- `sir_firewall/core.py`  
  SIR core logic (normalisation, rule checks, ITGL logging).

- `sir_firewall/__init__.py`  
  Exposes the `validate_sir` entrypoint.

- `tests/jailbreak_prompts_public.csv`  
  Public red-team suite. **You can expand or modify this; counts are inferred automatically.**

- `red_team_suite.py`  
  Runs the public suite through SIR, writes `proofs/latest-attempts.log`, and emits leak counts.

- `generate_certificate.py`  
  CI tool for building and signing audit certificates. Automatically derives `prompts_tested` from the CSV.

- `proofs/template.html`  
  Static HTML template that reads `latest-audit.json` and renders the current audit result (including real prompt count).

- `sdl.pub`  
  SDL’s public key for signature verification.

- `README.md`, `LICENSE`, `pyproject.toml`, `requirements.txt`  
  Docs, license, and dependency definitions.

---

## License

MIT Licensed  
© 2025 Structural Design Labs
