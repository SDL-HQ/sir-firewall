# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · 2025 jailbreak suite on Grok-3 · Cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Every successful CI run executes the **25-prompt 2025 jailbreak reference suite** on **Grok-3** and updates a **signed audit certificate** in `proofs/latest-audit.json`, together with a public HTML badge in `proofs/latest-audit.html`.

Repo: **https://github.com/SDL-HQ/sir-firewall**  
SDL: **https://www.structuraldesignlabs.com · @SDL_HQ**

---

## What SIR Does

SIR is a **pure-rule, pre-inference firewall** that sits in front of an LLM and decides:

- `PASS` → safe to send to the model  
- `BLOCKED` → rejected *before* the model ever sees it

It is designed to resist real-world prompt obfuscation (ROT13, base64, zero-width characters, spacing games, etc.) and is tested against a hardened 2025 jailbreak suite on Grok-3.

This repo includes:

- The **firewall core** (`src/sir_firewall`)
- A **public red-team suite** (`tests/jailbreak_prompts_public.csv`)
- A **CI workflow** that:
  - Runs the 25-prompt audit on Grok-3
  - Writes `leaks_count.txt`
  - Generates a **signed JSON certificate** in `proofs/latest-audit.json`
  - Publishes an HTML badge at `proofs/latest-audit.html`
- A **verification tool** (`tools/verify_certificate.py`) to check the signature with SDL’s public key (`spec/sdl.pub`)

---

## Verified Zero-Jailbreak Proof

You can verify the latest published audit certificate yourself with **one command**:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 -m tools.verify_certificate
```

Expected output (if the certificate is valid and unmodified):

```text
Signature verification PASSED — 100% real, cryptographically valid proof
```

To inspect the certificate fields (model, date, prompts, result, CI run URL), you can either open it in a browser:

- https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json

or use `jq` locally:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | jq
```

The HTML summary page is also kept in sync:

- https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html

This page reads `latest-audit.json` at runtime and shows the current result, leak count, and CI run link.

### Legacy 100-Prompt Certificate

The original 100-prompt audit certificate is preserved for reference:

- `proofs/audit-certificate-LEGACY-100-prompt.json`

It uses the same signing scheme and can be verified with the same command pattern, just pointing at that file instead of `latest-audit.json`.

---

## Install & Use

### 1. Clone and install

```bash
git clone https://github.com/SDL-HQ/sir-firewall
cd sir-firewall
pip install -r requirements.txt
```

This will install the minimal dependencies, including `cryptography` for certificate verification.

### 2. Basic Python usage

SIR is exposed via a single entry point, `validate_sir`, which returns a status and a small log:

```python
from sir_firewall import validate_sir

payload = {
    "input": "Your user prompt here"
    # or whatever structure your calling system uses; SIR only cares about the text field it’s wired to
}

result = validate_sir(payload)

print(result["status"])   # "PASS" or "BLOCKED"
# print(result["itgl_log"])  # optional: full decision/audit log for this call
```

You can plug this into your own inference pipeline by calling `validate_sir` **before** you send anything to your model.

---

## Running the Red-Team Audit Locally

The CI workflow (`.github/workflows/audit-and-sign.yml`) runs the **25-prompt public suite** on Grok-3 and then signs the result.  
You can trigger the same test manually from your machine.

### 1. Set your xAI / Grok API key

The exact environment variable name is defined in `red_team_suite.py`.  
For most setups it will look something like:

```bash
export XAI_API_KEY="your_grok3_api_key_here"
```

(If in doubt, open `red_team_suite.py` and check the `os.environ.get(...)` line for the key name.)

### 2. Run the suite

From the repo root:

```bash
python3 red_team_suite.py
```

This will:

- Load the **25 public prompts** from `tests/jailbreak_prompts_public.csv`
- Call Grok-3 with SIR in front
- Print a human-readable summary to stdout
- Write `leaks_count.txt` at the repo root with the number of jailbreak leaks detected

### 3. (Optional) Generate a new signed certificate

Normally CI does this for you, but if you have the SDL private key available (you probably don’t, which is the point), you can generate a fresh certificate locally:

```bash
export SDL_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----"
python3 tools/generate_certificate.py
```

This will:

- Build a new certificate JSON in `proofs/audit-certificate-*.json`
- Update the pointers:
  - `proofs/latest-audit.json`
  - `proofs/latest-audit.html` (from `proofs/template.html`)
- Print the paths of the generated files

Most users only ever need to **verify** the published cert, not generate new ones.

---

## Running Tests

There is a lightweight test harness under `tests/` that exercises the SIR core and keeps basic behaviours stable.

From the repo root:

```bash
pytest
```

This will run any unit tests (e.g. `tests/test_sir.py`) without touching external APIs.

---

## Files & Layout (Quick Map)

- `.github/workflows/audit-and-sign.yml`  
  CI pipeline → runs red-team suite, generates+signs cert, updates `latest-audit` files.

- `src/sir_firewall/`  
  SIR core logic (normalisation, rule checks, `validate_sir` entry point).

- `red_team_suite.py`  
  25-prompt Grok-3 red-team runner. Uses `tests/jailbreak_prompts_public.csv` and writes `leaks_count.txt`.

- `tests/jailbreak_prompts_public.csv`  
  Public 2025 reference jailbreak + harmless prompts (15 jailbreaks + 10 harmless) used by CI and `red_team_suite.py`.

- `proofs/`  
  - `latest-audit.json` — **current signed audit certificate** (what the README verify command uses)  
  - `latest-audit.html` — HTML view backed by `latest-audit.json`  
  - `template.html` — HTML template used by `generate_certificate.py`  
  - `audit-certificate-LEGACY-100-prompt.json` — archived 100-prompt certificate (legacy)

- `tools/`  
  - `verify_certificate.py` — loads `proofs/latest-audit.json`, checks hash + RSA signature with `spec/sdl.pub`  
  - `generate_certificate.py` — CI tool for building and signing certificates (normally only used in CI)

- `spec/sdl.pub`  
  SDL’s public key used for verifying signatures.

- `README.md`, `LICENSE`, `pyproject.toml`, `requirements.txt`  
  Project docs, license, and dependency definitions.

---

## License

MIT Licensed — free for everyone, forever.  
© 2025 Structural Design Labs
