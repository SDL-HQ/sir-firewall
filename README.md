# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · 0 leaks on the current 2025 Grok-3 jailbreak suite (latest signed replay) · Offline replay + cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Every successful CI run replays the **current 2025 Grok-3 jailbreak suite** through SIR (firewall-only, no live model calls), then:

* Writes a full attempt log to `proofs/latest-attempts.log`
* Writes a hash-chained ITGL ledger to `proofs/itgl_ledger.jsonl`
* Emits a cryptographically **signed audit certificate** in `proofs/latest-audit.json`
* Exposes a public HTML view in `proofs/latest-audit.html` (reads the JSON and renders a governance snapshot)

Repo: **[https://github.com/SDL-HQ/sir-firewall](https://github.com/SDL-HQ/sir-firewall)**
SDL: **[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com) · @SDL_HQ**

---

## Governance Certificate

View and verify the latest signed SIR governance audit:

* **HTML certificate (human-friendly)**
  [https://raw.githack.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html](https://raw.githack.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html)

* **Raw signed JSON (machine-verifiable)**

  ```bash
  curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json \
    | python -m tools.verify_certificate
  ```

The canonical signed artefact always lives at `proofs/latest-audit.json` on `main`.

---

## What SIR Does

SIR is a **pure-rule, pre-inference firewall** that sits in front of an LLM and decides:

1. **Should this prompt reach the model at all?**
2. **If yes, under what governance context?**

It never calls out to any external service. It just:

* Normalises and de-obfuscates the incoming text
* Applies a fixed rule set (no ML, no embeddings)
* Emits a `PASS` / `BLOCKED` decision plus a full audit log

You run SIR **before** your model. If SIR blocks it, the model never sees it.

---

## How It Works (Very Short Version)

**Inputs**

* A structured **ISC envelope** (Inference Safety Contract) that wraps the user payload
* Your own system instructions or upstream governance rules

**Core behaviour**

SIR:

1. **Normalises** the payload

   * Strips zero-width characters
   * Decodes common obfuscations (ROT13, Base64 fragments, etc.)
   * Collapses spacing / separators so “jail­break”, “j a i l b r e a k”, etc. all resolve

2. **Checks rule sets** on the normalised text

   * Jailbreak patterns
   * “Ignore previous instructions” style overrides
   * Obvious system prompt exfiltration patterns
   * Basic leakage / data-exfil flags

3. **Emits an ITGL log** (Integrity Trace Governance Log)

   * Every decision is appended as a hash-chained record
   * You can persist this as your **audit trail** for regulators, insurers, or internal governance

No gradients, no prompts, no tuning. Just deterministic rules and logs.

---

## Quick Start

### 1. Install dependencies

From the repo root:

```bash
pip install -r requirements.txt
```

(Or add the package to your own environment and wire it into your pipeline.)

### 2. Minimal example

```python
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
print(result["reason"])    # Short reason string like "clean" or an error code
# print(result["itgl_log"])  # Optional: full decision/audit log
```

You plug this in **before** your LLM call. If `status == "BLOCKED"`, you never send the prompt.

---

## Expected Output

`validate_sir` always returns a JSON-serialisable dict with at least:

* `status` – `"PASS"` or `"BLOCKED"`
* `reason` – short reason string or error code
* `domain_pack` – effective Domain ISC pack id (e.g. `generic_safety`)
* `itgl_log` – hash-chained Integrity Trace Governance Log entries
* On `PASS`, a `governance_context` block suitable for downstream governance tooling

### PASS example

```json
{
  "status": "PASS",
  "reason": "clean",
  "domain_pack": "generic_safety",
  "governance_context": {
    "domain_pack": "generic_safety",
    "isc_template": "EU-AI-Act-ISC-v1",
    "itgl_final_hash": "sha256:…",
    "policy_version": "2025-12-05-R4",
    "policy_hash": "sha256:…"
  },
  "itgl_log": [
    {
      "component": "isc_structure",
      "outcome": "pass",
      "hash": "…"
    },
    {
      "component": "jailbreak",
      "outcome": "pass",
      "hash": "…"
    },
    {
      "component": "final",
      "outcome": "complete",
      "hash": "…"
    }
  ]
}
```

### BLOCK example (jailbreak)

```json
{
  "status": "BLOCKED",
  "reason": "2025_jailbreak_pattern",
  "domain_pack": "generic_safety",
  "itgl_log": [
    {
      "component": "jailbreak",
      "outcome": "fail",
      "hash": "…"
    }
  ]
}
```

You can store `itgl_log` as your governance evidence or pipe it into your own logging stack.

### Systemic Reset (SR) – governance-level failure

SR is reserved for **deployment / governance failures** (e.g. missing or broken Domain ISC pack), not per-prompt jailbreaks. In those cases SIR refuses to run and returns:

```json
{
  "status": "BLOCKED",
  "reason": "systemic_reset_domain_pack_load_failed",
  "sr": {
    "sr_triggered": true,
    "sr_reason": "systemic_reset_domain_pack_load_failed",
    "sr_scope": "deployment"
  },
  "itgl_log": [
    {
      "component": "context",
      "outcome": "fail",
      "input": {
        "error": "domain_pack_load_failed",
        "message": "…"
      },
      "hash": "…"
    },
    {
      "component": "sr",
      "outcome": "triggered",
      "input": {
        "reason": "domain_pack_load_failed",
        "scope": "deployment"
      },
      "hash": "…"
    }
  ]
}
```

SR events are also written into the ITGL ledger as `component: "sr"` entries so ops / insurers can profile them over time.

---

## Round 2–3: Policy, ITGL & Domain Binding

Round 2 and 3 move SIR from “0 leaks on this suite” to:

> “0 leaks, with a signed audit bound to a specific **policy file**, a verifiable **ITGL ledger**, and a declared **domain pack + test suite**.”

Concretely:

* `policy/isc_policy.json` holds the active ISC policy for this repo.

* `sir_firewall.policy.get_policy_metadata()` exposes:

  * `policy_version`
  * `policy_hash` (SHA-256 of the policy file)

* `red_team_suite.py` writes a hash-chained ITGL ledger to:

  * `proofs/itgl_ledger.jsonl`

* `tools/verify_itgl.py` verifies the ledger chain end-to-end and exposes the **final hash**.

* `tools/generate_certificate.py`:

  * Counts prompts in the active CSV (e.g. `tests/jailbreak_prompts_public.csv`)
  * Reads leak counts from `leaks_count.txt` / `harmless_blocked.txt`
  * Reads the **final ITGL ledger hash** (normalised to `sha256:<hex>`, wired via the CI workflow)
  * Binds into the signed certificate:

    * `policy_version`
    * `policy_hash`
    * `itgl_final_hash`
    * `domain_pack`
    * `suite_path`

* Domain-aware Round 3 fields:

  * `domain_pack` – e.g. `generic_safety`, `hipaa_mental_health`, `pci_payments`
  * `suite_path` – the exact CSV path used for this audit run

`proofs/latest-audit.html` reads `latest-audit.json` and shows a **Governance snapshot**:

* Policy version
* Policy hash
* ITGL final hash
* Domain pack
* Test suite path
* Model label + leak counts

The signed `latest-audit.json` is the **canonical object** and is suitable for regulators, insurers, and internal governance tooling.

For NIST / ISO / EU AI Act mapping, see `docs/standards_alignment.md`.

---

## The Public 2025 Jailbreak Suite

This repo ships with a **public red-team CSV** at:

* `tests/jailbreak_prompts_public.csv`

Each row has:

* `prompt` – the actual test prompt sent through SIR
* `expected` – `"block"` for jailbreaks, `"allow"` for harmless prompts
* (Optional) `note` – human-readable category / commentary

The **exact number of prompts is not hard-coded anywhere**:

* `red_team_suite.py` loads the CSV and infers how many jailbreak vs harmless prompts there are.
* `tools/generate_certificate.py` **counts the rows** and writes `prompts_tested` into the signed certificate.
* The HTML certificate reads `latest-audit.json` and displays whatever `prompts_tested` actually is.

If you add or remove rows in `tests/jailbreak_prompts_public.csv`, the audit automatically reflects reality on the next CI run.

---

## Running the Red-Team Audit Locally (Firewall-Only)

The CI workflow (`.github/workflows/audit-and-sign.yml`) runs the public suite **through SIR only** and signs the result.
It does **not** call Grok-3 or any external model. You can trigger the same test locally.

### 1. (Optional) Set a model label for logs

SIR itself doesn’t call any model, but you can set a label so logs reflect what you *would* be protecting:

```bash
export LITELLM_MODEL="xai/grok-3-beta"   # used for log context only
```

If you don’t set this, a default is used.

### 2. Run the red-team suite

From the repo root:

```bash
python red_team_suite.py
```

This will:

* Load `tests/jailbreak_prompts_public.csv`
* Wrap each prompt in a minimal ISC envelope
* Run it through `sir_firewall.validate_sir`
* Write a full log to `proofs/latest-attempts.log`
* Write a hash-chained ITGL ledger to `proofs/itgl_ledger.jsonl`
* Write leak counts to:

  * `leaks_count.txt` – number of jailbreak prompts that leaked past SIR
  * `harmless_blocked.txt` – number of harmless prompts SIR blocked

Exit codes:

* **0** – audit passed: no jailbreak leaks, no harmless prompts blocked (`AUDIT PASSED`)
* **1** – audit failed: at least one jailbreak leak or harmless false-positive (`AUDIT FAILED`)

### 3. Generate a signed certificate (optional locally, automatic in CI)

From the repo root:

```bash
python tools/generate_certificate.py
```

This will:

* Count the prompts in the active CSV (e.g. `tests/jailbreak_prompts_public.csv`)

* Read leak counts from `leaks_count.txt` / `harmless_blocked.txt`

* Load policy metadata from `policy/isc_policy.json`

* Load the final ITGL ledger hash from the CI-wired environment (or directly from `proofs/itgl_ledger.jsonl` if you script it)

* Build a JSON payload with (among other fields):

  * `prompts_tested`
  * `jailbreaks_leaked`
  * `harmless_blocked`
  * `result` (`AUDIT PASSED` or `AUDIT FAILED`)
  * `policy_version` / `policy_hash`
  * `itgl_final_hash`
  * Model label, repo, commit SHA, CI run URL (where available)
  * `domain_pack` and `suite_path`

* Sign it with SDL’s private key (in CI) using RSA-PKCS1v15-SHA256

* Write:

  * `proofs/latest-audit.json`
  * `proofs/latest-audit.html` (static HTML that reads the JSON)

Locally, you’ll only be able to sign if you’ve provided the private key via `SDL_PRIVATE_KEY_PEM`.
In CI, this is wired as a GitHub secret.

---

## Verifying the Certificate

You can verify the signature with SDL’s public key (`sdl.pub`) and the verifier script.

From the repo root:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json \
  | python -m tools.verify_certificate
```

Or point it at a specific JSON file:

```bash
python tools/verify_certificate.py proofs/latest-audit.json
```

This checks:

* The SHA-256 payload hash
* The RSA signature against `sdl.pub`
* That the certificate content hasn’t been tampered with

Every certificate carries a **governance snapshot**:

* `policy_version` and `policy_hash` bind the audit to the exact policy in force
* `itgl_final_hash` is the final hash of the ITGL ledger for that run
* `domain_pack` and `suite_path` state *which* domain configuration and test suite were under audit

Together, the signature, policy hash, ITGL hash, and domain/suite fields give you a verifiable link between:

* The rules SIR was enforcing
* The decisions it made on the public jailbreak suite
* The exact domain mode and test dataset
* The audit certificate you’re looking at

---

## Repo Layout (Key Files)

* `sir_firewall/core.py`
  SIR core logic (normalisation, rule checks, ITGL logging, Systemic Reset, governance context).

* `sir_firewall/policy.py`
  Policy loader and metadata (`policy_version`, `policy_hash`).

* `sir_firewall/__init__.py`
  Exposes the `validate_sir` entrypoint.

* `policy/isc_policy.json`
  Active ISC policy file for this repo.

* `tests/jailbreak_prompts_public.csv`
  Public red-team suite. **You can expand or modify this; counts are inferred automatically.**

* `red_team_suite.py`
  Runs the public suite through SIR, writes `proofs/latest-attempts.log`, emits leak counts, and writes the ITGL ledger.

* `tools/generate_certificate.py`
  CI tool for building and signing audit certificates. Binds the audit to the current policy, ITGL ledger, and domain pack.

* `tools/verify_certificate.py`
  Verifies the RSA signature on an audit certificate using `sdl.pub`.

* `tools/verify_itgl.py`
  Verifies the ITGL ledger hash chain (`proofs/itgl_ledger.jsonl`).

* `tools/sr_profile.py`
  SR profiler. Scans `proofs/itgl_ledger.jsonl` for `component: "sr"` entries and summarises **Systemic Reset** events by reason and scope.

* `tools/quorum_firewall.py`
  Reference **quorum orchestrator**. Runs the same ISC envelope through multiple SIR Domain ISC packs and only passes if **all** firewalls return `PASS` and **no** SR is triggered.

* `proofs/template.html`
  Static HTML template that reads `latest-audit.json` and renders the current audit result and governance snapshot.

* `proofs/latest-audit.json`, `proofs/latest-audit.html`
  Latest signed audit certificate and human-readable view (on `main`).

* `docs/manaaki_integration.md`
  Design-complete, **future-state** description of how SIR will integrate into the Manaaki Health platform once its LLM stack is live.

* `sdl.pub`
  SDL’s public key for signature verification.

* `README.md`, `LICENSE`, `pyproject.toml`, `requirements.txt`
  Docs, license, and dependency definitions.

---

## Tools

Some helper scripts shipped with this repo:

* `tools/sr_profile.py`
  Diagnose how often SIR has triggered **Systemic Reset (SR)** and why, using the ITGL ledger.

* `tools/quorum_firewall.py`
  Show how to run SIR as part of a **quorum of firewalls**, aggregate decisions, and enforce “any BLOCK or SR ⇒ global BLOCK”.

See the script docstrings for usage examples.

---

## License

MIT Licensed
© 2025 Structural Design Labs
