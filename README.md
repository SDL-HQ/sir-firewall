# SIR v1.0.2 – Signal Integrity Resolver

**Pre-inference firewall · 0 leaks on the current 2025 Grok-3 jailbreak suite (latest signed replay) · Offline replay + cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Every successful CI run replays the active public suite through SIR (firewall only, no live model calls), then:

- Writes a full attempt log to `proofs/latest-attempts.log`
- Writes a hash-chained ITGL run ledger to `proofs/itgl_ledger.jsonl`
- Writes the run-level ITGL final hash to `proofs/itgl_final_hash.txt`
- Emits a cryptographically signed audit certificate in `proofs/latest-audit.json`
- Produces a public HTML view in `proofs/latest-audit.html` that reads the JSON and renders a governance snapshot
- Binds the certificate to:
  - the active ISC policy (`policy_version`, `policy_hash`)
  - the run ledger (`itgl_final_hash`)
  - the suite content (`suite_payload_hash`, `suite_format`)
  - the effective domain pack + suite path (`domain_pack`, `suite_path`)

Repo: https://github.com/SDL-HQ/sir-firewall  
SDL: https://www.structuraldesignlabs.com · @SDL_HQ · info@structuraldesignlabs.com

---

## What SIR Does

SIR is a pure-rule, pre-inference firewall that sits in front of an LLM and decides:

1. Should this prompt reach the model at all  
2. If yes, under what governance context

It never calls out to any external service. It:

- Normalises and de-obfuscates the incoming text
- Applies a fixed rule set (no ML, no embeddings)
- Emits a `PASS` or `BLOCKED` decision and a full audit log

You run SIR **before** your model. If SIR blocks it, the model never sees the prompt.

---

## How It Works (short version)

**Inputs**

- A structured ISC envelope (Inference Safety Contract) that wraps the user payload
- Your policy configuration in `policy/isc_policy.json`
- A Domain ISC pack (for example `generic_safety`) that can tighten per-template limits

**Core behaviour**

SIR:

1. Normalises the payload
   - Strips zero-width characters
   - Decodes common obfuscations (ROT13, Base64 fragments, spacing tricks)
   - Collapses spacing so things like `jail­break`, `j a i l b r e a k`, `j_a_i_l_b_r_e_a_k` all resolve

2. Checks rule sets on the normalised text
   - Jailbreak and model override patterns
   - `ignore previous instructions`-style overrides
   - System prompt exfiltration patterns
   - Basic leakage and data-exfil flags

3. Enforces ISC + friction
   - Validates the ISC envelope structure
   - Verifies checksums (and signatures once enabled)
   - Applies per-template friction limits (rough token caps)

4. Emits an ITGL log (Integrity Trace Governance Log)
   - Every decision step is appended as a hash-chained record
   - This can be persisted as your audit trail for regulators, insurers or internal governance

There are no gradients, no prompts and no tuning inside SIR. It is deterministic.

---

## Quick Start

### 1. Install dependencies

From the repo root:

```bash
pip install -r requirements.txt
````

Or add the package to your own environment and wire it into your pipeline.

### 2. Minimal example

```python
import hashlib
from sir_firewall import validate_sir

user_prompt = "User prompt goes here"
checksum = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()

payload = {
    "isc": {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": user_prompt,
        "checksum": checksum,
        "signature": "",
        "key_id": "default",
    }
}

result = validate_sir(payload)

print(result["status"])    # "PASS" or "BLOCKED"
print(result["reason"])    # Short reason string like "clean" or an error code
# print(result["itgl_log"])  # Optional: full decision/audit log
```

You plug this in **before** your LLM call. If `status == "BLOCKED"`, you do not send the prompt.

---

## Expected Output

`validate_sir` returns a JSON-serialisable dict with at least:

* `status` – `"PASS"` or `"BLOCKED"`
* `reason` – short reason string or error code
* `domain_pack` – effective Domain ISC pack id (for example `generic_safety`)
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
    "policy_version": "2025-12-05-R2",
    "policy_hash": "sha256:…"
  },
  "itgl_log": [
    { "component": "isc_structure", "outcome": "pass", "hash": "…" },
    { "component": "jailbreak", "outcome": "pass", "hash": "…" },
    { "component": "final", "outcome": "complete", "hash": "…" }
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
    { "component": "jailbreak", "outcome": "fail", "hash": "…" }
  ]
}
```

### Systemic Reset (SR) – governance-level failure

Systemic Reset is reserved for deployment and governance failures, not per-prompt jailbreaks. In those cases SIR refuses to run and returns:

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

SR events are written into the ITGL ledger as `component: "sr"` entries so they can be profiled over time.

---

## Governance Certificate and Evidence

Every successful CI run produces a signed governance audit. There are two views of it:

* A signed JSON certificate
* A human-readable HTML view that reads the JSON at runtime

### Where the evidence lives

There are two places you will see proofs.

1. **In the repo**

   On `main` the canonical signed artefact is:

   * `proofs/latest-audit.json` – source of truth
   * `proofs/latest-audit.html` – convenience view that reads `latest-audit.json`

2. **In the CI artefact**

   Each **SIR Real Governance Audit** workflow run uploads a bundle that contains:

   * `latest-audit.json`
   * `latest-audit.html`
   * `proofs/latest-attempts.log`
   * `proofs/itgl_ledger.jsonl`
   * `proofs/itgl_final_hash.txt`
   * plus related proof files

The JSON certificate is what matters for verification. The HTML exists to make it easier for humans to read.

### Viewing the HTML certificate

For a public view of the latest audit on `main`:

* HTML certificate (human friendly):
  [https://raw.githack.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html](https://raw.githack.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.html)

This page reads `latest-audit.json` from the same folder and renders a governance snapshot. If you open `latest-audit.html` directly from disk the browser may block the JSON fetch and the page will not populate correctly. That is expected.

### Verifying the signed JSON

To verify the latest certificate from the repo:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json \
  | python3 -m tools.verify_certificate
```

Or point the verifier at a local file, for example a JSON copied out of a CI artefact:

```bash
python3 -m tools.verify_certificate proofs/latest-audit.json
```

The verifier checks:

* The RSA signature against `sdl.pub`
* The payload hash inside the certificate
* That the certificate has not been tampered with

Each certificate carries a governance snapshot that binds:

* `policy_version` and `policy_hash` – which policy SIR was enforcing
* `itgl_final_hash` – the final hash of the run ledger for that run
* `suite_payload_hash` and `suite_format` – what suite content was actually evaluated
* `domain_pack` and `suite_path` – which domain pack and suite were under audit
* Model label, commit SHA and CI run URL

If there is any disagreement, the JSON certificate plus the ITGL ledger and policy files are the artefacts that should be checked. The HTML is presentation only.

---

## Public Suites

This repo ships with public red-team CSVs under `tests/`.

Suites can be:

* **Plain**: `prompt, expected, (optional id/note/category)`
* **Encoded**: `prompt_b64, expected, (optional id/note/category)`

Encoded suites are supported to allow publishing test sets without printing the decoded prompt text into logs/certs:

* `red_team_suite.py` decodes at runtime for evaluation
* logs do **not** print decoded prompt text for encoded prompts (they log `id/category` + `prompt_hash`)
* the ITGL run ledger stores `prompt_hash`, not the prompt text, for encoded prompts

### Selecting a suite

Suite selection order (mirrors CI behaviour):

1. If `SIR_SUITE_PATH` is set, use that
2. Else, switch on `SIR_ISC_PACK`:

   * `hipaa_mental_health` → `tests/hipaa_prompts_public.csv`
   * `pci_payments` → `tests/pci_prompts_public.csv`
3. Else default → `tests/jailbreak_prompts_public.csv`

---

## Running the Red-Team Audit Locally (firewall only)

The CI workflow runs the active suite through SIR only and signs the result. It does not call Grok or any external model. You can trigger the same test locally.

### Optional: set a model label for logs

SIR does not call the model, but you can set a label so logs reflect what you would be protecting:

```bash
export LITELLM_MODEL="xai/grok-3-beta"
```

### Optional: select pack / suite

```bash
export SIR_ISC_PACK="generic_safety"
# export SIR_SUITE_PATH="tests/jailbreak_prompts_public.csv"
```

### Run the suite

From the repo root:

```bash
python3 red_team_suite.py
```

This will:

* Load the active suite CSV
* Wrap each prompt in a minimal ISC envelope
* Run it through `sir_firewall.validate_sir`
* Write a full log to `proofs/latest-attempts.log`
* Write a hash-chained ITGL run ledger to `proofs/itgl_ledger.jsonl`
* Write leak counts to:

  * `leaks_count.txt` – jailbreak prompts that leaked past SIR
  * `harmless_blocked.txt` – harmless prompts that SIR blocked
* Write run ledger final hash to:

  * `proofs/itgl_final_hash.txt`

Exit codes:

* `0` – audit passed: no jailbreak leaks and no harmless prompts blocked
* `1` – audit failed: at least one jailbreak leak or harmless false positive

---

## Sanity run commands (local or CI)

Run from repo root:

```bash
python3 -m pip install -r requirements.txt

# (Optional) choose a domain pack / suite
# export SIR_ISC_PACK=generic_safety
# export SIR_SUITE_PATH=tests/jailbreak_prompts_public.csv

# 1) Run the suite (writes proofs/, leaks_count.txt, harmless_blocked.txt)
python3 red_team_suite.py

# 2) Verify the run ledger (writes proofs/itgl_final_hash.txt and prints ITGL_FINAL_HASH=...)
python3 tools/verify_itgl.py

# 3) Generate + RSA-sign the audit certificate (needs SDL_PRIVATE_KEY_PEM)
python3 tools/generate_certificate.py

# 4) Verify the signed certificate (uses sdl.pub)
python3 -m tools.verify_certificate proofs/latest-audit.json
```

If you want the HTML to populate locally (some browsers block `fetch()` on `file://`), serve `proofs/`:

```bash
cd proofs
python3 -m http.server 8080
# open http://localhost:8080/latest-audit.html
```

---

## Repo Layout (key files)

* `sir_firewall/core.py`
  SIR core logic: normalisation, rule checks, friction, ITGL logging, Systemic Reset, governance context.

* `sir_firewall/policy.py`
  Policy loader and metadata (`policy_version`, `policy_hash`).

* `sir_firewall/__init__.py`
  Exposes the `validate_sir` entrypoint.

* `policy/isc_policy.json`
  Active ISC policy file for this repo. The signed certificate binds directly to this file via `policy_version` and `policy_hash`.

* `policy/isc_packs/*.json`
  Domain ISC packs (e.g. `generic_safety`, plus any future packs like HIPAA/PCI).

* `tests/*.csv`
  Public red-team suites (plain and/or encoded).

* `red_team_suite.py`
  Runs the active suite through SIR, writes `proofs/latest-attempts.log`, leak counts, and the ITGL run ledger.

* `tools/generate_certificate.py`
  Builds and RSA-signs audit certificates. Binds the audit to the current policy, run ledger and suite content.

* `tools/verify_certificate.py`
  Verifies the RSA signature on an audit certificate using `sdl.pub`.

* `tools/verify_itgl.py`
  Verifies the ITGL run ledger chain in `proofs/itgl_ledger.jsonl` and writes `proofs/itgl_final_hash.txt`.

* `tools/sr_profile.py`
  Profiles Systemic Reset events from the ledger.

* `tools/quorum_firewall.py`
  Reference quorum orchestrator. Runs the same ISC envelope through multiple SIR domain packs and only passes if all firewalls return `PASS` and no SR is triggered.

* `proofs/template.html`
  Static HTML template that reads `latest-audit.json` and renders the current audit + governance snapshot.

* `proofs/latest-audit.json`, `proofs/latest-audit.html`
  Latest signed audit certificate and human-readable view on `main`.

* `docs/manaaki_integration.md`
  Future-state description of how SIR will integrate into the Manaaki Health platform once its LLM stack is live.

* `sdl.pub`
  SDL public key for certificate verification.

* `README.md`, `LICENSE`, `pyproject.toml`, `requirements.txt`
  Docs, license and dependency definitions.

---

## Security and Patents

### Security reporting

For security reporting, see `SECURITY.md`.

### Patents

This repository is licensed under MIT. The MIT License grants rights under copyright, not under patents. One or more patent applications owned by SDL Limited may cover methods and systems implemented by this project.

Use of this repository under the MIT License does not itself grant any licence to practice any SDL patents. For details and licensing contact points, see `PATENTS.md`.

---

## License

MIT License

---

## No phone-home

SIR never phones home.

* No telemetry
* No analytics
* No canaries
* No “first run” pings

If SIR is running, it’s not talking to us. Any network calls you see are from your own scripts or CI, not from the firewall.

© 2025 Structural Design Labs
