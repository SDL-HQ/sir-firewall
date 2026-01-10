SIR v1.0.2 — Signal Integrity Resolver
Pre-inference firewall · 2025 jailbreak suite on Grok-3 · Cryptographically signed proof

Live Audit badge:
[https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Every successful CI run executes a pre-inference audit suite (firewall-only by default) and updates a signed audit certificate in:
proofs/latest-audit.json
It also publishes a public HTML page on GitHub Pages:
proofs/latest-audit.html
Backed by the same signed JSON.

Repo: [https://github.com/SDL-HQ/sir-firewall](https://github.com/SDL-HQ/sir-firewall)
SDL: [https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com) · <-- updates + live test benchmarks coming Jan/Feb 26 · @SDL_HQ

WHAT SIR DOES

SIR is a pure-rule, pre-inference firewall that sits in front of an LLM and decides:

PASS  -> safe to send to the model
BLOCKED -> rejected before the model ever sees it

It is designed to resist real-world prompt obfuscation (ROT13, base64, zero-width characters, spacing games, etc.) and is tested against hardened jailbreak suites.

This repo includes:

* The firewall core (src/sir_firewall)
* Audit suites (tests/ and tests/domain_packs/)
* A CI workflow that:

  * Runs an audit suite through SIR (firewall-only by default)
  * Writes a proof log + summary
  * Generates a signed JSON certificate in proofs/latest-audit.json
  * Publishes proofs/latest-audit.html
* Verification tools:

  * tools/verify_certificate.py to check the RSA signature with SDL’s public key (spec/sdl.pub)
  * tools/verify_itgl.py to validate the ITGL hash-chained run ledger (proofs/itgl_ledger.jsonl)

VERIFIED PROOF (ONE COMMAND)

Verify the latest published audit certificate with one command:

curl -s [https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json](https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json) | python3 -m tools.verify_certificate

Expected output:
OK: Certificate signature valid and payload_hash matches.

HTML summary page:
[https://sdl-hq.github.io/sir-firewall/latest-audit.html](https://sdl-hq.github.io/sir-firewall/latest-audit.html)

ITGL LEDGER VERIFICATION (OPTIONAL, STRONGER PROOF)

Each audit run also emits an ITGL hash-chained ledger:
proofs/itgl_ledger.jsonl
This yields a single run-level anchor:

* proofs/itgl_final_hash.txt
* embedded in the signed certificate as itgl_final_hash

Verify the ledger locally:

python3 tools/verify_itgl.py

Expected output:
ITGL_FINAL_HASH=sha256:<...>
ITGL ledger verification OK: 25 entries, final_ledger_hash=<...>

DOMAIN PACKS (SUITES)

SIR audit suites are just CSV files.

Two supported formats:

1. Plain/public suites

Columns:

* id (optional)
* prompt
* expected (allow or block)
* note (optional)
* category (optional)

Example:
tests/jailbreak_prompts_public.csv

2. Sensitive/encoded suites

Columns:

* id
* prompt_b64 (base64-encoded UTF-8 prompt)
* expected (allow or block)
* note (optional)
* category (optional)

Examples live under:
tests/domain_packs/

The point of prompt_b64 is simple: the suite is still deterministic and testable, but the raw prompt text isn’t sitting in plaintext in the repo.

RUNNING THE RED-TEAM AUDIT LOCALLY

CI runs a firewall-only audit automatically. You can run the same harness yourself.

Firewall-only mode (recommended / matches CI default):

python3 red_team_suite.py --no-model-calls

Run a specific domain pack:

python3 red_team_suite.py --suite tests/domain_packs/generic_safety.csv --no-model-calls
python3 red_team_suite.py --suite tests/domain_packs/mental_health_clinical.csv --no-model-calls

Outputs:

* proofs/latest-attempts.log (human readable)
* proofs/run_summary.json (machine readable; generated during runs)
* leaks_count.txt + harmless_blocked.txt (back-compat)
* proofs/itgl_ledger.jsonl + proofs/itgl_final_hash.txt (ITGL run ledger + anchor)

Optional: live model-call mode (integration testing)

If you want to prove the firewall is actively gating real calls, run without --no-model-calls.
This is not required for certificate verification and is typically used for manual integration tests only.

LiteLLM will look for the relevant provider key (see LiteLLM docs). For xAI this is commonly:

export XAI_API_KEY="your_key_here"
python3 red_team_suite.py --suite tests/domain_packs/generic_safety.csv

CERTIFICATE GENERATION (CI / SIGNING)

Most users only ever need to verify the published certificate, not generate one.

In CI, the signer runs:

python3 tools/generate_certificate.py

It produces:

* proofs/latest-audit.json
* proofs/latest-audit.html
* proofs/audit-certificate-<timestamp>.json (archival)

FILES & LAYOUT (QUICK MAP)

.github/workflows/audit-and-sign.yml
CI pipeline -> runs audit suite through SIR (firewall-only by default), verifies ITGL, generates+signs cert, updates latest-audit files.

src/sir_firewall/
SIR core logic (normalisation, rule checks, validate_sir entry point).

red_team_suite.py
Audit harness. Reads a suite CSV, runs SIR gating, and writes proofs/run_summary.json.

tests/jailbreak_prompts_public.csv
Public 2025 reference prompts.

tests/domain_packs/
Additional suites (including base64-encoded packs).

proofs/

* latest-audit.json  (current signed certificate)
* latest-audit.html  (HTML view backed by latest-audit.json)
* template.html      (HTML template used by the signer)
* itgl_ledger.jsonl  (per-prompt hash-chained run ledger)
* itgl_final_hash.txt (run-level ITGL final hash: sha256:<hex>)

tools/

* verify_certificate.py  (verifies payload_hash + RSA signature using spec/sdl.pub)
* verify_itgl.py         (verifies ITGL ledger structure + chain integrity and emits ITGL_FINAL_HASH)
* generate_certificate.py (CI signer)

spec/sdl.pub
SDL public key used for verifying signatures.

LICENSE

MIT Licensed
© 2025 Structural Design Labs
