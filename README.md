# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · deterministic rules-only governance gate · cryptographically signed proof**

**Plain language:** SIR sits *in front of* an AI model and inspects a prompt **before** it ever reaches the model. It either **lets the prompt through** (`PASS`) or **blocks it** (`BLOCKED`) using deterministic rules. The goal is simple: prove—using verifiable evidence—that a given safety/governance configuration actually blocks known jailbreak and policy-bypass attempts, without relying on “trust us”.

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

---

## What SIR is (and isn’t)

**SIR is:**
- A **pre-inference firewall** (runs before an LLM sees the text)
- **Deterministic and explainable** (rules-only; no embeddings, no hidden scoring)
- A **proof-producing system** (signed certificate + safety fingerprint + ITGL ledger + per-run archive)

**SIR is not:**
- A post-hoc “moderation” layer that reacts after the model already saw the input
- A magic alignment solution for all harms
- A black-box classifier

---

## Why this exists

“Governance” claims are just vibes. SIR is built to make them **verifiable**:
- What suite was tested?
- What policy/config was used?
- What happened during the run?
- Can an auditor verify the claims offline?

---

## End-state design goals (current direction)

- **Firewall core:** deterministic, rules-only, explainable.
- **Suites (domain packs):** curated, versioned, testable, portable.
- **Proof system:**
  - Signed certificate (who issued it, what it claims)
  - Safety fingerprint (what configuration + result set it binds to)
  - ITGL ledger (how the run unfolded, hash chained)
  - Per-run archive (nothing disappears, failures included)
- **Two trust surfaces:**
  - Public GitHub Pages summary for humans
  - Offline verification for engineers and auditors
- **Integration evidence:**
  - Optional live gating runs that prove enforcement, not just claims

---

## Runtime requirements (important)

**Python 3.11+ is required.**

CI runs Python 3.11, and the codebase uses Python 3.10+ syntax. If you run Python 3.9 locally, it will fail.

---

## Repo map

- Firewall core: `src/sir_firewall/`
- Domain pack suites (CSV): `tests/domain_packs/`
- Suite schema validator: `tools/validate_domain_pack.py`
- Runner: `red_team_suite.py` (writes run logs + summary + ITGL)
- Proofs:
  - Signed cert (latest pointer): `proofs/latest-audit.json`
  - Human page (backed by JSON): `proofs/latest-audit.html`
  - ITGL ledger + final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
  - Run archive (passes + failures): `proofs/runs/<run_id>/...`
- Offline verification:
  - Public key: `spec/sdl.pub`
  - Verifier: `tools/verify_certificate.py`

---

## Offline verification (auditors / regulators / engineers)

### Verify the latest published certificate (offline)

1) Clone + install deps:

```bash
git clone https://github.com/SDL-HQ/sir-firewall.git
cd sir-firewall
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
````

2. Verify the published cert (no network beyond the download):

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json \
  | python tools/verify_certificate.py
```

Expected:

```text
OK: Certificate signature valid and payload_hash matches.
```

### Verify a specific cert file

```bash
python tools/verify_certificate.py proofs/latest-audit.json
```

### Verify using a different public key (local test signing)

```bash
python tools/verify_certificate.py proofs/latest-audit.json --pubkey local_keys/local_signing_key.pub.pem
```

> Note: You can also run the verifier as a module (`python -m tools.verify_certificate`) if your environment supports it, but the file-path form above is the most portable.

---

## Two trust surfaces

### 1) Public human summary (GitHub Pages)

* `docs/latest-audit.html` + `docs/latest-audit.json` are the **latest passing audit pointer**
* `docs/runs/` is the **truth-preserving run archive** (passes + failures)

### 2) Offline verification for engineers and auditors

* Download the JSON certificate
* Verify signature + payload hash using `tools/verify_certificate.py` and `spec/sdl.pub`
* Inspect governance anchors (policy hash/version, suite hash, ITGL final hash, fingerprint)

---

## Local install (Mac / Linux)

Recommended (matches CI):

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
python --version
```

You want: **Python 3.11.x**

---

## Run the audit locally (one command)

`tools/local_audit.py` runs the same path people normally trip over:

* suite schema validation
* suite execution (default: firewall-only, no model calls)
* ITGL verification + export
* optional signing + cert generation
* run archive publish
* optional local HTTP server (so HTML loads)

### Default (firewall-only, no signing)

```bash
python tools/local_audit.py --suite tests/domain_packs/generic_safety.csv
```

### Generate a locally signed cert (dev/test key, not SDL)

```bash
python tools/local_audit.py --suite tests/domain_packs/generic_safety.csv --sign local
```

### Serve the HTML locally (avoids `file://` fetch restrictions)

```bash
python tools/local_audit.py --suite tests/domain_packs/generic_safety.csv --serve
```

Then open:

* `http://localhost:8000/proofs/latest-audit.html`
* `http://localhost:8000/proofs/runs/index.html`

---

## Notes on local HTML viewing

`latest-audit.html` and `runs/index.html` load JSON via `fetch()`.
If you open them via `file://`, many browsers will block JSON loading.

Serve the repo over HTTP instead:

```bash
python -m http.server 8000
```

---

## License

MIT Licensed
© 2025 Structural Design Labs
