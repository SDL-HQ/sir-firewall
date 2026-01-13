# SIR v1.0.2 — Signal Integrity Resolver

**Deterministic pre-inference governance gate · rules-only · cryptographically signed proof**

**Plain language:** SIR sits *in front of* an AI model (or agent) and inspects a prompt **before** it reaches inference. It either **lets the prompt through** (`PASS`) or **blocks it** (`BLOCKED`) using deterministic, versioned rules.

SIR is built for **high-stakes AI**: regulated systems and agents that touch real money, real data, or real-world decisions. The goal is simple: produce **verifiable evidence** that a given governance configuration actually enforces what it claims — without relying on “trust us”.

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

---

## Live proof (GitHub Pages)

These are the **served pages** (human trust surface). Use these links — **do not** click the `.html` files in the repo browser (GitHub will show source instead of serving it).

- Latest passing audit (human page): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Run archive (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html

---

## What SIR is (and isn’t)

**SIR is:**
- A **pre-inference governance gate** (sometimes described as a “firewall”) that runs *before* an LLM sees the text
- **Deterministic and explainable** (rules-only; no embeddings, no hidden scoring)
- A **proof-producing system** (signed certificate + fingerprint + ITGL hash chain + per-run archives)

**SIR is not:**
- A post-hoc “moderation” layer that reacts after the model already saw the input
- A probabilistic “trust score” or black-box classifier
- A magic alignment solution for all harms

---

## Why this exists

Most “governance”, “safety”, and “compliance” claims are unverifiable. SIR exists to turn them into **auditable evidence** — the kind that security review, compliance, and (where applicable) underwriting can actually consume:

- What suite was tested?
- What policy/config was enforced?
- What happened during the run (including failures)?
- Can an independent party verify the claim **offline**?

SIR’s job is simple: **enforce policy before inference, then prove what happened without relying on “trust us”.**

---

## End-state design goals (current direction)

- **Gate core:** deterministic, rules-only, explainable.
- **Suites (domain packs):** curated, versioned, testable, portable.
- **Proof system:**
  - Signed certificate (who issued it, what it claims)
  - Fingerprint (what configuration + result set it binds to)
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

- Gate core: `src/sir_firewall/`
- Domain pack suites (CSV): `tests/domain_packs/`
- Suite schema validator: `tools/validate_domain_pack.py`
- Runner: `red_team_suite.py` (writes run logs + summary + ITGL)
- Proofs (repo artifacts):
  - Signed cert (latest pointer): `proofs/latest-audit.json`
  - Human page (backed by JSON): `proofs/latest-audit.html`
  - ITGL ledger + final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
  - Run archive (passes + failures): `proofs/runs/<run_id>/...`
  - Local unsigned snapshot (default local runs): `proofs/local-audit.json`, `proofs/local-audit.html`
- Offline verification:
  - Public key: `spec/sdl.pub`
  - Verifier: `tools/verify_certificate.py`

> Note: GitHub Pages serves the published proof surfaces at:
> `https://sdl-hq.github.io/sir-firewall/latest-audit.html` and `https://sdl-hq.github.io/sir-firewall/runs/index.html`.

---

## Offline verification (auditors / regulators / engineers)

### Verify the latest published certificate (offline)

1) Clone + install:

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

* `latest-audit.html` + `latest-audit.json` represent the **latest passing audit pointer**
* `runs/` is the **truth-preserving run archive** (passes + failures)

Use the served pages:

* [https://sdl-hq.github.io/sir-firewall/latest-audit.html](https://sdl-hq.github.io/sir-firewall/latest-audit.html)
* [https://sdl-hq.github.io/sir-firewall/runs/index.html](https://sdl-hq.github.io/sir-firewall/runs/index.html)

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
* suite execution (default: gate-only, no model calls)
* ITGL verification + export
* optional signing + cert generation
* run archive publish
* optional local HTTP server (so HTML loads)

### Default (gate-only, no signing)

This produces a **LOCAL UNSIGNED snapshot** (so there’s no confusion with CI / SDL-signed proofs):

* `proofs/local-audit.json`
* `proofs/local-audit.html`

```bash
python tools/local_audit.py --suite tests/domain_packs/generic_safety.csv
```

### Generate a locally signed cert (dev/test key, not SDL)

This produces:

* `proofs/latest-audit.json`
* `proofs/latest-audit.html`
* plus `local_keys/local_signing_key*.pem`

```bash
python tools/local_audit.py --suite tests/domain_packs/generic_safety.csv --sign local
```

Verify the locally signed cert:

```bash
python tools/verify_certificate.py proofs/latest-audit.json --pubkey local_keys/local_signing_key.pub.pem
```

### Serve the HTML locally (avoids `file://` fetch restrictions)

```bash
python tools/local_audit.py --suite tests/domain_packs/generic_safety.csv --serve
```

Then open:

* Default (`--sign none`): `http://localhost:8000/proofs/local-audit.html`
* Local-signed (`--sign local`): `http://localhost:8000/proofs/latest-audit.html`
* Run archive: `http://localhost:8000/proofs/runs/index.html`

---

## Notes on local HTML viewing

`local-audit.html`, `latest-audit.html`, and `runs/index.html` load JSON via `fetch()`.
If you open them via `file://`, many browsers will block JSON loading.

Serve the repo over HTTP instead:

```bash
python -m http.server 8000
```

---

## License

MIT Licensed
© 2025 Structural Design Labs

---

## Contact

[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com) · [info@structuraldesignlabs.com](mailto:info@structuraldesignlabs.com) · @SDL_HQ
