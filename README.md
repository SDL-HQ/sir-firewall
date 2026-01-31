# SIR v1.0.2: Signal Integrity Resolver

**Deterministic pre-inference governance gate · rules-only · cryptographically signed proof**

**Plain language:** SIR sits in front of an AI model (or agent) and inspects a prompt **before** it reaches inference. It either **lets the prompt through** (`PASS`) or **blocks it** (`BLOCKED`) using deterministic, versioned rules.

Models provide capability. **SIR makes governance enforceable and provable.** It does not claim model alignment. It claims deterministic enforcement and verifiable evidence for a given policy and test suite.

SIR is built for **high-stakes AI**: regulated systems and agents that touch real money, real data, or real-world decisions. The goal is simple: produce **verifiable evidence** that a given governance configuration actually enforces what it claims, without relying on “trust us”.

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

---

## Live proof (GitHub Pages)

These are the **served pages** (human trust surface). Use these links. Do not click the `.html` files in the repo browser (GitHub will show source instead of serving it).

- Latest passing audit (human page): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Run archive (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html

---

## What SIR is (and isn’t)

**SIR is:**
- A **pre-inference governance gate** that runs before an LLM sees the text
- **Deterministic and explainable** (rules-only; no embeddings, no hidden scoring)
- A **proof-producing system** (signed certificate + fingerprint + ITGL hash chain + per-run archives)

**SIR is not:**
- A post-hoc moderation layer that reacts after the model already saw the input
- A probabilistic trust score or black-box classifier
- A general alignment or ethics solution

---

## Modes of operation

- **Audit-only:** run suites and publish signed proof without affecting production traffic
- **Gating:** enforce policy in real time at ingress, `PASS` or `BLOCK` with reasons

---

## Why this exists

Most “governance”, “safety”, and “compliance” claims are unverifiable. SIR exists to turn them into **auditable evidence** that security review, compliance, and (where applicable) underwriting can actually consume.

Accountability sits in two versioned, auditable boxes:
- **Policy (domain pack):** human-written, versioned rules you set
- **Enforcement (SIR):** deterministic gate that enforces those rules exactly and produces signed proof

Questions SIR answers with evidence:
- What suite was tested?
- What policy and configuration was enforced?
- What happened during the run (including failures)?
- Can an independent party verify the claim **offline**?

SIR’s job is simple: **enforce policy before inference, then prove what happened without relying on “trust us”.**

---

## Repo map

- Gate core: `src/sir_firewall/`
- Domain pack suites (CSV): `tests/domain_packs/`
- Suite schema validator: `tools/validate_domain_pack.py`
- Runner: `red_team_suite.py` (writes run logs + summary + ITGL)
- Proofs (repo artefacts):
  - Signed cert (latest pointer): `proofs/latest-audit.json`
  - Human page (backed by JSON): `proofs/latest-audit.html`
  - ITGL ledger + final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
  - Run archive (passes + failures): `proofs/runs/<run_id>/...`
  - Local unsigned snapshot (default local runs): `proofs/local-audit.json`, `proofs/local-audit.html`
- Offline verification:
  - Public key: `spec/sdl.pub`
  - Verifier: `tools/verify_certificate.py`

Note: GitHub Pages serves the published proof surfaces at:
- `https://sdl-hq.github.io/sir-firewall/latest-audit.html`
- `https://sdl-hq.github.io/sir-firewall/runs/index.html`

---

## Quick verify (paste this)

This is the simplest way to verify the latest published certificate on a Mac or Linux machine.

Paste this into Terminal:

```bash
git clone https://github.com/SDL-HQ/sir-firewall.git && cd sir-firewall && \
python3 -m venv .venv && source .venv/bin/activate && \
python3 -m pip install -U pip && python3 -m pip install -e . && \
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py
````

Expected:

```text
OK: Certificate signature valid and payload_hash matches.
```

If you see an error about `cryptography` not being installed, run:

```bash
python3 -m pip install cryptography
```

If you see an error that `python3` is not found, Python is not installed on this machine.

---

## Guides

* Engineer guide (local runs, signing, serving): `docs/engineer-guide.md`
* Trial guide (auditors, insurers, evidence capture): `docs/trial-guide.md`

---

## Licence

MIT Licensed
© 2025 Structural Design Labs

---

## Contact

[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com) · [info@structuraldesignlabs.com](mailto:info@structuraldesignlabs.com) · @SDL_HQ

