# SIR v1.0.2: Signal Integrity Resolver

[![SIR Real Governance Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Deterministic pre-inference governance gate · rules-only · cryptographically signed proof

Plain language: SIR sits in front of an AI model (or agent) and inspects a prompt before it reaches inference. It either lets the prompt through (PASS) or blocks it (BLOCKED) using deterministic, versioned rules.

Models provide capability. SIR makes governance enforceable and provable. It does not claim model alignment. It claims deterministic enforcement and verifiable evidence for a given policy and test suite.

SIR is built for high-stakes AI: regulated systems and agents that touch real money, real data, or real-world decisions. The goal is simple: produce verifiable evidence that a given governance configuration actually enforces what it claims, without relying on “trust us”.

Terminology note: in public/operator wording we prefer **governance gate**. Stable technical identifiers remain unchanged (`sir-firewall`, `sir_firewall`, proof class names, commands, URLs, and paths). See `docs/terminology.md`.

---

## Live proof (GitHub Pages)

These are the served pages (human trust surface). Use these links. Do not click the `.html` files in the repo browser (GitHub will show source instead of serving it).

- Latest passing audit (human page): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Latest run status (PASS / FAIL / INCONCLUSIVE): https://sdl-hq.github.io/sir-firewall/latest-run.json
- Run archive (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html

Important semantics:

- `latest-audit.*` means latest PASSING audit (last known good proof).
- `latest-run.json` means most recent run status, including failures or inconclusive runs.
- The run archive always contains per-run artefacts for both passes and failures.

---

## Quick verify (latest published proof)

Mac/Linux:

```bash
git clone https://github.com/SDL-HQ/sir-firewall.git && cd sir-firewall && \
python3 -m venv .venv && source .venv/bin/activate && \
python3 -m pip install -U pip && python3 -m pip install -e . && \
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Expected:

`OK: Certificate signature valid and payload_hash matches.`

Note on the trailing `-`: it explicitly means “read JSON from stdin” (the pipe). This is the explicit/portable form we standardise on here.

If you downloaded the file instead of piping:

```bash
python3 tools/verify_certificate.py proofs/latest-audit.json
python3 tools/validate_certificate_contract.py proofs/latest-audit.json
```

---

## Quickstart

Canonical install paths:

```bash
# audit mode
python3 -m pip install -e .

# live mode
python3 -m pip install -e ".[live]"

# verify-only (published certificate, no local run)
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Operator path (recommended):

```bash
python3 -m pip install -e .
sir run --mode audit --pack generic_safety
```

Live gating check (PASS prompts call provider):

```bash
python3 -m pip install -e ".[live]"
export XAI_API_KEY=your_xai_api_key_here
sir run --mode live --pack generic_safety
```

Windows note: if `pip install -e ".[live]"` fails due to long paths, run from a short path (e.g. `C:\sir\...`) or enable Windows long path support.

`publish_run.py` produces signed archive receipts and requires `SDL_PRIVATE_KEY_PEM`; not required for basic evaluation.

Low-level `python3 tools/...` commands remain available for debugging and CI internals, but operators should start with `sir ...`.

---

## What SIR is (and isn’t)

SIR is:

* A deterministic pre-inference governance gate that runs before an LLM sees the text
* Text-first and request-level in current capability
* Structured-envelope aware around that request path
* Pack/scenario evaluation against that request path
* Deterministic and explainable (rules-only; no embeddings, no hidden scoring)
* A proof-producing system (signed certificate + fingerprint + ITGL hash chain + per-run archives)

SIR is not:

* A post-hoc moderation layer that reacts after the model already saw the input
* A probabilistic trust score or black-box classifier
* A general alignment or ethics solution

Current boundary summary:

* No native multimodal gating
* No deep stateful conversational governance
* No native tool/function-call governance
* No internal model reasoning visibility
* No post-inference model behavior governance

For full scope boundary, failure modes, and residual-risk semantics, use `docs/assurance-kit.md` (canonical).

---

## Evidence semantics (canonical)

Evidence is defined by the versioned contract:

* Evidence contract: `spec/evidence_contract.v1.json`
* Contract validator: `tools/validate_certificate_contract.py`

Key fields:

* `proof_class` is explicit: `FIREWALL_ONLY_AUDIT`, `LIVE_GATING_CHECK`, `SCENARIO_AUDIT`
* `provider_call_attempts` counts attempted downstream calls (including retries/timeouts)
* `provider_call_successes` is informational
* `model_calls_made` is a legacy alias equal to `provider_call_attempts`
* `trust_fingerprint` is canonical; `safety_fingerprint` is retained as legacy alias

---

## Why this exists

Most “governance”, “safety”, and “compliance” claims are unverifiable. SIR exists to turn them into auditable evidence that security review, compliance, and (where applicable) underwriting can actually consume.

Accountability sits in two versioned, auditable boxes:

* Policy (domain packs): human-written, versioned rules you set
* Enforcement (SIR): deterministic gate that enforces those rules exactly and produces signed proof

Questions SIR answers with evidence:

* What suite was tested?
* What policy and configuration was enforced?
* What happened during the run (including failures)?
* Can an independent party verify the claim offline?

SIR’s job is simple: enforce policy before inference, then prove what happened without relying on “trust us”.

---

## Repo map (minimal)

* Gate core: `src/sir_firewall/`
* Domain pack suites (CSV): `tests/domain_packs/`
* Scenario packs: `tests/scenario_packs/`
* Runner: `red_team_suite.py` (writes run logs + summary + ITGL)
* Proofs (repo artefacts):

  * Signed cert (latest pointer): `proofs/latest-audit.json`
  * Human page (backed by JSON): `proofs/latest-audit.html`
  * ITGL ledger + final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
  * Run archive (passes + failures): `proofs/runs/<run_id>/...`
* Offline verification:

  * Public key: `spec/sdl.pub`
  * Cert verifier: `tools/verify_certificate.py`
  * Archive receipt verifier: `tools/verify_archive_receipt.py`

---

## Guides

* Assurance kit (canonical evaluation and verification path): `docs/assurance-kit.md`
* Evaluator technical explainer (D8 boundary/claims/residual risk): `docs/evaluator-technical-explainer.md`
* Engineer guide (local runs, signing, serving): `docs/engineer-guide.md`
* Trial guide (auditors, insurers, evidence capture): `docs/trial-guide.md`
* Key governance readiness (authority map and CRYPTO_ENFORCED checklist): `docs/key-governance-readiness.md`
* Retention / Tier B export: `RETENTION.md`

---

## Troubleshooting

If you see an error about cryptography not being installed:

```bash
python3 -m pip install cryptography
```

If you see an error that `python3` is not found, Python is not installed on this machine.

---

## Licence

MIT Licensed © 2025 Structural Design Labs

---

## Contact

[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com) · [info@structuraldesignlabs.com](mailto:info@structuraldesignlabs.com) · @SDL_HQ

```
```
