# SIR: Signal Integrity Resolver Version 2.1

[![SIR Real Governance Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Deterministic pre-inference governance gate · rules-only · cryptographically signed proof

Plain language: SIR sits in front of an AI model or agent and inspects a prompt before it reaches inference. It either lets the prompt through (`PASS`) or blocks it (`BLOCK`) using deterministic, versioned rules.

Models provide capability. SIR makes governance enforceable and provable. It does not claim model alignment. It claims deterministic enforcement and verifiable evidence for a given policy and test suite.

SIR is built for high-stakes AI systems that touch real money, real data, or real-world decisions. The goal is simple: produce verifiable evidence that a given governance configuration actually enforces what it claims, without relying on "trust us".

Terminology note: in public and operator wording we prefer **governance gate**. Stable technical identifiers remain unchanged (`sir-firewall`, `sir_firewall`, proof class names, commands, URLs, and paths). See `docs/terminology.md`.

---

## Live proof (GitHub Pages)

These are the served pages (human trust surface). Use these links. Do not click the `.html` files in the repo browser because GitHub will show source instead of serving it.

- Latest passing audit (human page): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Latest run status (PASS / FAIL / INCONCLUSIVE): https://sdl-hq.github.io/sir-firewall/latest-run.json
- Run archive (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html

Important semantics:

- `latest-audit.*` means latest passing audit (last known good proof).
- `latest-run.json` means most recent run status, including failures or inconclusive runs.
- The run archive always contains per-run artefacts for both passes and failures.
- Gate outcome (`PASS` / `BLOCK`) is distinct from run/publication status (`PASS` / `FAIL` / `INCONCLUSIVE`).
- `latest-audit.*` and `latest-run.*` are single-run truth surfaces, not paired benchmark claims.
- Procedural cold-start path: `docs/minimal-pilot-runbook.md`
- Evaluation and interpretation path: `docs/evaluator-technical-explainer.md`

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

`OK: payload_hash matches reconstructed signed payload and signature verifies against ...; this proves payload integrity + signature validity only (not policy correctness, model safety, or broader trust guarantees).`

Verification scope note: certificate verification is cryptographic integrity checking of signed payload bytes against the relevant public key material (`signing_key_id` via registry when resolvable, otherwise explicit `--pubkey`). It does not prove policy correctness, model safety, deployment completeness, or broader organizational trust posture.

Note on the trailing `-`: it explicitly means "read JSON from stdin" (the pipe). This is the explicit and portable form we standardise on here.

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

Source-tree bootstrap fallback (no editable install; useful for restricted or offline environments):

```bash
PYTHONPATH=src python3 red_team_suite.py --suite tests/domain_packs/generic_safety.csv --no-model-calls
```

Expected smoke result for `generic_safety`: `Leaks: 0 | Harmless blocked: 0`

Live gating check (PASS prompts call provider):

```bash
python3 -m pip install -e ".[live]"

# xAI example
export XAI_API_KEY=your_xai_api_key_here
sir run --mode live --pack generic_safety --provider xai --model grok-4-1-fast

# OpenAI example
export OPENAI_API_KEY=your_openai_api_key_here
sir run --mode live --pack generic_safety --provider openai --model gpt-5.4-mini
```

Windows note: if `pip install -e ".[live]"` fails due to long paths, run from a short path such as `C:\sir\...` or enable Windows long path support.

Current supported provider and model selection is documented in `docs/model-selection.md`.

`publish_run.py` produces signed archive receipts and requires `SDL_PRIVATE_KEY_PEM`; this is not required for basic evaluation.

Low-level `python3 tools/...` commands remain available for debugging and CI internals, but operators should start with `sir ...`.

---

## What SIR is (and isn’t)

SIR is:

* A deterministic pre-inference governance gate that runs before an LLM sees the text
* Primarily text-first at the request path, with bounded first-wave support for structured and tool-result ingress
* Structured-envelope aware around that request path
* Pack and scenario evaluation against that request path
* Deterministic and explainable (rules-only; no embeddings, no hidden scoring)
* A proof-producing system (signed certificate, fingerprint, ITGL hash chain, and per-run archives)

SIR is not:

* A post-hoc moderation layer that reacts after the model already saw the input
* A probabilistic trust score or black-box classifier
* A general alignment or ethics solution
* Native multimodal governance
* Deep stateful conversational governance
* Native full tool or function-call governance
* Internal model reasoning visibility
* Post-inference model behavior governance

For current scope boundary, failure modes, and residual-risk semantics, use `docs/assurance-kit.md`.

---

## Evidence semantics (canonical)

Evidence is defined by the versioned contract:

* Evidence contract: `spec/evidence_contract.v1.json`
* Contract validator: `tools/validate_certificate_contract.py`

Key fields:

* `proof_class` is explicit: `FIREWALL_ONLY_AUDIT`, `LIVE_GATING_CHECK`, `SCENARIO_AUDIT`
* `provider_call_attempts` counts attempted downstream calls, including retries and timeouts
* `provider_call_successes` is informational
* `model_calls_made` is a legacy alias equal to `provider_call_attempts`
* `trust_fingerprint` is canonical; `safety_fingerprint` is retained as a legacy alias

---

## Why this exists

Most "governance", "safety", and "compliance" claims are unverifiable. SIR exists to turn them into auditable evidence that security review, compliance, and, where applicable, underwriting can actually consume.

Accountability sits in two versioned, auditable boxes:

* Policy (domain packs): human-written, versioned rules you set
* Enforcement (SIR): deterministic gate that enforces those rules exactly and produces signed proof

Questions SIR answers with evidence:

* What suite was tested?
* What policy and configuration was enforced?
* What happened during the run, including failures?
* Can an independent party verify the claim offline?

SIR’s job is simple: enforce policy before inference, then prove what happened without relying on "trust us".

---

## Repo map (minimal)

* Gate core: `src/sir_firewall/`
* Domain pack suites (CSV): `tests/domain_packs/`
* Scenario packs: `tests/scenario_packs/`
* Runner: `red_team_suite.py` (writes run logs, summary, and ITGL)
* Proofs (repo artefacts):

  * Signed cert (latest pointer): `proofs/latest-audit.json`
  * Human page (backed by JSON): `proofs/latest-audit.html`
  * ITGL ledger and final hash: `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`
  * Run archive (passes + failures): `proofs/runs/<run_id>/...`
* Offline verification:

  * Public key: `spec/sdl.pub`
  * Cert verifier: `tools/verify_certificate.py`
  * Archive receipt verifier: `tools/verify_archive_receipt.py`

---

## Guides

* [Minimal pilot runbook](docs/minimal-pilot-runbook.md) (procedural cold-start path)
* [Evaluator technical explainer](docs/evaluator-technical-explainer.md) (evaluation and interpretation path)
* [Assurance kit](docs/assurance-kit.md) (supporting evaluation and verification reference)
* [Evidence perimeter note](docs/evidence-perimeter.v2.md) (current bounded benchmark perimeter)
* [External technical review preparation](docs/external-technical-review-prep.md)
* [Engineer guide](docs/engineer-guide.md) (local runs, signing, serving)
* [Trial guide](docs/trial-guide.md) (auditors, insurers, evidence capture)
* [Key governance readiness](docs/key-governance-readiness.md) (authority map and `CRYPTO_ENFORCED` checklist)
* [Release notes](docs/release-notes-2.1.md) (2.1 closeout)
* [Retention / Tier B export](RETENTION.md)

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
