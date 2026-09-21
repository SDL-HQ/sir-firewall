# SIR: Signal Integrity Resolver Version 2.3.4

[![SIR Real Governance Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)

Deterministic pre-inference governance gate · rules-only · cryptographically signed proof

Plain language: SIR sits in front of an AI model or agent and inspects a prompt before it reaches inference. It either lets the prompt through (`PASS`) or blocks it (`BLOCKED`) using deterministic, versioned rules.

Models provide capability. SIR makes governance enforceable and provable. It does not claim model alignment. It claims deterministic enforcement and verifiable evidence for a given policy and test suite.

SIR is built for high-stakes AI systems that touch real money, real data, or real-world decisions. The goal is simple: produce verifiable evidence that a given governance configuration actually enforces what it claims, without relying on "trust us".

Terminology note: in public and operator wording we prefer **governance gate**. Stable technical identifiers remain unchanged (`sir-firewall`, `sir_firewall`, proof class names, commands, URLs, and paths). See `docs/terminology.md`.

---

## Live proof (GitHub Pages)

These are the served pages (human trust surface). Use these links. Do not click the `.html` files in the repo browser because GitHub will show source instead of serving it.

- Latest passing audit (human page): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Latest live/model-in-loop audit (human page): https://sdl-hq.github.io/sir-firewall/latest-live-audit.html
- Latest run status (PASS / FAIL / INCONCLUSIVE): https://sdl-hq.github.io/sir-firewall/latest-run.json
- Run archive (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html

Important semantics:

- `latest-audit.*` means latest passing audit (last known good proof).
- `latest-live-audit.*` means the latest attributable `LIVE_GATING_CHECK` with at least one successful provider call, regardless of result.
- `latest-run.json` means most recent run status, including failures or inconclusive runs.
- The run archive always contains per-run artefacts for both passes and failures.
- Gate request status (`PASS` / `BLOCKED`) is distinct from run/publication status (`PASS` / `FAIL` / `INCONCLUSIVE`).
- `latest-audit.*` and `latest-run.*` are single-run truth surfaces, not paired benchmark claims.
- Procedural cold-start path: `docs/minimal-pilot-runbook.md`
- Evaluation and interpretation path: `docs/evaluator-technical-explainer.md`

---

## Verify a published evidence package

Verification answers three separate questions:

1. **Were these bytes signed by this key?** Run `verify_certificate.py`
   without `--ledger`. This proves only signed-payload integrity and is the
   only available verification for certificates earlier than SIR 2.3.4.
2. **Do these signed bytes name this log?** For SIR 2.3.4 and later, run
   `verify_certificate.py --ledger` with that run archive's own ledger. This is
   the documented default.
3. **Did this run mean what its result says?** That requires separate run
   accounting and semantic review; it is outside certificate/ledger binding.

### Quick verify (SIR 2.3.4 or later run archive)

Mac/Linux:

```bash
git clone https://github.com/SDL-HQ/sir-firewall.git && cd sir-firewall && \
python3 -m venv .venv && source .venv/bin/activate && \
python3 -m pip install -U pip && python3 -m pip install -e . && \
RUN_ID=<2.3.4-or-later-run-id> && \
python3 tools/verify_certificate.py "docs/runs/${RUN_ID}/audit.json" \
  --ledger "docs/runs/${RUN_ID}/proofs/itgl_ledger.jsonl"
```

Expected:

`OK: payload_hash matches reconstructed signed payload and signature verifies against ...; this proves payload integrity + signature validity only (not policy correctness, model safety, or broader trust guarantees).`

Without `--ledger`, certificate verification is only cryptographic integrity
checking of signed payload bytes against relevant public-key material. With
`--ledger`, it additionally checks that the signed hash and prompt count name
that chain-valid log. Neither form proves policy correctness, run-accounting
correctness, model safety, deployment completeness, or organizational trust.

For a pre-2.3.4 certificate, or when asking only the narrower signature
question, omit `--ledger`:

```bash
python3 tools/verify_certificate.py proofs/latest-audit.json
python3 tools/validate_certificate_contract.py proofs/latest-audit.json
```

Evidence contract v1 applies to `sir_firewall_version` 2.2.0 and later. The
contract validator exits `8` with a `NOT APPLICABLE` message for older or
unversioned certificates; this is distinct from exit `2`, which reports a
genuine violation by an in-scope certificate.

### Standalone verifier dependencies

The verifier tools do not require installing `sir_firewall`. A minimal copied
verification bundle needs `tools/verify_certificate.py`, `tools/verify_itgl.py`,
`tools/itgl.py`, `tools/key_registry.py`, `spec/sdl.pub`,
`spec/pubkeys/key_registry.v1.json`, and
`spec/pubkeys/key_registry.v1.schema.json`, plus the certificate and ledger.
Python's `cryptography` package is required. The key-registry module and schema
are pre-existing dependencies of certificate verification.

The root-level `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`,
`proofs/run_id.txt`, and `proofs/run_summary.json` are mutable compatibility
copies for older tooling. They are not evidence; verify against the artifacts
inside the identity-matched per-run archive.

### Positive and negative verification examples

| Valid signed certificate | Deliberately invalid certificate |
|---|---|
| `python3 tools/verify_certificate.py proofs/latest-audit.json` | `python3 tools/verify_certificate.py examples/verifier-negatives/tampered-leak-count.json` |
| Prints `OK: payload_hash matches reconstructed signed payload and signature verifies ...` | Refuses with `ERROR: payload_hash mismatch` and exit code `3` |

`verify_certificate.py` uses exit code `7` specifically when `--ledger` chain
verification or the signed terminal-hash/row-count binding fails. Codes `2`–`6`
retain their existing certificate and signature failure meanings.

The same deliberately invalid certificate demonstrates why consumers must run both tools:

```bash
python3 tools/validate_certificate_contract.py examples/verifier-negatives/tampered-leak-count.json
# OK: certificate satisfies evidence contract v1.

python3 tools/verify_certificate.py examples/verifier-negatives/tampered-leak-count.json
# ERROR: payload_hash mismatch
```

The contract validator establishes shape and required fields, while the verifier establishes integrity and authenticity. See [`examples/verifier-negatives/`](examples/verifier-negatives/) for all five deliberately invalid examples and their exact diagnostics.

---

## Quickstart

**Installation support boundary:** The `sir` console command is supported only from an editable installation of a complete repository checkout (`python3 -m pip install -e .`). The CLI reads committed policy, registry, suite, tool, and proof-template files from repository-relative paths. A wheel or non-editable `pip install .` is not a supported relocatable runtime installation. Running `sir` after moving or deleting the checkout used by the editable installation is unsupported.

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
sir run --mode live --pack generic_safety --provider xai --model grok-4.3

# OpenAI example
export OPENAI_API_KEY=your_openai_api_key_here
sir run --mode live --pack generic_safety --provider openai --model gpt-5.4-mini
```

Windows note: if `pip install -e ".[live]"` fails due to long paths, run from a short path such as `C:\sir\...` or enable Windows long path support.

Current supported provider and model selection is documented in `docs/model-selection.md`.

`publish_run.py` produces signed archive receipts and requires `SDL_PRIVATE_KEY_PEM`; this is not required for basic evaluation.

Low-level `python3 tools/...` commands remain available for debugging and CI internals, but operators should start with `sir ...`.

`sir packs list` reports public registry entries. It does not guarantee that a same-named ISC policy pack exists; see `tests/domain_packs/README.md` for the current execution constraint.

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
* `trust_fingerprint` is canonical. `safety_fingerprint` is a deprecated legacy
  alias retained through the 2.x line and scheduled for removal in SIR 3.0.0;
  consumers must migrate to `trust_fingerprint` before upgrading to 3.0.0.

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
  * Latest live certificate and human page: `proofs/latest-live-audit.json`, `proofs/latest-live-audit.html`
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
* [Compliance evidence map](docs/compliance-evidence-map.md) (reviewer-facing evidence packaging map)
* [Evidence perimeter note](docs/evidence-perimeter.v5.md) (current bounded benchmark perimeter)
* [Threat model](docs/threat-model.md) (trust, integration, verification, retention, and control boundaries)
* [Failure modes](docs/failure-modes.md) (fail-closed verdicts, escaped exceptions, and process boundaries)
* [Rule-coverage report](docs/rule-coverage.md) (deterministic and full-gate benchmark coverage)
* [OWASP LLM Top 10 2026 mapping](docs/owasp-llm-top-10-2026.md) (version-stamped control mapping)
* [Public backlog](docs/backlog.md) (known constraints and planned hardening)
* [External technical review preparation](docs/external-technical-review-prep.md)
* [Engineer guide](docs/engineer-guide.md) (local runs, signing, serving)
* [Trial guide](docs/trial-guide.md) (auditors, insurers, evidence capture)
* [Key governance readiness](docs/key-governance-readiness.md) (authority map and `CRYPTO_ENFORCED` checklist)
* [SIR 2.3.4 release notes](docs/release-notes-2.3.4.md) (evidence-binding correction)
* [SIR 2.3.3 release notes](docs/release-notes-2.3.3.md) (generic systemic-reset audit accounting)
* [SIR 2.3.2 release notes](docs/release-notes-2.3.2.md) (parser symmetry and registry cleanup)
* [SIR 2.3.1 release notes](docs/release-notes-2.3.1.md) (failure-mode hardening)
* [SIR 2.3.0 release notes](docs/release-notes-2.3.0.md) (systemic-reset audit accounting)
* [SIR 2.2.1 release notes](docs/release-notes-2.2.1.md) (generative validation tests and CI dependency hygiene)
* [SIR 2.2.0 release notes](docs/release-notes-2.2.md) (2.2 closeout)
* [Retention / Tier B export](RETENTION.md)
* [Security policy](SECURITY.md)
* [Archive](docs/archive/README.md) (archived and superseded documents)

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
