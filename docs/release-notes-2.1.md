# Release Notes 2.1

## Overview

Version 2.1 brings SIR to a more stable, clearer, and more reviewable state without changing its core philosophy.

SIR remains a deterministic pre-inference governance gate with rules-only enforcement, signed proof, and truth-preserving archive semantics. This release tightens coherence across operator paths, trust surfaces, structured ingress work, tool-result ingress work, and benchmark/archive publication behavior.

This is not a product-shape rewrite. It is a consolidation release that improves correctness, usability, and trust-surface integrity.

---

## What changed in 2.1

### 1. Trust-surface and publication coherence

SIR 2.1 tightens the relationship between the canonical public proof surfaces:

- `latest-audit.*` remains the latest conclusive passing proof
- `latest-run.*` remains the most recent run status, including failures or inconclusive runs
- run archive and benchmark indexes continue to preserve per-run truth

This release includes workflow fixes so benchmark publication paths do not leave `latest-run.*` or `latest-audit.*` behind when archive/index truth has moved forward.

### 2. Evidence and reviewability improvements

SIR 2.1 strengthens audit readability and evidence clarity through additive improvements such as:

- pack identity binding in runtime/evidence context
- PASS-path deterministic rule-family explainability
- explicit obfuscation signal reporting
- bundle-local human-readable audit reporting
- lightweight monitoring summary surface derived from run archive truth

These changes improve reviewability without changing the underlying deterministic enforcement model.

### 3. Operator and integration usability

SIR 2.1 improves the normal operator path by making the current usage model easier to understand and apply:

- `validate_text(...)` thin wrapper for simpler raw-text integration
- clearer offline-capable operator path documentation
- clearer integration patterns for:
  - Python middleware
  - containerised sidecar deployment
  - agentic pipeline pre-call wrapper

The goal was to reduce friction without introducing a second engine or weakening the current boundary model.

### 4. Structured governance first-wave expansion

Structured governance support is still intentionally bounded, but 2.1 moves it beyond a single-pack proof point.

The current supported structured declaration is now proven across:

- `generic_safety`
- `support_operator_override`
- `data_exfiltration_pressure`

This keeps:

- one supported structured schema
- one deterministic engine
- one fail-closed model

It does not introduce a generic multi-schema platform.

### 5. Tool-result ingress first-wave support

SIR 2.1 includes first-wave support for bounded `tool_result` ingress in the same `validate_sir()` engine.

This includes:

- explicit `tool_result` ingress path
- fail-closed validation
- bounded content-length enforcement
- exploratory coverage
- improved PASS-path provenance for tool-result handling

This is intentionally bounded. It is not full native tool/function-call governance.

### 6. Benchmark/dashboard coherence tightening

Pair data and deltas are now surfaced more coherently in benchmark display layers, without changing benchmark data generation or index semantics.

This release keeps benchmark/archive truth model semantics intact while improving the clarity of visible paired benchmark output.

### 7. Human-facing terminology cleanup

Public and operator-facing wording now aligns more consistently with the preferred terminology:

- **governance gate** for human-facing wording
- stable machine and compatibility identifiers retained unchanged

This means identifiers such as:

- `sir-firewall`
- `sir_firewall`
- `sir_firewall_version`
- `FIREWALL_ONLY_AUDIT`

remain stable, while human-facing labels and titles are cleaner and more consistent.

---

## What did not change

SIR 2.1 does **not** change the core truth model.

It remains true that:

- `latest-audit.*` is the latest passing proof, not the latest run of any kind
- `latest-run.*` is the latest run status, including failures and inconclusive runs
- archive/index surfaces preserve pass and non-pass history
- proof verification remains cryptographic integrity verification, not a claim of policy correctness or model safety
- SIR remains deterministic and rules-only
- SIR does not claim general alignment, ethics, or full model-governance coverage

Stable machine identifiers, proof class values, schema keys, package names, and path identities were intentionally preserved.

---

## Current capability boundary

SIR 2.1 is stronger and clearer than 2.0, but its current boundary remains intentional.

SIR is currently:

- pre-inference
- deterministic
- request-path focused
- primarily text-first
- proof-producing
- archive-preserving

SIR 2.1 still does **not** provide:

- native multimodal governance
- deep stateful conversational governance
- internal model reasoning visibility
- full native tool/function-call governance
- post-inference model behavior governance

Structured ingress and tool-result ingress are first-wave bounded additions, not a shift into broad orchestration or agent-platform scope.

---

## Trust and verification

For operators, reviewers, and auditors, the important point in 2.1 is not just “more features”.

It is that the trust surfaces are now more coherent and easier to interpret:

- latest-pass
- latest-run
- run archive
- benchmark archive/index
- offline verification
- signed proof artifacts

remain aligned to the same evidence-first model.

Use the current docs set for the intended paths:

- procedural cold start: `docs/minimal-pilot-runbook.md`
- evaluation and interpretation: `docs/evaluator-technical-explainer.md`
- supporting evaluation/verification reference: `docs/assurance-kit.md`

---

## Upgrade / release posture

2.1 should be understood as a consolidation release.

It brings SIR to a more stable and reviewable point by:

- tightening truth-surface integrity
- improving operator clarity
- improving trust-surface coherence
- extending bounded structured and tool-result capabilities carefully
- avoiding unnecessary architecture sprawl

This release is intended to support a period of testing, verification, and stability rather than immediate new feature expansion.

---

## Closing note

SIR 2.1 is meant to be boring in the right ways:

- deterministic
- explicit
- verifiable
- bounded
- honest about what it does and does not do

That is the point of the release.
