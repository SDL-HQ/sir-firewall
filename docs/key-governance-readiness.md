# SIR Key Governance Readiness

This document defines the key governance readiness layer for SIR.

Terminology follows `docs/terminology.md`: prefer **governance gate** in descriptive text, while keeping stable canonical identifiers unchanged.

It does not enable `CRYPTO_ENFORCED`.
It does not change proof generation or verification behavior.
It defines trust surfaces, authority boundaries, and readiness conditions for a future hardening step.

## Current state

As of April 4, 2026:

- `CRYPTO_ENFORCED` remains `false` by design.
- Existing verification behavior remains source compatible.
- Local and CI workflows may use non-authoritative keys for development and acceptance.
- Authoritative public verification is still anchored to published SDL trust material.

## Trust surface map

### Authoritative verification trust source

Primary authoritative trust sources are:

- `spec/sdl.pub`
- `spec/pubkeys/key_registry.v1.json`

Intended use:

- Third-party verification of published proof material.
- Verification paths that represent SDL-signed artefacts.

Authority rule:

- For public SDL claims, keys resolved from authoritative trust sources are authoritative.

### Non-authoritative local and workflow keys

Non-authoritative keys include:

- locally generated dev keys (for example `/tmp/sir_dev_priv.pem` and `/tmp/sir_dev_pub.pem`)
- ephemeral workflow keys used in CI acceptance runs
- any key injected only for local demonstration or temporary test execution

Intended use:

- local testing
- CI acceptance checks
- demo and operator rehearsal workflows

Authority rule:

- Non-authoritative keys must not be represented as authoritative SDL trust anchors.

## Key classes and verification posture

| Key class | Example location | Authoritative | Verification posture |
| --- | --- | --- | --- |
| SDL repository public key | `spec/sdl.pub` | Yes | Default offline verification anchor for published SDL artefacts |
| SDL registry entries | `spec/pubkeys/key_registry.v1.json` | Yes | Authoritative key set for key-id based verification and future rotation readiness |
| Local dev keypair | `/tmp/sir_dev_pub.pem` | No | Acceptable only for local/dev proofs when verifier explicitly points to that key |
| CI ephemeral keypair | workflow-generated temporary key | No | Acceptance-only path for CI-generated proof material |

## Canonical authoritative vs non-authoritative semantics

Authoritative path:

- SDL-signed proof material verified against repository trust anchors.
- Claims are bounded to published evidence and verifier output.

Non-authoritative path:

- Local or workflow-signed material verified with explicit non-authoritative key input.
- Valid for test correctness and pipeline checks, not for SDL public assurance claims.

Segregation rule:

- Documentation and tooling examples should label non-authoritative flows as local/dev/CI.
- Authoritative and non-authoritative keys should not share ambiguous labels.

## Future rotation model at high level

This section is a readiness shape only.

1. Add new authoritative public key entry to `spec/pubkeys/key_registry.v1.json` with `status: active` and clear validity timestamps.
2. Keep prior key available as `active` or `retired` for compatibility window.
3. Update signing to emit `signing_key_id` for the active authoritative key.
4. Verify historical proofs against the registry using proof timestamp semantics.
5. Move old key to `retired` or `revoked` when policy requires, preserving non-retroactive verification semantics already documented by registry expectations.
6. Keep `spec/sdl.pub` and registry alignment explicit during transition windows.

This does not require background key services and does not mandate a PKI rollout.

## CRYPTO_ENFORCED readiness checklist

All items below should be true before enabling `CRYPTO_ENFORCED`.

### Governance and authority

- [ ] Authoritative signing owner is defined and documented.
- [ ] Authoritative key storage and access model is defined.
- [ ] Authoritative and non-authoritative signing paths are documented separately.

### Trust source stability

- [ ] Authoritative verifier trust source is stable (`spec/sdl.pub` and/or registry-driven model).
- [ ] Key registry update process is documented and reviewable.
- [ ] Key identifiers used in proofs are consistent with registry entries.

### Compatibility and verification behavior

- [ ] Historical proof verification behavior is documented for rotation and revocation windows.
- [ ] Verifier behavior for missing timestamp during revocation checks is explicitly tested.
- [ ] Existing pass/fail/archive semantics remain unchanged by key governance updates.

### Test and acceptance coverage

- [ ] Acceptance tests cover authoritative verification path.
- [ ] Acceptance tests cover non-authoritative local/CI path with explicit key override.
- [ ] Negative tests cover wrong key, revoked key, and missing key-id behavior.

### Rollout safeguards

- [ ] A dry-run plan exists for enabling `CRYPTO_ENFORCED` in a controlled environment.
- [ ] Rollback criteria are documented if verification rejects expected historical artefacts.
- [ ] Operator docs are updated before any enforcement flip.

## Overlap risk notes

Potential overlap risks and containment:

- Risk: non-authoritative examples are mistaken for SDL authoritative claims.
  - Containment: explicit labels in docs and command examples.
- Risk: registry evolution could imply retroactive invalidation confusion.
  - Containment: preserve timestamp-based verifier semantics from registry expectations.
- Risk: readiness work could drift into behavior changes.
  - Containment: this phase is documentation and checklist only, with no `CRYPTO_ENFORCED` enablement.

## Out of scope for this phase

- Enabling `CRYPTO_ENFORCED`
- Implementing production key custody infrastructure
- Refactoring proof generation
- Changing archive semantics
- Introducing background key management services
