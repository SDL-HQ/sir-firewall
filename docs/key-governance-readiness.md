# SIR Key Governance Readiness

This document defines the key governance readiness layer for SIR.

Terminology follows `docs/terminology.md`: prefer **governance gate** in descriptive text, while keeping stable canonical identifiers unchanged.

It does not enable `CRYPTO_ENFORCED`.
It does not change proof generation or verification behavior.
It defines trust surfaces, authority boundaries, and readiness conditions for a future hardening step.
It is not the canonical product-boundary definition document; use `docs/evaluator-technical-explainer.md` for boundary and residual-risk semantics, and `docs/assurance-kit.md` as supporting walkthrough context.

## Current state

- `CRYPTO_ENFORCED` remains `false` by design.
- Existing verification behavior remains source compatible.
- Local and CI workflows may use non-authoritative keys for development and acceptance.
- Authoritative public claims remain governed by the published SDL trust-material convention and the verification boundaries described below.

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

Verification-enforcement boundary:

- "Authoritative" and "non-authoritative" are governance classifications, not conclusions produced solely by a successful signature check.
- When a certificate carries a resolvable `signing_key_id`, the verifier uses the matching registry key and applies registry revocation semantics.
- A document that names its signing key is verified against the registry's entry for that key and against nothing else. A registry that is missing or unreadable, and a registry that does not have the named key, are both refused at exit 6, the code for a check that could not be performed, and nothing about the document is verified. No flag asks for a public key file instead. Until 21 November 2026 a missing registry was a warning and the configured `--pubkey`, and two of the three verifiers also used a public key file for a key the registry did not have.
- Use `--require-registry` for verification that must rest on registry keys only. What it removes is the one remaining use of a public key file, described in the next point.
- A public key file is a candidate in one case: a certificate that names no `signing_key_id`, which is tried against the registry's implicit entry and then against `--pubkey`. A key read from the file is held to the registry. After the signature verifies, the verifier asks whether any registry entry holds that key, by the key and not by a name, and applies that entry's revocation and anchored-set rules. A key no entry holds is verified as non-authoritative material, as before.

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
| SDL repository public key | `spec/sdl.pub` | Yes | The active key, as a file. Read by a verifier only as the second candidate for a certificate that names no `signing_key_id` |
| SDL registry entries | `spec/pubkeys/key_registry.v1.json` | Yes | The verification anchor for every document that names its key, and the only one |
| Local dev keypair | `/tmp/sir_dev_pub.pem` | No | Acceptable only for local/dev proofs, verified through the local registry that key is enrolled in |
| CI ephemeral keypair | workflow-generated temporary key | No | Acceptance-only path for CI-generated proof material |

## Canonical authoritative vs non-authoritative semantics

Authoritative path:

- SDL-signed proof material verified with a resolvable repository registry key, or under a verification procedure that otherwise establishes the approved SDL trust anchor.
- Registry resolution fails closed by default. For registry keys only, with no public key file as a candidate, use `--require-registry`.
- Successful signature verification establishes integrity and validity against the selected key; the authoritative SDL classification additionally depends on the governance provenance of that key.
- Claims remain bounded to the published evidence and verifier output.

Non-authoritative path:

- Local or workflow-signed material is verified through the signer's own registry, the one a signer is required to enrol its key in, passed as `--key-registry`. That establishes the signature against the key that registry names. It does not establish SDL trust, because the registry is not SDL's.
- When registry material is unavailable or unreadable, or does not have the key a document names, the verifier refuses at exit 6. A document that names its key is never verified against `--pubkey` alone.
- Such verification is valid for test correctness and pipeline checks, not for SDL public assurance claims.

Segregation rule:

- Documentation and tooling examples should label non-authoritative flows as local/dev/CI.
- Authoritative and non-authoritative keys should not share ambiguous labels.

## Future rotation model at high level

This section is a readiness shape only.

1. Add new authoritative public key entry to `spec/pubkeys/key_registry.v1.json` with `status: active` and clear validity timestamps.
2. Keep prior key available as `active` or `retired` for compatibility window.
3. Configure signing with `SDL_SIGNING_KEY_ID` so generated certificates identify the selected active key. Certificate generation already emits `signing_key_id`, defaulting to `default`.
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
