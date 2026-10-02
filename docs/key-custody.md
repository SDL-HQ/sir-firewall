# Signing key custody

What is true of the signing key today, established by reading the workflows and
the tools rather than by intention. Where something is a convention rather than
an enforced control, this document says so.

## Where the private key lives

The private half exists only as the repository secret `SDL_PRIVATE_KEY_PEM`. No
private key material is committed to this repository. The public half is
`spec/sdl.pub` and the registry entry is in
`spec/pubkeys/key_registry.v1.json`.

Every tool that signs reads the key from the environment and fails closed
without it: `tools/generate_certificate.py`, `tools/publish_run.py`,
`tools/sign_policy.py`, `tools/sign_isc.py`.

## What can sign with it

The real secret is referenced in one workflow, `.github/workflows/audit-and-sign.yml`,
by both of its jobs:

- `audit-and-sign`, which runs on a push to `main` or `dev`, and on a manual
  dispatch whose operation is not `benchmark`
- `benchmark-dispatch`, which runs on a manual dispatch whose operation is
  `benchmark`

So three routes reach the key: a push to `main`, a push to `dev`, and a manual
workflow dispatch by someone with that permission.

`dev` is a signing-capable branch and the branch ruleset targets `main` only.
Anyone able to push to `dev` can cause a signature with the production key. That
is a current property of the setup, not a recommendation.

## What cannot sign with it

`.github/workflows/r1-cli-acceptance.yml` runs on pull requests and never reads
the secret. It generates an ephemeral RSA key with `openssl` at the start of the
job and exports that as `SDL_PRIVATE_KEY_PEM` for the steps that follow.

This is deliberate and worth stating plainly, because it determines what a
pull-request run can produce: a certificate signed in a pull request cannot
verify against the published key registry. It is also the mechanism behind the
six published certificates described in `archive-errata.md` as failing signature
verification. Those were signed outside continuous integration with a key that
is not the registered one, while asserting the registered key's identifier.

## Rotation

`tools/rotate_keys.py` exists. It retires the active entry and adds a new one.

It is referenced nowhere else: not by any workflow, not by any test, not by any
document other than this one. It has never been exercised, and no key has been
rotated. The registry holds a single entry, `default`, created 2025-01-01, with
status `active` and no revocation recorded.

## Append-only, and what that word is worth here

Nothing enforces append-only on the key registry. There is no continuous
integration check, no test, and no schema constraint preventing an entry from
being edited or removed. Append-only is a convention, not a control, and a
reader should treat it that way.

What the schema does define, in `x_verifier_expectations` of
`spec/pubkeys/key_registry.v1.schema.json`, is revocation semantics for
verifiers: a revoked key must not retroactively invalidate proofs signed before
its `revoked_utc`, and verification fails only for proofs whose `timestamp_utc`
is at or after that moment. That governs how a verifier behaves when a
revocation exists. It says nothing about who may change the registry.

## What a reviewer should take from this

The key is held as a secret and no copy is committed. Signing is confined to one
workflow, and pull-request runs provably cannot sign with it. Rotation is
unexercised, revocation has never been used, and registry integrity rests on
repository access control rather than on any mechanism in this repository.

A buyer who needs stronger custody than that is asking for a hardware-backed or
externally managed signing key, which this repository does not currently have
and does not claim to have.
