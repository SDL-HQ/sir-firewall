# Signing key custody

What is true of the signing key today, established by reading the workflows and
the tools rather than by intention. Where something is a convention rather than
an enforced control, this document says so.

Last verified 7 October 2026, against `release/2.4`.

Several claims in this document are pinned by tests rather than left as prose,
because a custody document nobody can check is worth very little. Those tests
are named where the claim is made.

## Where the private key lives

The private half exists as the repository secret `SDL_PRIVATE_KEY_PEM`, and as a
single file on the maintainer's machine, mode 0600, outside any repository
checkout. No private key material is committed to this repository.

The public half is published twice: `spec/sdl.pub`, which is the default public
key for the certificate, archive receipt and export bundle verifiers, and the
registry entry in `spec/pubkeys/key_registry.v1.json`.

The repository variable `SDL_SIGNING_KEY_ID` names which registry entry the
secret corresponds to. It is not optional. `tools/generate_certificate.py` and
`tools/sign_policy.py` both read it and both fall back to `default`, so a
rotation that replaced the secret without setting the variable would stamp
every certificate with a key id that did not sign it.

Every tool that signs reads the key from the environment and fails closed
without it: `tools/generate_certificate.py`, `tools/publish_run.py`,
`tools/sign_policy.py`, `tools/sign_isc.py`.

## What can sign with it

The real secret is referenced in one workflow,
`.github/workflows/audit-and-sign.yml`, by both of its jobs:

- `audit-and-sign`, which runs on a push to `main`, and on a manual dispatch
  whose operation is not `benchmark`
- `benchmark-dispatch`, which runs on a manual dispatch whose operation is
  `benchmark`

So two routes reach the key: a push to `main`, and a manual workflow dispatch by
someone with that permission. `main` is the branch the Protect Main ruleset
covers.

Until 6 October 2026 `dev` was also a signing-capable branch while the ruleset
targeted `main` only, which meant anyone able to push to `dev` could cause a
signature with the production key. `dev` was removed from the triggers in
commit `8445871`.

Pinned by `tests/test_signing_surface.py`:
`test_only_one_workflow_can_reach_the_production_signing_key`,
`test_only_main_signs_on_push`,
`test_the_signing_key_id_travels_with_the_secret`, and
`test_every_workflow_that_signs_declares_why_it_may`, which fails the moment a
new workflow reads the secret.

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

Pinned by `test_pull_request_runs_cannot_sign_with_the_production_key`.

## The registry is the only way to resolve a key

A public key file on disk answers no question about status. It cannot say
whether the key is active, retired or revoked, so a verifier that trusts one is
outside every control described below.

On 6 October 2026 `policy/sdl_public_key.pem` was found still holding the
retired `default` public key, referenced by nothing, two commits in its entire
history. It was the most obvious-looking file for a reader to verify against and
it answered to no registry. It was deleted, and
`tests/test_key_surface.py::test_no_public_key_material_outside_the_registry`
fails if public key material reappears outside `spec/sdl.pub` and
`spec/pubkeys/`.

`tests/test_key_surface.py::test_spec_sdl_pub_matches_the_active_registry_entry`
pins the other half: the file the verifiers default to is the key the registry
calls active.

Since 7 October 2026 the signed policy also carries its key identity.
`policy/isc_policy.signed.json` records `schema` and `key_id`, the signature
covers both, and `tools/verify_policy.py` resolves the key through the registry
and requires status `active`. Before that change the signed policy named no key
at all and could only be checked against whichever public key file was on disk.
That mattered more than it looked: `tools/generate_certificate.py` refuses to
issue a certificate when `verify_policy()` fails, so this artefact gates every
other signature the project produces.

## What happens if the signing key leaks

This is the question this document exists to answer, so it is answered plainly,
including the part that is not covered.

**Revocation is anchored to something the key holder does not control.** A
registry entry records `last_trusted_run_id`. A certificate counts as
pre-revocation only if the continuous integration run number embedded in its
`run_id` is at or below that anchor. Run numbers are issued by GitHub, and a
leaked key grants no push access, so the holder cannot mint one.

**The self-asserted timestamp can only tighten the window, never widen it.**
Until 6 October 2026 revocation compared `timestamp_utc`, a field inside the
signed payload, which the key holder chooses. Anyone holding the key could mint
a correctly signed certificate backdated to before the revocation, so revocation
was defeated by exactly the party it existed to stop. The reproduction and the
fix are in `tools/key_registry.py`, and
`tests/test_key_revocation_anchor.py::test_end_to_end_backdated_certificate_from_a_revoked_key_is_refused`
is the regression.

**Verification fails closed.** With no anchor on the entry, or no parseable run
number on the certificate, the answer is refusal rather than acceptance.
`tools/verify_certificate.py` exits `10`, `REVOCATION_FAILURE`, which is
distinct from every other failure so a consumer can tell revocation apart from a
bad signature or a missing field.

**What revocation does not contain.** Only 24 of the 292 published certificates
carry a parseable run number. Revoking `default` rather than retiring it would
therefore refuse the other 268, because the rule fails closed. That is a real
cost and it has not been accepted yet: `default` is currently **retired, not
revoked**, so nothing is refused today. The options are to accept the forfeit,
to publish a one-off attestation anchoring the historical set, or to defer until
the key is known to be exposed. This is an open decision, recorded here so a
reader is not left to assume it was handled.

**A detached certificate cannot be anchored at all.** Anchoring works on
archives published through continuous integration. A certificate handed over
directly has no published run behind it, which is consistent with what the
README already says about canonical run-location binding.

**Rotation is now exercised rather than theoretical.** See below.

## Rotation procedure

Run in this order. Steps 2, 3 and 4 exist because each of them failed at least
once during the 6 October rotation, and the failures are recorded at the end of
this section rather than quietly fixed.

**1. Generate the new key pair.** The private key goes outside the repository.
`tools/rotate_keys.py` requires `--private-out` and refuses to write a private
key into the tree.

```
python3 tools/rotate_keys.py --private-out ~/.sdl-keys/sir-signing-<date>.pem
```

Defaults worth knowing: the new key id is `sdl-<UTC stamp>`, the key is 4096
bits, and the tool refuses anything below 4096. It retires the previously active
entry and derives its `last_trusted_run_id` from the published archives under
`--archive-root`, or takes it from `--last-trusted-run-id`. It writes
`spec/sdl.pub`, a historical copy under `spec/pubkeys/`, and the registry entry.

**2. Fingerprint the new private key against `spec/sdl.pub` before touching the
secret.** A repository secret cannot be read back. The only other way to find
out what is in it is to use it, which means a failed signing run. Check first:

```
python3 - <<'PY'
import hashlib, sys
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, Encoding, PublicFormat)
def spki(k):
    return k.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
priv = load_pem_private_key(open(sys.argv[1], "rb").read(), password=None)
pub = load_pem_public_key(open("spec/sdl.pub", "rb").read())
a = hashlib.sha256(spki(priv.public_key())).hexdigest()[:24]
b = hashlib.sha256(spki(pub)).hexdigest()[:24]
print(priv.key_size, "bit", a, "MATCH" if a == b else f"MISMATCH (spec/sdl.pub is {b})")
PY
```

Pass the private key path as the argument. Expect `4096 bit ... MATCH`.

**3. Update the secret and the variable together.** In repository Settings,
Secrets and variables, Actions:

- Secret `SDL_PRIVATE_KEY_PEM`, the entire PEM file including the
  `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` lines and the
  trailing newline. Copy the file rather than selecting text:
  `pbcopy < <private key path>`.
- Variable `SDL_SIGNING_KEY_ID`, the new key id, for example
  `sdl-2026-10-06`. This is an identifier string, never key material.
  Repository variables are not masked and are readable by anyone who can read
  Actions logs.

Changing one without the other produces certificates whose stated key id did not
sign them.

**4. Re-sign the policy and commit it.** `policy/isc_policy.signed.json` is
committed, and `tools/generate_certificate.py` refuses to sign under a policy it
cannot verify. A rotation therefore invalidates the committed signed policy, and
so does any change to the signature format.

```
SDL_PRIVATE_KEY_PEM="$(cat <private key path>)" SDL_SIGNING_KEY_ID=<new key id> \
  python3 tools/sign_policy.py && python3 tools/verify_policy.py
```

Then run the full test suite before committing. Skipping this step turns 24
tests red and the cause is not obvious from the failures.

**5. Validate in continuous integration before calling the rotation done.** The
first run after a rotation is part of the rotation, not a separate event. Use a
`workflow_dispatch` of `SIR Real Governance Audit` against the release branch in
audit mode: the publication step is gated on `CANONICAL_PUBLICATION_CONTEXT`,
which is true only on `main`, so the run proves the signing and verification
path end to end without publishing anything or moving the branch.

A green run means three things jointly: the secret holds the private half of
`spec/sdl.pub`, because the policy signing and certificate generation steps
passed; the certificate's `signing_key_id` resolves in the registry and that
entry's public key verifies the signature, because the verification step runs
with `--require-registry`; and the two agree, because neither could pass alone.

**6. Destroy the superseded private key**, and any intermediate copies written
during the rotation. Record that it was destroyed, and where it had been.

### What this procedure has been through

A procedure that has been run once and failed twice is more trustworthy than one
that has never been run, so the failures stay recorded.

The 6 October rotation was the first ever performed. `tools/rotate_keys.py` had
`key_size=2048` hardcoded, so the first attempt silently downgraded the
production key from 4096 bits. It was discarded and redone.
`tests/test_key_revocation_anchor.py::test_no_rotation_may_weaken_the_signing_key`
now pins the floor.

The first continuous integration run after the rotation failed, because the
private key pasted into the secret came from an intermediate file in a temporary
directory rather than from the new key. Nothing was published: the policy was
signed with the wrong key, `verify_policy()` rejected it, and
`generate_certificate.py` raised rather than issuing a certificate that would
not verify. That is the refusal path working on a real mismatch rather than a
synthetic one, and it is the reason step 2 exists.

Re-signing the policy was not in this document before 7 October 2026. Its
absence cost 24 red tests during the rotation and would have cost more during an
incident, which is the reason step 4 exists.

## Append-only, and what that word is worth here

Nothing enforces append-only on the key registry. There is no continuous
integration check, no test, and no schema constraint preventing an entry from
being edited or removed. Append-only is a convention, not a control, and a
reader should treat it that way.

What the registry does define, in `x_verifier_expectations`, is the revocation
semantics described above: the anchor decides, the self-asserted timestamp can
only tighten, and absence of either fails closed. That governs how a verifier
behaves. It says nothing about who may change the registry.

## What a reviewer should take from this

The key is held as a secret and no copy is committed. Signing is confined to one
workflow and one branch, and both facts are pinned by tests rather than asserted
here. Pull-request runs provably cannot sign with it. Rotation has been
exercised once, end to end, including its failures. Revocation is anchored to
run numbers the key holder cannot forge, and fails closed when it cannot be
anchored.

What is still true: registry integrity rests on repository access control rather
than on any mechanism in this repository, 268 of 292 published archives cannot
be anchored, and a buyer who needs stronger custody than that is asking for a
hardware-backed or externally managed signing key, which this repository does
not currently have and does not claim to have.
