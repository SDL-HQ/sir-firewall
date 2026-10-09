# Working notes for agents in this repository

Read this before changing anything. It records the constraints that are not
obvious from the tree and that have each caused a real defect at least once.

## What this is

SIR (Signal Integrity Resolver) is a deterministic pre-inference governance
gate. It evaluates a request against an enumerated rule set before any model is
called, returns pass or block, and emits a signed certificate describing the
run. There is no model in the decision path, so the same input under the same
policy produces the same decision.

Two planes, and they fail differently:

- **Control plane.** The gate decides. Failures are silent and, as the system
  is currently built, uncountable after the fact: the ledger records a hash per
  prompt, not the input that produced it.
- **Evidence plane.** The ledger and certificate record what happened.
  Failures are silent but countable afterwards, because the artefacts persist.

Most of the hard-won rules below are about the evidence plane.

## The rule that matters most

**An assertion must be derived from the artefact it names, at the moment of
signing.** Every significant defect in this project's history has the same
shape: a value was read from a second copy of an identity (an environment
variable, a mutable file, a filename, a cached page) rather than computed from
the thing it claimed to describe. Signature validity and chain integrity do not
detect this. Nothing detects it except deriving the value from the referent.

If you find yourself writing "read X from the environment, fall back to a
file", stop. That exact pattern shipped 268 unbindable certificates over 253
days.

## Repo geography, and the traps

- **`docs/` is the GitHub Pages root.** Moving or renaming a file there changes
  a live URL. Add banners to superseded documents; do not relocate them.
- **`docs/runs/index.json` is a display cap of the newest 200 runs**
  (`publish_run.py --keep`, default 200), not a manifest. Run directories are
  never pruned. At the time of writing the archive holds 284 certificates and
  the index lists 200. **Any measurement over "the archive" must iterate the
  directories.** Measuring the index gives a smaller, wrong answer. This has
  happened, and was published in a draft before being caught.
- **`proofs/runs/<run_id>/` is the canonical ledger location.**
  `sir_firewall.evidence_paths.canonical_ledger_path()` derives it from a run
  identifier. Use it. Do not locate a ledger by directory adjacency: several
  certificates can sit beside one ledger, and guessing binds the wrong pair.
- The published website is a separate deploy bundle, not in this repo.

## Evidence contracts

| Contract | Applies from | Adds |
| --- | --- | --- |
| `spec/evidence_contract.v1.json` | 2.2.0 | baseline required fields |
| `spec/evidence_contract.v2.json` | 2.3.4 | `itgl_row_count`, `detached_ledger` |
| `spec/evidence_contract.v3.json` | 2.3.5 | `enforced_policy_matches_signed_policy` |
| `spec/evidence_contract.v4.json` | 2.4.0 | `content_evaluated`, `systemic_reset_count`, `configuration_hash`, `counters_checked_against_ledger`, `signing_key_id` |

`validate_certificate_contract.py` selects by the certificate's own
`sir_firewall_version`. Certificates below 2.2.0 return exit 8 (out of scope),
not a failure. When adding a contract, raise the floor rather than adding a
required field to an existing one. A field required at a floor that predates
the field invalidates every certificate in between. This has happened.

Selecting by the certificate's own version means the artefact chooses the rule
that judges it. `verify_certificate.py` therefore applies the v4 floor from the
bound ledger instead: a certificate bound to a chain version 2 ledger must carry
the v4 fields whatever version it claims, exit 2 if it does not. A ledger's
chain version is covered by its own row hashes and chained to the terminal hash
the certificate signs, so unlike `sir_firewall_version` it cannot be restamped.
The field list is duplicated as `CONTRACT_V4_ADDED_FIELDS` in the verifier so a
minimal bundle needs no spec file;
`tests/test_contract_floor_is_not_self_asserted.py` holds the two together.

## Exit codes

`tools/verify_certificate.py`:

| Code | Meaning |
| --- | --- |
| 0 | verified |
| 2 | missing required fields (also argparse usage errors) |
| 3 | payload hash mismatch |
| 4 | malformed base64 |
| 5 | signature does not verify |
| 6 | signature verification error |
| 7 | binding failure: chain invalid, terminal-hash mismatch, or row-count mismatch |
| 9 | binding **not checked**: no ledger was found, or the certificate predates `itgl_row_count` |
| 10 | the signing key is revoked for this archive |
| 11 | counter binding failure: the signed counters are not supported by the bound ledger |

`tools/validate_certificate_contract.py`: 0 pass, 2 contract violation, 3 load
error, 8 below the applicability floor.

`tools/verify_evidence.py`, the consolidated command and the documented
evaluator procedure: 0 established, 1 **not established**, 2 failed, 3 the run
directory could not be read. It reports five properties separately and its
verdict is the worst state present.

7 and 9 are deliberately distinct. 7 means the binding was checked and is
wrong. 9 means it could not be checked at all. Collapsing them loses the
distinction between an attack and a defect. The same distinction is what
separates exit 1 from exit 2 in `verify_evidence.py`, and it is why a
certificate from before `itgl_row_count` existed reports 9 rather than 7: 219
published archives never carried that field, and reporting a format change as a
binding failure manufactures a catastrophe.

**Unknown is not a pass and not a failure.** A property nobody could check is
not a property that holds. This is the same rule as
`content_false_positive_rate` being null rather than zero and
`counters_checked_against_ledger: false` not meaning agreement.

## The evaluator procedure

`docs/assurance-kit.md` documents one command over one run directory. Prefer it
over the individual tools when reaching a verdict: it passes explicit paths
rather than letting `verify_certificate.py` discover a ledger, which resolves
against the working directory and can find a copy elsewhere on disk, and it
reports signing trust as a property of its own rather than leaving it to be
inferred from which flags were typed. Registry resolution is its default and
there is no flag that asks for it; `--allow-unregistered-key` opts out and
changes the verdict.

## Invariants that must not quietly break

- **Binding is verified by default.** `--no-ledger` is the only successful
  explicit skip, and it must announce itself on stderr even under `--quiet`.
- **The ledger is resolved from the certificate's signed `run_id`**, never from
  where the file happens to sit. A certificate carrying no `run_id` returns 9.
- **The signed policy is compared to the enforced policy before signing.** A
  mismatch refuses to sign; the outcome is recorded as a signed certificate
  field.
- **Documented output must match real output.** The verifier's success string
  is quoted in `README.md`, three evaluator documents under `docs/`, and the
  website bundle. Changing the wording without updating all of them has
  happened twice. A test asserts the rendered blocks against actual stdout.
  Keep it.

- **Absent input is never a pass.** CI steps that run under `always()` are
  reached even when the checkout or the audit itself failed. A missing counter
  file means the audit did not run, which is inconclusive, not zero leaks. The
  verdict step fails closed and sets `INCONCLUSIVE=true`, and the proof commit
  message reports `unknown` rather than `0`. This was a live defect: a run
  whose checkout failed reported a green verdict step over an empty workspace.

- **A certificate is signed only for the run that produced its summary.**
  `proofs/run_summary.json` is committed, so it sits on disk even in a job where the
  audit never executed. The run identifier embeds the producing CI run, and the
  generator refuses to sign when that does not match the current execution. Before
  this check, a job whose audit died regenerated the previous run's certificate from
  stale artefacts, computed it as passed, and was free to publish it as the canonical
  latest proof.

- **A signed manifest is a claim about what was published, so check git carries
  it.** `publish_run.py` hashes whatever it finds in the run directory into
  `manifest.json` and signs that manifest. If an ignore rule or a missing
  `git add` then drops one of those files, the archive is published incomplete,
  the receipt check fails for every third party, and CI stays green because
  nothing on the runner noticed. `check_archive_staged.py` compares the signed
  manifest against the git index before the publishing commit and fails closed.
  This was a live defect for ninety-nine published archives. Note the mechanism:
  a `.gitignore` pattern without a leading slash matches at every depth, so a
  rule meant for a mutable file at the repo root silently applied inside every
  run archive.

- **Cannot be checked and fails are different results.** Verification is
  three-valued. Folding records that fail into a count of records that could not
  be checked makes a published figure look like a limitation of age rather than
  a defect. Report the three separately, and derive the counts with
  `archive_verification_report.py` rather than by hand.

## CI credentials, and how they fail

`audit-and-sign.yml` checks out with `SIR_AUDIT_PUSH_TOKEN` on `main` and with
`github.token` on every other ref. That secret is a personal access token with
a hard expiry, and it is the only credential the audit bot has.

When it expires or is regenerated, the failure does not say so. Checkout
retries three times, prints `could not read Username for 'https://github.com'`,
then exits 128. Every step needing a working tree is skipped, the `always()`
steps fail on missing files, and the run surfaces a dozen errors, none of which
mention a token.

If the audit fails on `main` while branches and pull requests stay green, check
that secret first. Regenerating a token changes its value and revokes the old
one, so a token regenerated for local use must be written back into the secret.
Editing a token's permissions does not change its value.

## Before you merge

1. `pytest -q`. Full suite, with no `PYTHONPATH` and no editable install:
   every entry point finds the package for itself, and a suite whose result
   depends on the ambient environment is not evidence. No test count is stated
   here on purpose, because a number in a document rots between commits.
2. `python3 tools/verify_policy.py`. Signed policy matches enforced policy.
3. Run the published verification command from the website against the current
   release and diff its real stdout against what the site renders. Instance
   eight of the recurring defect was exactly this drift.
4. If the verifier's output wording changed, grep the whole tree and the
   website bundle for the old string.
5. Report the SHA that is actually on the remote. Four reports in one release
   cycle named a commit that could not be resolved, which made verification
   slower than the work.

## Deliberately left alone

- Six published certificates carry 2048-bit signatures from a key that was
  never published, so they cannot be verified by anyone. They stay published.
  Removing them would tidy the archive and destroy the evidence.
- `signing_key_id` is a hardcoded constant rather than derived from the key.
  Recorded as a known residual; a rotation is currently indistinguishable from
  an attack.
- No certificate has ever been produced with `CRYPTO_ENFORCED` true. The key
  registry consulted by the runtime gate is empty, so enabling it would block
  all traffic.

## Working agreement

Run it, do not trust the report, including your own. Every defect found in the
2.3.5 cycle survived careful reading and died the moment something was
executed. A prescription is a claim about what the code will do and deserves
the same verification as any other claim; three fixes in that cycle each
created the next defect because they were reasoned about rather than tested.
