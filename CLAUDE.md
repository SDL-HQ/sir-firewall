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
  never pruned, so the archive is always larger than the index and that gap grows
  with every run. No figure is given here on purpose; derive the current ones with
  `archive_verification_report.py`. **Any measurement over "the archive" must
  iterate the directories.** Measuring the index gives a smaller, wrong answer. This has
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
| 11 | binding failure on a signed value: the counters, the configuration identity, or the `result` itself is not supported by the bound ledger |
| 12 | the document is not a SIR audit certificate, and nothing about it was verified, including its signature |

`tools/verify_baseline_record.py`: 0 verified, 2 not a baseline record, 3
payload hash mismatch, 4 malformed base64, 5 signature does not verify, 6 the
signature check could not be performed, 7 the bound ledger does not support
the record, 10 the signing key is revoked.

`tools/verify_archive_receipt.py`: 0 verified, 2 a named file is missing or
changed or the receipt signature does not verify, 3 the manifest or receipt
could not be read, 6 the signature check could not be performed.

`tools/validate_certificate_contract.py`: 0 pass, 2 contract violation, 3 load
error, 8 below the applicability floor.

**5 and 6 are the same distinction as 7 and 9**, applied to the signature
rather than the binding. 5 means the signature was checked and the payload
does not bear it, which is a statement about the document. 6 means the check
did not complete, which is a statement about us: a malformed entry in our own
registry, an unsupported algorithm, a library that is absent, or a programming
error in the verifier. Collapsing them reports our defect as the document's,
and that is the only defect class here that reads as dishonesty rather than as
a limit. `verify_evidence.py` therefore classifies 6 as **unknown**, not
failed, from every tool that returns it.

Until 17 October 2026 only `verify_certificate.py` drew that line.
`verify_baseline_record.py` and `verify_archive_receipt.py` each printed a
distinct message for a check that raised and then returned the code for a
signature that does not verify, so the distinction reached a person reading
stderr and nothing else. `verify_policy.py` carried a comment saying every
cryptography exception is a failure, which is true of the outcome and wrong
about the fact. Inside the gate, `_verify_signature` returned a bare false for
all of it.

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

- **The verdict is recomputed, not taken on trust.** `compute_audit_result`
  lives in `tools/itgl.py`, beside `derive_counters`, and
  `generate_certificate.py` imports it rather than holding a copy.
  `verify_certificate.py` recomputes `result` from the derived counters and the
  certificate's `proof_class`, and reports disagreement under exit 11, as it
  does for the counters and for the configuration identity.

  Until 17 October 2026 `counter_disagreements` recomputed every input to the
  verdict and nothing recomputed the verdict. The function sat in the
  generator, which is not in the shipped bundle and is called by no verifier,
  so the field that gates canonical publication, the CI outcome and the public
  homepage was the one derived value nothing checked. Measured on a copy of a
  published certificate: `AUDIT FAILED` with `jailbreaks_leaked: 0` passed
  `validate_certificate_contract.py` at exit 0, and so did `AUDIT PASSED` with
  `jailbreaks_leaked: 7`. The signature meant no third party could forge
  either; it never meant a producer could not sign one. Recomputed over the
  archive when this landed: 68 of 68 certificates with derivable rows agreed
  with their signed string, and the 292 older ones report not checked.

  The first thing the check caught was one of our own fixtures.
  `test_an_honest_certificate_verifies` asserted exit 0 for a certificate
  reading `AUDIT PASSED` over rows carrying a leak, a harmless block and a
  reset. It derives its result now, because writing the corrected literal
  would restate the same bug at a better value.

  `configurations_observed` is derived too, and was the reason to look: it was
  the one input of the six that no one recomputed, read from
  `proofs/run_summary.json`, the file that sits on disk even in a job where the
  audit never ran. `configuration_hash` is deliberately **not** in
  `DERIVABLE_ROW_FIELDS`; adding it there would make `derive_counters` return
  None for the 250 ledgers written before the field and turn every counter they
  check today into not checked. The derivation mirrors the producer at
  `red_team_suite.py` around line 869, counting **distinct non-empty** hashes,
  because a row rejected before a configuration was established writes `""` and
  is a gate decision rather than a second configuration. Zero is a real answer
  and is INCONCLUSIVE: `None > 1` and `0 > 1` are both false, so returning
  unknown for "no configuration witnessed" would collide with the legacy
  sentinel and change no verdict. The configuration conditions have never fired
  in any published run, so `tests/test_the_verdict_is_recomputed_not_asserted.py`
  is the deliverable rather than the derivation. Note what is **not** changed:
  the generator still reads the counters from the summary while the verifier
  derives them from the rows. That asymmetry is the cross-check. Making the
  producer derive them too would have deleted the check being added.

- **A check that could not run is not a bad signature.** `_verify_signature`
  in `core.py` returns one of the `SIGNATURE_*` reasons rather than a bool,
  and the `crypto_signature` ledger row records which, plus
  `signature_established` so a consumer does not keep its own list of which
  reasons mean what. `invalid` is the only one that is a statement about the
  request; `crypto_unavailable`, `signature_absent`, `key_unknown` and
  `check_raised` are statements about us. The ITGL row's `output` is a
  free-form dict covered by the row hash, so adding a field needs no schema
  or version bump and old ledgers verify against their own hashes unchanged.
  Enforcement is deliberately untouched: a broken check still blocks under
  `CRYPTO_ENFORCED`, because fail-closed was never the defect. The record was.

- **What the verifier prints is published, not described.**
  `docs/verification-transcripts.json` holds the exact stdout, exit code and
  command for `verify_evidence.py` over both halves of the newest six
  valid-complete pairs, captured by running it.
  `tools/publish_verification_transcripts.py` writes it, `--check` re-captures
  and refuses on drift, and both publishing steps in `audit-and-sign.yml`
  regenerate it in the same commit as the archive. A consumer renders the
  stored text verbatim and never rebuilds a sentence from certificate fields.
  The website did rebuild one, in JavaScript, from `signing_key_id`,
  `itgl_final_hash`, `itgl_row_count` and `prompts_tested`, and published it as
  what the command prints; it matched because a person kept it in step. Six
  pairs is not a round number: the website renders the newest six and pins one
  of them, and `tests/test_verification_transcripts.py` asserts that coupling
  so a run a public surface could show cannot be a run with no transcript.
  Nothing is written into a published run directory, because `manifest.json` is
  signed over what that directory holds. The tool writes only when something
  other than the clock has moved: a routine audit adds no benchmark pair, so
  it captures what is already there, and the first live run committed a
  one-line timestamp diff to a published artefact for nothing.
  `generated_at_utc` therefore means when the content was produced, and that
  the transcripts were re-captured today is evidenced by the CI run that did
  it.

- **Two trees are published from here, and the same rules scan both.**
  `tools/publication_rules.py` holds the working-document, private-key,
  credential and patent rules in one place.
  `tests/test_no_working_documents_in_the_public_repository.py` runs them over
  this repository's tracked files on every commit, and
  `tools/generate_shop_window.py` runs them over the window it is about to
  push. That second run is the only inspection the window's generated prose
  ever gets: its `README.md`, `LIMITS.md`, `VERIFY.md` and `GENERATED` exist in
  no file here, and one of them carries an error message captured live from a
  subprocess. Do not give either surface its own copy of the rules; a second
  copy of an identity is this project's recurring defect, and the window's copy
  is the half nobody would be watching. Exhibits are scanned for secrets and
  not for writing, because an audited prompt may contain any words at all.
  Planting the patent phrase inline in a test is how the vault's guard caught
  its own test suite: use `publication_rules.PATENT_SAMPLE` instead of
  exempting another file.

  The window's About line is the exception, because GitHub keeps it in
  repository settings where no rebuild reaches it. The generator composes it
  from the same figures as the README, writes it into `GENERATED` as a single
  line, and prints it at the end of a build. Paste it from there rather than
  retyping it; it went stale within a day of being written by hand. The number
  words, the list of files a visitor runs and the walk that computes what they
  install all live in `generate_shop_window.py` for the same reason, and
  `tests/test_the_evidence_window_is_reachable.py` holds the two public pages
  against them.

  The window states the archive's totals as at the tag it was built from, not
  in the present tense. A run is published on every merge here and the window
  is rebuilt only when a release is cut, so a present-tense total is wrong
  within a day and has no way to correct itself while the weekly rebuild skips
  a release that predates the generator. It said "It holds 356 runs" while the
  archive held 359. A page that cannot go stale beats a page that is currently
  accurate, which is the same answer the website reached for its own dated
  figure.

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
`github.token` on every other ref. That secret is a fine-grained personal access
token and it is the only credential the audit bot has.

**It has no expiration date, deliberately.** An expiry would stop publication on
a date nobody is watching, and the failure would arrive looking like the first
mode below rather than like a diary entry coming due. The cost of the choice is
that it is only revoked by someone revoking it, so it is worth checking exists
and is still scoped to this repository when reviewing custody. Checked
12 October 2026: metadata read, actions, contents and pull requests read and
write, `SDL-HQ/sir-firewall` only, no account permissions.

The credential that does expire is a different one: `Mayor-13 local push`,
expiring 25 December 2026, which is the keychain token behind local `git push`
and has nothing to do with CI. When it goes, your terminal stops pushing with
the same unhelpful message as below while CI stays green.

Since 12 October 2026 it also opens the proof pull request, as `GH_TOKEN` for
`gh pr create` and `gh pr merge --auto`, so it needs **pull-requests write** as
well as contents write. A pull request opened with `GITHUB_TOKEN` is authored by
the Actions bot, and GitHub does not let that event start further workflows, so
the required checks never run and publication stays pending forever. That is
what proof pull request #342 was. Editing a token's permissions does not change
its value, so adding the permission does not mean re-entering the secret.

It has two failure modes and neither names the token.

**Expired, regenerated, or missing contents write.** Checkout retries three
times, prints `could not read Username for 'https://github.com'`, then exits
128. Every step needing a working tree is skipped, the `always()` steps fail on
missing files, and the run surfaces a dozen errors, none of which mention a
token.

**Contents write but no pull-requests write.** The audit passes, the archive is
built, the proof branch pushes, and `gh pr create` fails with
`must be a collaborator (createPullRequest)`. The step reports publication
pending rather than failing, which is correct and also indistinguishable at a
glance from the defect above it. If a proof branch exists on the remote with no
pull request against it, check that permission.

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
