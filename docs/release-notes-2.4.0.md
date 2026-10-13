# SIR 2.4.0 release notes

SIR 2.4.0 is a bounded technical-diligence release. Its purpose was not new
capability but to make the existing evidence survive someone who goes looking
for the failures. Ten acceptance conditions were written down before the work
started, in `release-checklist.json`, and `tools/check_release_checklist.py`
refuses the merge path unless every one of them carries evidence that resolves:
a test that exists, an artefact that exists, or a command that runs to its
stated exit code. Prose is not evidence.

All ten are met. The suite is 754 tests.

Certificates emitted by this release are governed by evidence contract v4, whose
applicability floor is 2.4.0, adding `content_evaluated`,
`systemic_reset_count`, `configuration_hash`, `counters_checked_against_ledger`
and `signing_key_id` to the required set. The package version is bumped to 2.4.0
by this release, so it is the first release whose runs produce certificates
governed by v4. No archive published before it declares 2.4.0, and no published
archive is rewritten or re-signed.

## The pattern this release found

Every substantive defect in it was a missing binding. Nothing broke a signature.
Things were not tied to what they described: a certificate to the ledger it
named, a counter to the rows it summarised, a signed policy to the key that
signed it, a declared configuration to the artefacts actually loaded, a suite
identity to the pack that enforced it.

A second pattern appeared partway through and is worth stating because it is
less obvious. **Unknown reported as failure is the same defect as unknown
reported as success.** Three instances were closed: 219 archives reported a
format change as tampering, errata figures counted checks that never ran as
clean, and quorum aggregation failed open. In each case a verifier answered a
question it had not asked.

## What changed, by item

**Item 0, freeze mechanism.** The checklist gate runs on the merge path and the
bypass route is recorded rather than left implicit, including who can use it and
what GitHub records when they do.

**Item 1, execution accounting.** A run now reports what it actually evaluated.
`content_evaluated`, `content_allow_prompts`, `content_block_prompts` and
`systemic_reset_count` are signed fields, so a run that assessed nothing can no
longer present itself as a clean pass. Suite identity and pack identity are
separate on every surface that reports both.

**Item 2, configuration identity.** Every verdict carries the configuration that
produced it, computed from the artefacts actually loaded rather than asserted by
the caller, and it cannot change during a run.

**Item 3, evidence correctness.** Published counters derive from the ledger, and
the generator refuses to sign what the ledger does not support. `chain_version`
2 binds a row's contents into its own hash rather than binding order alone. The
chain has one implementation, in the verifier that ships to readers. The
contract floor is taken from the bound ledger rather than from the certificate's
own version claim, which the signer chooses.

Two consequences of the version bump are worth stating, because both are
enforced from the ledger rather than from the certificate's own version claim. A
certificate whose version puts it at or above the floor is refused if its bound
ledger is `chain_version` 1, because a version 1 row hash does not cover the
row's contents and accepting one would accept an unbound row. And a certificate
bound to a `chain_version` 2 ledger is required to carry the five fields v4
adds, whatever version it claims, because a ledger's chain version is covered by
its own row hashes and so cannot be restamped.

Both were found by the bump rather than by argument. Bumping the package version
turned six tests red whose fixtures described a pre-v4 run: version 1 ledgers,
and certificates missing the added fields. The fixtures were corrected to
describe what a run at this version produces, and they now build their ledger
rows through `tools/itgl.py` rather than through a private copy of the hash
rule, so writer and verifier cannot drift apart in a fixture either.

**Item 4, verification consolidation.** `tools/verify_evidence.py` checks one run
directory with one command across five properties: signing trust, certificate,
signed counters, archive custody and evidence contract. It reports UNKNOWN as
UNKNOWN. Every tool in the repository now runs from a clone, and the test suite
gives one answer rather than depending on an undeclared dependency.

**Item 5, key custody.** The signing key was rotated, revocation is anchored to
the publishing run rather than the signer's timestamp, the signed policy is bound
to the key that signed it and resolved through the registry, and no key material
reaches a diagnostic. `docs/key-custody.md` carries the procedure that was
actually run, including the three steps that failed the first time.

**Item 6, legitimate workload.** False positives are measured over
independently authored text: NCSC and ICO guidance under the Open Government
Licence, committed with attribution, hash-pinned, and refused by the tool if a
carrier does not match its manifest. The rate is published per stratum with its
sampling method, because a single combined figure would be an artefact of the
mix. The false-positive denominator was corrected to the allow-prompts, which is
what the rate is over.

**Item 7, reference demonstration.** Two claims with two scopes, because one
piece of evidence cannot carry both. See below.

**Item 8, claims register.** `docs/claims-register.md` records every public
technical claim with a status, evidence a reader can check, and whether the
feature sits inside the filed specification. See below.

**Item 9, runnable suites.** Every registry entry declares the ISC policy pack
it is enforced under, separately from its own identifier. Four of the nine
entries had been unrunnable since 16 April 2026, producing runs in which every
row was a systemic reset while still asserting a pack and a suite. Selecting a
suite whose declared pack does not exist now fails at resolution.

## Downstream calls, in two scopes

Item 7's condition is universal: all supported failure paths produce zero
downstream calls. A harness cannot support that word, because it sees only the
paths it runs, so the two halves are published separately.

**Structural, bounded to SIR's own code.** No code path in SIR can issue a
downstream call unless the gate returned `PASS` and the call flag is enabled.
The route to a provider is a single choke point, `src/sir_firewall/` imports
nothing capable of a network call, and a module that cannot reach the network
cannot make a call on any path, exercised or not.
`tests/test_no_downstream_call_without_approval.py` holds it, and was checked
against seven mutations of a scratch copy, each of which failed a test.

**Observed, bounded to the paths exercised.** On each failure path the harness
runs, zero downstream calls were observed, with a positive control that must
fire and a per-case check that the path was reached. The paths the runner cannot
construct are named in `docs/reference-demonstration.md` rather than omitted.

**Neither half covers an integrator who ignores the verdict.** A caller that
reads `BLOCKED` and calls the model anyway is outside both, and nothing in SIR
can prevent it.

## Findings a reader should know

**The domain pack changes no verdict any registry suite measures.** Across 453
prompts in eight suites under each of six packs, every per-prompt status and
triggered rule was identical while the signed `configuration_hash` differed for
each pack. So no published run's verdicts depended on its domain pack. This is
not a finding that packs are inert: they control ISC templates, friction limits,
enforcement flags and structured schemas, and no registry suite exercises any of
those, which is why the measurement reads as it does. Recorded in
`docs/threat-model.md` as a third category beside derived and asserted fields:
derived, correct, signed, and not load-bearing.

**There is no use-versus-mention distinction.** A request containing attacker
wording is blocked whether or not the surrounding request is defensive. Measured
over published guidance: 220 requests of that guidance in five task shapes were
all allowed, and the same passages inside a staff-awareness task with one quoted
attacker phrase appended were blocked 264 times out of 264. This is deliberate
rather than a defect, because a quoted injection payload is still an injection
payload at the point of inference. The consequence for a reader is that the
false-positive rate for a team is not a property of their domain but the
proportion of their requests that quote attacker wording.

**The first non-zero false-positive rate in the project.**
`scenario_injection_chain` turn 13, `t014_hypothetical_safe_request`, is
labelled allow and is blocked. Its own note reads "control to avoid overblocking
hypothetical framing", so it is a control placed to catch this and it is
failing. The suite reports one harmless block over five allow-prompts, a rate of
0.2, and four leaks of ten. Two things recorded earlier were narrower than they
read: the zero-in-every-suite survey covered the seven domain suites and the two
scenario suites were outside it, and the denominator defect was recorded as
latent on the grounds that every surveyed suite reported zero. Neither statement
reached a public surface.

**Of 453 prompts, none is byte-identical to the text the gate evaluated.** The
approved request is forwarded byte-for-byte; the decision is made on its
normalised form. 359 differ by case and whitespace folding, 94 substantively. Of
the 168 labelled allow the gate passes 167, and 7 of those differ substantively
and are forwarded. In those 7 normalisation added text and removed none. Whether
the added text being harmless is rule design or luck is not measured.

**99 published archives are incomplete against their own signed manifests.**
They name `leaks_count.txt` and `harmless_blocked.txt`, and a repository ignore
rule meant those two files were never committed, so the documented verification
prints a failure on 34% of the archive. Disclosed in `docs/archive-errata.md`,
whose figures are generated rather than transcribed.

**43 of 292 certificates carry no `signing_key_id`.** With nothing to resolve,
the verifier fell through to `spec/sdl.pub`, which has held the new key since the
rotation, so the documented procedure reported a signature failure on 15% of the
archive. An absent field now resolves as `default`, which is what its absence
always meant.

**219 of 292 certificates are governed by no evidence contract**, because the
contracts begin at 2.2.0. They are not invalid: signature, binding and custody
verify. No contract governs their structure, and `verify_evidence.py` now says
so on every pre-2.2.0 archive. A further 105 pre-2.3.4 certificates cannot have
their ledger binding established, disclosed in
`docs/evidence-binding-correction.md`.

## Published claims corrected

Four public surfaces said things the evidence does not support. None was decided
in the sense of choosing between options; all four were corrected.

- The README claimed evidence that a given governance **configuration** actually
  enforces what it claims, in two places. Both now read **rule set**, because
  the pack measurement says the policy-shaped input changes no verdict, and a
  paragraph immediately after the goal sentence states what the evidence does
  and does not establish.
- The repository About description claimed to block policy-breaking requests and
  to serve regulated and insurable AI. The gate blocks requests matching its
  published rules; nothing supports attribution, which is the first thing an
  insurance conversation assumes, and naming a regulatory context with no
  behaviour behind it is the same defect as a statute-named template id.
- The `sir packs list` warning was stale: the constraint it described was removed
  by item 9.
- The homepage implied the naming of uncovered rows was independent of the gate.
  The list is generated by calling the gate's own rule function, so the
  prediction and the result are one function evaluated twice. The page now leads
  with that disclosure, deployed 12 October 2026. The same deploy replaced
  hardcoded run counts and the certificate decomposition with pointers to
  generated surfaces, added the errata link, and added an exclusion to the pilot
  page stating that SIR cannot attribute an action or an outcome to a specific
  user or session.

Two replacement wordings were themselves wrong and are recorded as such in the
claims register rather than quietly amended. The first About replacement claimed
a verifiable record of **every run**, which the 99 incomplete archives refuse,
and it reached two public surfaces before anyone noticed. A register row also
asserted that nothing supported the insurance half, which overstated it and was
written without reading the publication it concerned.

## How this release's own process failed

Recorded because a release whose condition is that its evidence survives
inspection should say how its own production did not. Every item below was caught
by a guard rather than by luck, and each one changed how the next piece of work
was built.

**Two commits reached origin red.** In both cases the suite was not re-run before
the push. It is 754 tests and takes about 45 seconds.

**A version guard could not see a new file until it was committed.** It built its
file list from `git ls-files`, so a new version-bearing document was invisible to
it, passed locally, and failed on the first run after the commit. It now also
scans untracked files that are not ignored, and it caught the next two cases
before the commit rather than after.

**Three harness errors produced false results, and one produced a false defect.**
A measurement harness reached the gate through an invented call signature and
reported every prompt blocked, including a plainly benign one, while every suite
reported no harmless blocks. A failure-path harness reported a fail-open defect
that did not exist: the policy file it corrupted was not the one the gate reads,
and then the gate kept loading from the repository, because a symlinked `src/`
resolves back to it and the runner inserts its own directory's `src` ahead of
`PYTHONPATH`. A row-counting tool reached the correct published total of 453
through two errors that cancelled, missing a `content_b64` row and counting the
deliberate-failure canary.

The pattern in all three is assertions about the environment rather than about
the subject. The harnesses now carry positive controls that must fire, and
per-case checks that the path under test was actually reached, and the
measurement tests assert per-suite counts rather than only a total. A result that
is uniformly clean or uniformly negative is treated as a harness fault until
shown otherwise.

**A verification record named a surface it had not tested.** Item 8 ends on a
human check of the live site, which is stated in the checklist rather than made
to look automated. That record first read 9 October against the production
hostname. What was checked on 9 October was a preview deployment; production went
live on 12 October and was checked then. Corrected in place, because a
verification record naming a surface it did not test is precisely the defect the
item was written to prevent.

**A deploy bundle shipped with every directory unreadable.** Rebuilding the
website archive reconstructed its directory entries from their names alone, which
dropped the mode bits and left every directory at `0600`, so the deploy failed
before any page was served. The rebuild now copies each entry's own metadata.

## The independent pre-release review, and what it changed

2.4.0 was reviewed before release by a party that did not build it, working
read-only from a pinned revision, with a second model contributing a further
fourteen items. The response, with every finding confirmed or rebutted against
source, is held outside this repository in the private operations record. What
it changed here is below.

**Most of it confirmed the backlog rather than finding defects.** Eleven of the
fourteen follow-up items were already recorded in `docs/backlog.md`,
`docs/archive-errata.md` or `docs/key-governance-readiness.md`. A reviewer with
no access to those documents re-derived them and found almost nothing outside
them.

**Eight expected-block prompts that pass the gate turned out to be the published
uncovered rows.** `account_recovery_fraud` publishes five by identifier and
`eu_ai_act_compliance_pressure` publishes twenty-six; all eight are among them.
The gate did what the published coverage says it will. That is the bounded claim
working, observed by someone who did not know it was the claim.

**Four corrections were made, and three are in this release.**

*Runner evaluability was derived from the wrong field.* `tools/rule_coverage_report.py`
used each suite's own `pack_id` where the runner resolves through the registry's
`enforcement_pack`. `docs/rule-coverage.md` and `docs/domain-packs.html`
published `account_recovery_fraud`, `mental_health_clinical`,
`scenario_injection_chain` and `scenario_tool_injection` as not runner-evaluable,
and stated that running such a suite evaluates no prompt content. The runner
evaluates every row of all four. `docs/coverage.json` never carried the column,
so the website's limits table was unaffected. The derivation now mirrors the
runner, the markdown table is generated rather than transcribed, and
`tests/test_runnable_suites.py` holds the two in agreement for every registry
entry.

*The benchmark run marker published unknown as a verdict.* An absent, malformed
or unrecognised certificate result became a conclusive `FAIL`, where the
single-run marker already refused. Neither publishes a false pass and they are
not equally true: a conclusive failure describes a run the evidence does not
describe. Both markers now recognise the same three results and raise on
anything else.

*A green branch dispatch did not require a conclusive certificate.* `AUDIT_PASS`
is computed from three counter files before the certificate exists, and the
certificate has six inconclusive conditions that computation cannot see. On
`main` the run marker wrote the certificate's verdict back and caught them; it is
publication-gated, so on a branch dispatch nothing did, and a job could go green
while its own certificate said the run was inconclusive. That dispatch is what
`docs/key-custody.md` step 5 tells an operator to run before calling a key
rotation complete. The finalize step now requires the counters and the
certificate to agree, unconditionally, so a divergence between two independently
computed sources is a visible failure rather than a silent preference for one.

*`sir packs list` hid an active suite and implied an enforcement pack that may
not exist.* It filtered on visibility, which hid `mental_health_clinical`, whose
`encoded` class exists so its prompts are not in plaintext. That is a reason
about content and the command prints none, while the suite's existence was
already published on two surfaces. It now filters on status and prints
`visibility` and `enforcement_pack`, which also closes the backlog row about
registry discoverability being read as execution availability.

**The 453-prompt six-pack measurement was repeated at this revision.** 453
prompts from the eight active registry suites were evaluated under each of the
six ISC policy packs, 2718 gate evaluations in total. No prompt's status, reason
or triggered rules differed across the six, and the six packs produced six
distinct `configuration_hash` values. The 8 October figure reproduces.

The first version of this section argued that a rerun was unnecessary instead of
running one, on the grounds that every input to the original was unchanged. That
argument was wrong twice. It was incomplete, because the configuration identity
hashes the source of several normalisation helpers that the argument did not
enumerate, and it was unnecessary, because the rerun takes about one second. An
estimated cost was used to avoid work that was cheaper than the estimate. The
measurement is now a measurement.

**The commit making those corrections was itself reviewed, and needed six
more.** The review was run against a pinned revision of the correction commit,
read-only, before any of it was released. Four of the six were introduced or
left behind by that commit; two are older code the review reached while reading
it. A seventh item below was introduced by the fix for the first one and found
by mutating it.

*Two tests passed under mutations of the behaviour they exist to prevent.* The
branch-dispatch test checked publication gating only on lines mentioning
`AUDIT_JSON`, which is the certificate's existence guard and not its result
comparison, so gating the comparison alone passed the test and reopened the gap
it closed. The `packs list` test is named for every active registry entry and
asserted that at least four rows differed from their own identifier, so dropping
a same-named active suite passed. Both are now derived from the thing they
describe, the first from the two guards that make up the check and the second
from the registry, and both fail under the mutations that passed. Three
mutations of the same commit had already been run and two of those passed on the
first attempt, so this is the second time in one release that mutation testing
found a test asserting the wrong thing. The difference is who ran it: the first
two were found here, and these two were not, because the mutations that would
have caught them were not the ones chosen.

*Correcting one of those tests produced a test that failed on unmutated code.*
The first correction asserted that no conditional anywhere in the finalize step
is gated on the publication context, which reads like the general form of the
defect and is false: the step already carries a correct publication-gated
conditional requiring the run marker's status. It is scoped to the certificate
check now. A wider invariant is not a safer one when the code does not hold it,
and only running the mutation showed which it was.

*Two numbers in the published description of the certificate gate were wrong.*
The release notes, the workflow comment and a test docstring all said the
certificate has four inconclusive conditions the counter script cannot see.
`_compute_audit_result` has seven conditions, six of which that script cannot
see, and the three descriptions omitted a failed domain-pack load and an
all-attempts-failed provider path entirely. The same sentences described the
live provider condition as every provider call failing, where the code is any.
The number came from counting the conditions its author had in mind rather than
the conditions in the function.

*Four documents described the behaviour `sir packs list` had before this commit
changed it.* `README.md`, `tests/domain_packs/README.md`,
`tests/domain_packs/mental_health_clinical.md` and the introduction to the
suite table in `docs/backlog.md` all still said the command filters on
visibility, and two of them still said four active suites produce systemic-reset
blocks rather than evaluating their rows. That stopped being true on 8 October.
A run of all four now reports zero systemic resets and the published per-suite
figures. The commit that changed the behaviour is the commit that left the
documentation describing the old behaviour, which is the same defect as a figure
nobody regenerated, with prose in place of the figure.

*A document could be silently corrupted by the generator that owns its region.*
`replace_generated` required exactly one opening and one closing marker and then
did slice arithmetic that is silent when they are in the wrong order: with the
end marker first, the text before it was replaced and everything between the two
markers was deleted. A corrupted published surface and a correct one are the same
kind of file. This predates the correction commit. The archive generator
already had the check; the coverage generator never did.

*A failed publication run could leave the published set disagreeing with
itself.* Both generators wrote each surface as they rendered the next, so a
marker error in a later surface left the earlier ones updated and the rest
stale. This also predates the correction commit, and the review named it in the
coverage generator only; the archive generator had the same shape and is fixed
with it. Every refusal the inputs can cause is now reached before the first
write. Neither is atomic and neither claims to be.

*A malformed certificate failed CI with a stack trace.* The finalize step parsed
the certificate with an inline `python -c` that raised under `set -e`, so the
explanation of what was being checked never printed, and a certificate with no
`result` printed an empty string, making two different failures look the same.
That is now `tools/read_certificate_result.py`, which never raises and names
which failure it was, for the reason `tools/ci_audit_verdict.sh` is a file: a
rule nobody can invoke cannot be exercised.

## What is not claimed

No claim about false-positive rates for any customer workload. The measured
figures are for the corpora named, with their sampling methods.

No claim that the evidence establishes causal responsibility for a verdict. It
establishes which configuration was present, that it was computed from the
artefacts loaded, and that it did not change during the run.

No claim about attribution. SIR has no actor, user, session or principal field
and observes neither the model's output nor any downstream action.

## Known open items

**The scenario suites diverge from their published figures.** Three archives
carry `scenario_injection_chain`, all April 2026 at SIR 1.0.2, all reporting
zero harmless blocks and zero leaks. Today's run reports one and four. Whether
the rules changed or the suite changed is not established. Both scenario suites
are pinned to current behaviour so the drift cannot widen unnoticed.

**No registry suite exercises what the domain packs configure.** Closing it needs
a suite whose prompts differ in outcome across packs, which changes suite hashes
and coverage denominators and is therefore a benchmark-content decision with an
evidence rerun.

**The historical set and key revocation.** Every published certificate was
signed by the registry entry `default`. Revoking it rather than retiring it would
refuse 268 of 292 archives, because only 24 carry a parseable run identity.
Nothing is refused today. The superseded private key was destroyed on 8 October
and the record is in `docs/key-custody.md`.

Both of the first two are tracked in `docs/backlog.md`.

## Verifying this release

Three commands, from a clone, with no credentials and no network:

```
python3 tools/check_release_checklist.py --run-commands
python3 tools/demonstrate_failure_paths.py
python3 tools/verify_evidence.py docs/runs/<run id>
```

`docs/reference-demonstration.md` is the unaided reproduction path for item 7.
`docs/claims-register.md` is the shortest route to what this release does and
does not support.
