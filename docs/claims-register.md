# Claims register

Every public technical claim SIR makes, and whether it survives a reader who
goes looking for the failures.

Item 8 of the 2.4 release. The condition is not that the claims are impressive;
it is that each one **remains true when the reader examines the failures**. A
claim that is true only while nobody checks is the thing this register exists
to catch.

Last reviewed 8 October 2026 at SIR 2.3.8, on the `release/2.4` branch.

The release item this register serves stays **open** while it exists, and
deliberately so. The condition is about the claims rather than about the
register, and one public surface still carries a claim recorded below as not
surviving examination: the website homepage. It is listed under `blocked_on` in
`release-checklist.json`. A register that ticked its own item while the surface
it audits was unchanged would be the defect it was built to find.

The README's two wordings and the repository About description were all
corrected on 8 October rather than carried as decisions. The About description
is a repository setting with no deploy bundle, so it had no reason to wait on
the website pass; the homepage does.

## How to read this

**Status** is one of:

| | |
|---|---|
| **holds** | True, and it survives inspection of the failures. |
| **qualified** | True as written, but a reader examining the evidence finds something the claim does not prepare them for. The qualification is stated here and in the surface itself. |
| **corrected** | Was false or stale. The surface has been changed. |
| **open** | A decision is required before the surface is changed. Named, not deferred silently. |

**Coverage** records whether the feature sits inside the filed specification
(US 19/820,502) or outside it, per
`claude/patent-coverage-boundary-2026-10-05.md`. This column exists so that
nobody tells a buyer a feature is covered when it is not, and so that valuable
material is not discovered to be undescribed at contest time. It is not legal
advice and it is not a determination of patentability.

The boundary is fixed: nothing shipped after 25 September 2026 can be added to
that application.

---

## README.md

### "Deterministic pre-inference governance gate, rules-only"

**holds.** No embeddings, no scoring, no model in the decision path. The
deciding code is `deterministic_rules.py` and the normalisation functions, both
covered by `configuration_hash`.

*Coverage: inside, claimed.* Claims 1 and 14 recite deterministic rule
evaluation and a binary decision without model inference.

### "It claims deterministic enforcement and verifiable evidence for a given policy and test suite"

**corrected.** Both halves were true. The defect was what "a given policy"
meant to a reader, and the word now reads **rule set**.

Measured 8 October 2026: across 453 prompts in all eight registry suites, run
under each of the six ISC policy packs, every per-prompt status and triggered
rule was identical, while the signed `configuration_hash` differed for every
pack. The baseline policy and the deterministic rules decide; the **domain pack
does not change any verdict these suites measure**.

So "for a given policy" was true of the baseline policy and misleading if a
reader took "policy" to include the domain pack. A pack must load, and selecting
a suite whose declared pack does not exist now fails at resolution rather than
producing a run in which every row is a systemic reset, but which pack loads
changes nothing these suites measure.

Recorded in `docs/threat-model.md` as a third category beside derived and
asserted fields: derived, correct, signed, and not load-bearing.

*Coverage: inside, not claimed.* Domain packs appear throughout the
specification, 63 mentions, including content hash over the canonical dataset
and rejection on an absent or unsupported pack. They are in the amendment
reservoir rather than in the claims.

### "produce verifiable evidence that a given governance configuration actually enforces what it claims"

**corrected.** This was the sharpest claim on any surface and the one the pack
finding bore on most directly.

The evidence does establish that a particular configuration was present, was
computed from the artefacts actually loaded rather than asserted by the caller,
and did not change during the run. That is what item 2 of this release set out
to make true, and it is true.

It does not establish that the configuration was **causally responsible** for
any decision. For every published run, the same verdicts would have been
produced under any of the six packs.

Three forms were available, in increasing order of modesty: an identity claim
("identified and unchanged during the run"), the same enforcement claim over the
thing that actually decides ("a given rule set actually enforces what it
claims"), and keeping the sentence with the measurement beside it. The second
was taken. The first retreats from something the archive does demonstrate, which
is the same error in the other direction; the third leaves a misleading word in
a sentence a reader stops at.

The README now reads **rule set**, and the paragraph immediately after it states
both what the evidence establishes and what it does not, including the
measurement and the guard against the opposite overclaim. The website carries
the same wording and is queued in `claude/website-changes-queued.md` rather than
changed here, because the site is a separate deploy bundle.

*Coverage: inside, partly claimed.* Claim 4 recites a configuration hash from a
policy file loaded at initialisation. Paragraph [0086] supports the broader
version covering rule group versions and rule parameters, which is stronger and
unclaimed.

### "The run archive always contains per-run artefacts for both passes and failures"

**qualified.** True as intended: failures are archived, not only passes, and the
archive holds 292 runs including failed and inconclusive ones.

A reader who examines the failures finds something the sentence does not prepare
them for. **99 archives published between April and September 2026 name
`leaks_count.txt` and `harmless_blocked.txt` in their signed manifests, and a
repository-wide ignore rule meant those two files were never committed.** The
receipt verifier reports `file listed in manifest is missing` for every one.

Disclosed in `docs/archive-errata.md`, whose figures are now generated rather
than transcribed and are held by `tests/test_archive_errata_figures.py`. The
README sentence should cross-reference the errata; it currently does not.

*Coverage: inside, claimed.* Claims 5, 11 and 18 recite latest-audit and
latest-run as distinct truth surfaces.

### "A proof-producing system (signed certificate, fingerprint, ITGL hash chain, and per-run archives)"

**qualified.** All four artefacts exist and verify. Three qualifications a
reader finds on inspection:

- **219 of the 292 published certificates are governed by no evidence
  contract.** The contracts begin at SIR 2.2.0 and 219 archives predate it. They
  are not invalid; signature, binding and custody verify. No contract governs
  their structure. Now disclosed by behaviour: `tools/verify_evidence.py`
  reports it on every pre-2.2.0 archive.
- **All 292 report `counters_checked_against_ledger: false`.** Their ledgers
  predate the fields needed to recompute the signed counters. False means not
  checked, which is not agreement, and the contract says so in those words.
- **105 pre-2.3.4 certificates cannot have their ledger binding established.**
  Before 2.3.4 `itgl_final_hash` came from an environment variable or a mutable
  file. Disclosed in `docs/evidence-binding-correction.md`. Every certificate
  from 2.3.4 onward matches its ledger, 24 of 24.

*Coverage: inside, claimed.* Chained audit entry and signed proof artefact
(claims 1, 14); offline verification without access to the originating system
(claim 9); per-run regeneration from genesis (claims 13, 19). The
`trust_fingerprint` composition at [0232] is inside and unclaimed.

### "`sir packs list` ... does not guarantee that a same-named ISC policy pack exists"

**corrected.** Stale as of `a787ed1`. The constraint it warned about is gone:
every registry entry now declares the ISC policy pack it is enforced under,
separately from its own identifier, and selecting a suite whose declared pack
does not exist fails at resolution rather than producing a run in which every
row is a systemic reset.

Four of the nine entries had been unrunnable since `e0ee45d` on 16 April 2026.

*Coverage: inside, not claimed.* "Rejection on absent or unsupported pack" is
described in the specification. Item 9's fast failure moves the implementation
toward the described behaviour.

### Zero downstream calls on failure paths

**holds, bounded to SIR's own code.** No code path in SIR can issue a
downstream call unless the gate returned `PASS` and the call flag is enabled.

That is a universal, and it rests on the topology rather than on a harness. The
route to a provider is one choke point: `_maybe_call_model` and
`_call_provider_model` each have exactly one definition and one caller, the call
site is guarded on the verdict and the flag, the inner function refuses before
doing anything when calls are disabled, every provider invocation is inside the
leaf, the availability-probe import is asserted never to be called, and
`src/sir_firewall/` imports nothing capable of a network call. A module that
cannot reach the network cannot make a downstream call on any path, exercised or
not.

`tests/test_no_downstream_call_without_approval.py` holds all of it, and was
verified against seven mutations of a scratch copy, each of which failed a test.
A structural test that has never been shown to fail is worth nothing.

**The observation is a separate and weaker claim**, deliberately: on each
failure path the harness exercises, zero downstream calls were observed. A
harness cannot support the word "all", because it sees only the paths it runs.
`tools/demonstrate_failure_paths.py` runs the real runner in live mode with a
counterfeit provider client that records and raises, carries a positive control
that must fire, and refuses to report anything if a case did not reach the path
it claims to exercise. The paths it cannot construct are named in
`docs/reference-demonstration.md` rather than omitted.

**Neither half covers an integrator who ignores the verdict.** A caller that
reads `BLOCKED` and calls the model anyway is outside both, and nothing in SIR
can prevent it. That is the same boundary as the attribution gap.

*Coverage: outside.* The reference harness is product work. The boundary note
treats items 1, 4, 6, 7 and 8 as outside the specification unless something
specific turns up, and nothing here did.

### "approved calls preserve the evaluated content"

**qualified, and the qualification is the whole of it.** The sentence reads two
ways and only one is true.

The approved request is forwarded byte-for-byte when the call flag is enabled,
which is what the single call site does. What the model receives is not what the
rules matched: the gate decides on the normalised payload and the runner
forwards the raw prompt.

Measured over 453 prompts in the eight registry suites: **none is byte-identical
to the text evaluated.** 359 differ by case and whitespace folding alone and 94
differ substantively. Of the 168 labelled allow the gate passes 167, and 7 of
those differ substantively and are forwarded. In those 7 the evaluated string
contains the forwarded string, so normalisation added text and removed none:
` override` five times, ` bypass`, ` human oversight`.

So the gate decided on text it had partly added, which is the non-idempotent
marker recovery recorded above. For these 7 that addition did not cause a block.
**Whether that is rule design or luck is not measured**, and no surface says
otherwise.

Two prompts have the reverse shape, where the evaluated form does not contain
the forwarded one. Both are a base64 wrapper replaced by its decoded payload, so
the wrapper's rule hit disappears because the wrapper did. Both are blocked.
They are why no surface says normalisation only ever adds.

*Coverage: inside, claimed in part.* Claim 2 recites the normalisation modes and
claim 9 offline verification without access to the evaluated content. The
difference between the evaluated and the forwarded string is not recited.

### "Deterministic and explainable (rules-only; no embeddings, no hidden scoring)"

**holds, and as of this release it is checked rather than argued.** The
rules-only half rested on an argument about the design, which is the weakest
form of evidence in this register and the form it exists to find.

Rules-only is a property of what the deciding code imports, so it is derived
from the source rather than stated. The whole of `src/sir_firewall/` imports the
standard library and `cryptography`, and nothing else: no model client, no
numeric library, no tokeniser, nothing that could compute a similarity score.
`tests/test_no_model_in_the_decision_path.py` fails if that changes, and names
the import and the file it appeared in.

The model client is where the claim implies it is. `litellm` is declared in the
`live` optional extra and not in `dependencies`, so installing the gate does not
install it, and it is imported at three call sites in `red_team_suite.py`, all
of them after the gate has returned a verdict. Both directions are asserted, so
the claim fails if a client reaches the gate and also if the suite stops using
one, which would mean the separation no longer separates anything.

Deterministic is measured: 8 registry suites run under each of 6 policy packs,
48 runs over 453 prompts, and each suite produced one verdict fingerprint across
all six. Identical inputs gave identical per-prompt status and triggered rule
every time.

Explainable is held by behaviour. A blocked row carries `triggered_rule` and
`rule_hits`, pinned by `tests/test_row_is_self_describing.py` and
`tests/test_rule_metadata.py`.

*Coverage: inside, claimed.* Claim 6 recites rule families used and found to
produce no match, recorded on the decision.

---

## docs/failure-modes.md and docs/assurance-kit.md

### The boundaries list

**holds, newly complete.** One limit was missing from it until `0d48fa3` while
being treated as acceptable-because-disclosed:

**A request containing attacker wording is blocked whether or not the
surrounding request is defensive.** SIR draws no distinction between using such
wording and quoting it. Measured over published NCSC and ICO guidance: 220
requests of that guidance in five task shapes were all allowed; the same
passages inside a staff-awareness task with one quoted attacker phrase appended
were blocked 264 times out of 264.

This is deliberate rather than a defect. A quoted injection payload is still an
injection payload at the point of inference, and allowing it because the request
looks defensive would mean inferring intent from framing.

The consequence for a reader is stated: the false-positive rate for a team is
not a property of their domain but the proportion of their requests that quote
attacker wording.

**The registry suites contain an instance, found 9 October 2026, and it is the
project's first non-zero false-positive rate.** `scenario_injection_chain` turn
13, `t014_hypothetical_safe_request`, is labelled `expected: allow` and is
blocked. Its own note reads *"control to avoid overblocking hypothetical
framing"*, so it is a control placed to catch this phenomenon and it is failing.
The suite reports `harmless_blocked: 1` over 5 allow-prompts, a
`content_false_positive_rate` of **0.2**, and `jailbreaks_leaked: 4` of 10.

Two things that were recorded as true are narrower than they read. The survey
finding zero `harmless_blocked` in every suite covered the **seven domain
suites**; the two scenario suites were outside it. And the mismatched
false-positive denominator was recorded as latent, on the grounds that every
suite reported zero so both denominators evaluated to 0.0. Here they do not:
over the allow-prompts the rate is 0.2 and over everything evaluated it is
0.067, so the fix in `f277125` corrected a figure that is observable rather than
dormant. Neither statement reached a public surface, which was checked.

Three published archives carry this suite, all April 2026 at SIR 1.0.2, all
reporting `harmless_blocked: 0`, `jailbreaks_leaked: 0` and `AUDIT PASSED`.
Today's run disagrees. **Whether the rules changed or the suite changed is not
established**, and it is a named backlog row rather than a conclusion. Both
scenario suites are now pinned to current behaviour by
`tests/test_runnable_suites.py`, because the existing reproduction test covers
`account_recovery_fraud` alone, which is how a four-leak drift against a
published zero sat unnoticed.

*Coverage: outside.* Reported as a limit, not as a feature.

### The assurance kit's worked example

**holds.** Its documented output is pinned to the actual output by
`tests/test_canonical_example_run.py`, and a second test fails if the kit shows
an `UNKNOWN` property it does not explain. The example's own result is
`AUDIT FAILED`, 26 of 150 prompts leaked, and the kit says so.

---

## Other public surfaces

These two rows were `##` sections until 8 October, which meant the structural
checks in `tests/test_claims_register.py` never saw them: every parametrized
test reads `###` claim rows. The two claims the register had not yet closed were
therefore the two it was not checking. They are `###` rows now.

### The GitHub repository About description

Text until 8 October 2026: *"Building SIR: deterministic pre-inference
governance gate. Blocks policy-breaking requests. Signed, offline-verifiable
audits for regulated/insurable AI. MIT."*

**corrected.** Carried as "simply false, corrected on sight" since 2 October
without a record of which part was wrong. Three parts were, for three different
reasons:

- **"Blocks policy-breaking requests."** The gate blocks requests matching its
  deterministic rules. "Policy-breaking" invites a reader to think the
  organisation's policy determines the block, and the pack measurement says the
  policy-shaped input changes no verdict.
- **"for insurable AI."** This reads as a capability. The supporting material,
  the publication at `/insurable-ai/`, is an argument about the **preconditions**
  for underwriting AI, which is coherent and is not the same claim. The gate
  also lacks what an insurance conversation assumes first: SIR cannot attribute
  an action to a person. There is no actor, user, session or principal field
  anywhere in it, and it is input-only and pre-inference, so it observes neither
  the model's output nor any downstream action.
- **"for regulated AI."** Named a regulatory context with no behaviour behind
  it, which is the same defect as the statute-named template ids on the open
  decisions list. A shorter sentence does not make it a different problem.

Replaced 8 October 2026 with:

> Building SIR: deterministic pre-inference governance gate. Rules-only, no
> model in the decision path. Blocks requests matching its published rules.
> Signed, offline-verifiable audit records. MIT.

Every clause there is checkable, and "no model in the decision path" became a
tested claim rather than an argued one on the same day, in
`tests/test_no_model_in_the_decision_path.py`. The insurability argument stays
on `/insurable-ai/`, labelled as preconditions, which is what it is.

The same claim, shortened to 148 characters, is on X, where the limit is 160:

> Building SIR: deterministic pre-inference governance gate. Rules-only, no
> model in the decision path. Signed, offline-verifiable audit records. MIT.

#### Two corrections to this row, both made on 8 October

Recorded rather than quietly amended, because a register that cannot correct
itself is the thing it was built to catch.

**It said "Nothing supports the insurance half."** That overstated it and was
written without reading the publication at `/insurable-ai/`, which is a coherent
argument about the preconditions for underwriting AI. The defect is that the
About description read as a capability, not that the argument is absent.

**The first replacement wording claimed too much, and it was published before
anyone noticed.** It ended "signs an offline-verifiable record of **every
run**". The original description said "Signed, offline-verifiable audits" with
no quantifier, which survives inspection; the universal was introduced in the
replacement. It does not survive: running the documented one-command
verification on any of the 99 archives in Appendix A of
`docs/archive-errata.md` prints `VERDICT: FAILED` and exits 2, because their
signed manifests name two files a repository ignore rule kept from ever being
committed. A reader doing exactly what the sentence invites falsifies it on 34%
of the published archive.

That is the same defect class as the "configuration" wording corrected earlier
the same day: a true-sounding sentence that invites a conclusion the evidence
refuses. It got past this register, its tests, and two reviewers, which is worth
knowing about all three. `tests/test_claims_register.py` now fails if any
surface claims every run verifies while that errata list is non-empty, and will
fail again if the list is ever emptied, because then the stronger claim becomes
available and this row should say so.

*Coverage: inside for the blocking half, claimed; outside for the insurance
half.*
Claims 1 and 14 recite deterministic rule evaluation and a binary decision
without model inference. Nothing in the 64 pages recites an actor, user, session
or principal, so the attribution an insurance conversation assumes is neither
implemented nor described, and no amendment can add it.

### The website homepage uncovered-row claim (structuraldesignlabs.com)

The site is not changed in this release by decision: the figures move every
release and it is a separate deploy bundle. The audit is recorded in
`claude/website-changes-queued.md`.

**open**, and it is the site's central claim. The homepage's uncovered-row claim
implies the naming of uncovered rows was independent of the gate, and it was
not. The list is generated by calling the gate's own rule function. The
agreement is one function evaluated twice, which is a useful regression guard
and not the independent confirmation the page implies.

**Decided 8 October 2026: lead with the disclosure.** Qualifying leaves the
match as the headline and the correction as a footnote, which is the structure
rejected on the README earlier the same day. Leading with it converts a near
tautology into the part of that page a customer can actually check. The
replacement paragraph is in `claude/website-changes-queued.md`.

**Still open**, because the decision is not the change. The site is a separate
deploy bundle and the sentence is live until it is pushed. This row closes when
the deploy is up and the live paragraph matches the queued wording, not when the
queue file exists.

Four items from this release now need to reach the site when it is next touched:
the errata link, the pack measurement, the use-versus-mention limit, and the
rule-set wording corrected on the README on 8 October.

*Coverage: outside.* The rule-coverage report is a build artefact. The patent
boundary note places the coverage reporting work outside the specification, and
the uncovered-row list it generates is not recited.

---

## What this register does not cover

**No single claim about downstream call suppression**, because one piece of
evidence cannot carry the universal and the observation. Item 7 landed on
9 October 2026 and the two halves are separate rows below, with separate scopes.

**No claim about false-positive rates for any customer workload.** The measured
figures are for the corpora named, with their sampling methods. A rate for a
real team depends on the proportion of their requests that quote attacker
wording, which is a property of their work and not of SIR.

**Four of the five surfaces carrying the description cannot be tested from
here.** The same sentence now lives on the README, the GitHub About field,
LinkedIn, X and the website. Only the README is in version control, and it is
the only one a test can read. The other four drift silently: nothing fails if
one of them is edited, and nothing fails if one of them is left behind when the
wording changes, which it did twice on 8 October.

The register is the only record that the five are meant to agree, and the
wording for each is written out here so a reader can compare them by eye. That
is a weaker guarantee than the repository surfaces have and it is stated rather
than implied. The first thing to check when any of these claims is questioned is
whether the four untested surfaces still say what this row says they say.

---

## Decisions this register surfaces

1. **Whether `mental_health_clinical`'s rule-coverage figure of 5 of 15 stays
   published** now that the suite runs and reports 10 leaks of 25. The two are
   different measurements and both are now available.

Three entries have left this list since it was written, and none of them was
decided in the sense the list meant. The configuration-enforcement claim, the
About description and the homepage framing were all corrected instead. A list of
decisions that empties by correction rather than by choice is the outcome this
register was built for.

## One patent consequence of this release, recorded here because it changes a parked decision

`claude/patent-coverage-boundary-2026-10-05.md` parked a second application for
generator-side refusal, to be revisited **only if
`enforced_policy_matches_signed_policy` survives evidence contract v4 and cash
allows**.

**It survives.** The field is in v4's required set, confirmed 8 October 2026 in
`628f22f`. One of the two conditions on that parked decision is now met.

The feature is **outside the filed specification entirely**: "generator",
"refuse", "refusal", "decline" and "withhold" appear zero times in the 64 pages.
The disclosure cut-off is **24 September 2027**, and the cheap route recorded is
an NZ provisional to hold the date rather than a full filing.

This register does not reopen the decision. It records that the condition it
waited on has been satisfied, so the decision is now live rather than parked.
