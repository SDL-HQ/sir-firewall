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
register, and two public surfaces still carry claims recorded below as not
surviving examination: the repository About description and the website
homepage. They are listed under `blocked_on` in `release-checklist.json` and the
replacement wording is Ryan's to write. A register that ticked its own item
while the surfaces it audits were unchanged would be the defect it was built to
find.

The README's two wordings were corrected on 8 October rather than carried as
decisions, because the correction was a word rather than a position.

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

Current text: *"Building SIR: deterministic pre-inference governance gate.
Blocks policy-breaking requests. Signed, offline-verifiable audits for
regulated/insurable AI. MIT."*

**open.** Carried as "simply false, corrected on sight" since 2 October without
a record of which part is wrong. Two candidates, both real:

- **"Blocks policy-breaking requests."** The gate blocks requests matching its
  deterministic rules. "Policy-breaking" invites a reader to think the
  organisation's policy determines the block, and the pack measurement says the
  policy-shaped input changes no verdict. The accurate form is close to "blocks
  requests matching its deterministic rules".
- **"for regulated/insurable AI."** Nothing supports the insurance half. SIR
  cannot attribute an action to a person: there is no actor, user, session or
  principal field anywhere in the gate, and it is input-only and pre-inference,
  so it observes neither the model's output nor any downstream action. That is
  the first thing an insurance conversation assumes is possible.

**Decision required** on the replacement wording. This is public copy and it is
Ryan's to write.

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

**Decision required**: qualify it, or lead with the disclosure instead of the
match.

Four items from this release now need to reach the site when it is next touched:
the errata link, the pack measurement, the use-versus-mention limit, and the
rule-set wording corrected on the README on 8 October.

*Coverage: outside.* The rule-coverage report is a build artefact. The patent
boundary note places the coverage reporting work outside the specification, and
the uncovered-row list it generates is not recited.

---

## What this register does not cover

**Item 7 is not built**, so no claim about downstream call suppression appears
here. SIR's zero-downstream-call behaviour on failure paths is asserted in the
architecture and not yet demonstrated by a reproducible harness. No public
surface should claim it until item 7 lands.

**No claim about false-positive rates for any customer workload.** The measured
figures are for the corpora named, with their sampling methods. A rate for a
real team depends on the proportion of their requests that quote attacker
wording, which is a property of their work and not of SIR.

---

## Decisions this register surfaces

1. **The About description.** Replacement wording.
2. **The homepage uncovered-row claim.** Qualify it, or lead with the
   disclosure.
3. **Whether `mental_health_clinical`'s rule-coverage figure of 5 of 15 stays
   published** now that the suite runs and reports 10 leaks of 25. The two are
   different measurements and both are now available.

The configuration-enforcement claim was the first entry on this list and is now
corrected rather than decided. The website wording that matches it is queued.

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
