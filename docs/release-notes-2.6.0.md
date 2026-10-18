# SIR 2.6.0 release notes

Three items, and they are the same defect three times: two different facts
reported through one value, where one fact is about the counterparty and the
other is about us. Collapsing them reports our own limitation as the other
party's failure, which is the only defect class in this project that reads as
dishonesty rather than as a limit.

## A check that could not run is not a bad signature

`_verify_signature` in `core.py` returned a bare false for a signature that
does not verify, an absent cryptography library, a key the registry does not
know, and a programming error in our own verifier. One value, four meanings,
one of which is a statement about the request and three of which are
statements about us.

It now returns one of the `SIGNATURE_*` reasons, and the `crypto_signature`
ledger row records which, plus `signature_established` so a consumer does not
keep its own list of which reasons mean what. `invalid` is the only reason
that is about the request.

Enforcement is deliberately untouched. A broken check still blocks under
`CRYPTO_ENFORCED`, because failing closed was never the defect. The record
was.

The ITGL row's `output` is a free-form dict covered by the row hash, so the
new field needed no schema or version bump and every published ledger still
verifies against its own hashes unchanged.

## The verdict is recomputed rather than trusted

`counter_disagreements` recomputed every input to the verdict and nothing
recomputed the verdict. `compute_audit_result` lived in
`generate_certificate.py`, which is not in the minimal verification bundle and
is called by no verifier. So the field that gates canonical publication, the CI
outcome and the public homepage was the one derived value with nothing behind
it.

Measured on a copy of a published certificate, with the counters left truthful
so that only the verdict was wrong:

    result: "AUDIT FAILED" with jailbreaks_leaked: 0   -> validator exit 0
    result: "AUDIT PASSED" with jailbreaks_leaked: 7   -> validator exit 0

The signature meant no third party could forge either. It never meant a
producer could not sign one.

`compute_audit_result` now lives in `tools/itgl.py`, inside the bundle a third
party gets, and the generator imports it rather than holding a copy.
`verify_certificate.py` recomputes `result` from the derived counters and the
certificate's `proof_class` and reports disagreement under exit 11, as it does
for the counters and the configuration identity. `configurations_observed` is
derived from the rows too: it was the one input of six read from
`proofs/run_summary.json`, the file that sits on disk even in a job where the
audit never ran.

Recomputed over the archive when this landed: 68 of 68 certificates with
derivable rows agree with their signed string, and the older ones report not
checked. No published status moved.

## A provider declining is the provider deciding

`provider_call_failures` incremented identically for a timeout and for a
provider refusing the content. A timeout is us failing to complete a call; a
refusal is the provider working. Both drove a `LIVE_GATING_CHECK` certificate
to `INCONCLUSIVE` for reasons a reader could not distinguish.

There is now a `declined` provider-call outcome and a `provider_call_declined`
counter at row version 2, with a v2 baseline record schema. Documents that
make provider calls carry `refusal_detection` and `provider_output_limit`, so
two runs' figures are comparable or visibly not.

The limit is stated rather than hidden, because it was measured rather than
expected: **the detection rule fires on nothing in the archive.** All 24
content refusals in the published history record their class as `APIError`,
and the rule looks for litellm's `ContentPolicyViolationError`, so
`provider_call_declined` reads zero on every run ever published. The mechanism
is right and the predicate does not fire on the one provider there is evidence
for. Widening it would make a signed counter depend on an error string the
provider can reword, or would swallow 1,273 errors that are ours rather than
theirs. Both are recorded as rows instead.

## What this release found about itself

**An unread counter stopped being a missing check and became a guaranteed
disagreement.** Recomputing a signed value is the fix above. Its price is that
the producer and the verifier must take the same inputs, and nothing enforced
that. `provider_call_declined` was derived by the verifier and left unread by
the generator, so the keyword defaulted to zero at signing. Measured: a
`LIVE_GATING_CHECK` run whose every provider call was declined computed
`INCONCLUSIVE` at signing and `AUDIT PASSED` from the rows, so an honest
certificate was refused at exit 11 by the check meant to protect it. Shipped
broken in one change and fixed in the next, in this release.

**A fixture asserted a verdict its own rows contradicted.**
`test_an_honest_certificate_verifies` had asserted exit 0 since 8 October for a
certificate reading `AUDIT PASSED` over rows carrying a leak, a harmless block
and a reset. It derives its result now, because writing the corrected literal
would have restated the same defect at a better value.

**The publication guard was silent on account identifiers.** A provider's
verbose content refusal carries organisational identifiers in its error body,
and the runner writes provider error text verbatim into the attempts log,
deliberately, because an error's class and code are evidence. Thirteen such
refusals reached six tracked files and `offences()` returned nothing for any of
them, because an account identifier is not a credential and no rule described
one. Measured when it was found: zero matches for every credential pattern
across 5,646 published artefacts, so no key has ever been published. The
guard's silence was the defect rather than the publication.

Three things about that were only visible by running something. The detector
matched its own placeholder, so a file the redactor had just cleaned still read
as an offence. Redaction has to happen before truncation, because truncating
first can cut an identifier in half. And a comment explaining the rule carried
the shape the rule refuses, which the guard caught on its own source.

**The credential check stripped a value only to decide whether it was empty.**
Nothing in SIR reads the provider credential, because litellm reads the
environment itself, so a key pasted with a trailing newline passed and failed
at the provider with an error naming no whitespace. It is refused up front now,
and not stripped: repairing it would leave the value SIR validated and the
value the provider receives as two copies of one identity.

**The verdict tool established a property from the document it was checking.**
`verify_evidence.py` reports its "signed counters" property from the
certificate's own `counters_checked_against_ledger` field, and
`verify_certificate.py` printed a note and exited 0 when the rows could not be
derived from. So a certificate asserting the flag over an underivable chain
version 2 ledger produced "the signed counters were recomputed from the rows
the certificate binds" about a recomputation that never ran. A value read from
the document instead of derived from the rows, in the tool the assurance kit
tells a reader to prefer. The refusal is narrow: a certificate may say the
check did not happen, and only an unsupported claim is refused. Measured over
all 369 published run directories before and after: 77 established, 184 not
established, 108 failed, identical. Found by an outside review and confirmed by
building the document.

**The version inventory kept two copies of the version list.** Adding the
history symbol for the previous release to one of them left every mutable
pointer failing with an empty counter: the version was recognised and
unmatchable at the same time. One tuple now, two readers. A second copy of an
identity, in the test that exists to guard version identity.

## The gate and the runner are frozen from here

Development stops at 2.6.0 rather than continuing quietly, and that is stated
here rather than left to look dormant, as it was at 2.3.6.

The reason is a measurement rather than a mood. The last cycle found defects
across the whole severity range and treated them all with the same urgency:
one of them was a verifier establishing a property from the document it was
checking, and another was a published figure with no date on it. Both got a
change. Nothing sorted them, because the machinery that finds defects here is
better than the judgement that triages them, and a project with no shipping
pressure will let that machinery set the agenda indefinitely.

So the seven rows added to `docs/backlog.md` this release stay rows. That is
what `docs/release-criteria.md` says a row is for: the difference between a
release that ships with its limits recorded and one that waits for a condition
nobody wrote down.

What is not frozen: the evidence format, which is being worked on separately,
and conversations with the people who would have to accept this evidence for
any of it to matter. Six months and 370 published runs have produced no
outside reader, and that is the only open question no amount of further
hardening answers.

## What is not claimed

The refusal counter does not measure provider refusals. It counts the ones the
rule can see, and the rule sees none of those in the archive. That is stated
above and in `docs/backlog.md` rather than left for a reader to discover.

Nothing here measures model behaviour. Every provider call is made at one
output token, so a successful call establishes that an endpoint was reachable
after the gate said PASS and nothing else.

The verdict being recomputable means a producer can no longer sign a verdict
its rows contradict. It does not mean the rule set is adequate; no run of any
design establishes that, and `docs/rule-coverage.md` is its proper home.

## Known open items

Seven rows were added to `docs/backlog.md` this release, recording what two
adversarial reviews and their verification found. The two worth reading first:
the gate blocks ordinary prose containing a danger-word substring, so "From now
on we should use the abundant historical data for the forecast" is blocked; and
the signing key identity is read from the environment with a constant fallback
in four code paths, which has already produced the archive's six unverifiable
certificates.

The first of those two now has a public surface recorded against it. Checking
the claims register for this release re-verified the repository's own About
description, a row outstanding since 8 October for want of access, and found
that "Blocks requests matching its published rules" is the sentence the
substring behaviour does not support: the sentence above is blocked with
`rule_hits: []` and all seven rule families reporting clean. It was the
register's one open row at the tag, because the limit cannot be stated in a
GitHub About line and the wording was therefore a decision rather than a fix.

**Amended after the tag**, visibly rather than silently, because these notes
describe a release that shipped: the row was closed later the same day. The
sentence is gone rather than narrowed and nothing replaced it. A replacement was
drafted and withdrawn, which is the part worth recording. "Known false positives
published" reads as a published false-positive rate, and
`content_false_positive_rate` has never been published with a value at all. The
counts are published and the rate is not, and an About line has no room to hold
that difference, so the replacement would have been a second instance of the
defect being removed. The gate's behaviour is unchanged and remains a backlog
row.

The rename of the verdict string is not in this release. `AUDIT PASSED` still
invites the reading that the rule set is adequate, and changing it is a v5
contract change: all four contracts carry the enum, contracts are selected by
the certificate's own version, and 71 files hold the literals.

## Verifying this release

```
python3 tools/verify_certificate.py --run-dir docs/runs/<run_id>
python3 tools/verify_baseline_record.py --run-dir docs/runs/<run_id>
python3 tools/check_release_checklist.py --run-commands
```

The first two refuse the other document kind rather than reporting it as
verified. The third reports fourteen of fourteen for this release: the eleven
conditions 2.5.0 stated, which are durable properties rather than one
release's features and each still resolve, plus one per item above. It reports
nothing about whether the claims in these notes were re-examined; that is
`docs/claims-register.md`.

That register was not reviewed in full for this release, and it says so in its
own first paragraph rather than carrying a date that implies otherwise. Four of
its sixteen rows were re-checked, those being the ones this release moved, and
the table marks which. One of the four changed status and one closed a row that
had been outstanding for ten days. The remaining twelve rest on the reading of
16 October.
