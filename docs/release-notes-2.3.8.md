# SIR 2.3.8 release notes

SIR 2.3.8 corrects published claims that do not match what the evidence records.
It changes no gate behaviour, no evidence contract, no artefact schema, and no
signed field. Nothing is rewritten or re-signed.

Certificates produced by this release declare `sir_firewall_version` 2.3.8 and
are governed by evidence contract v3, whose applicability floor remains 2.3.5.

## The paired baseline records no gate decision

`red_team_suite.py` sets a hardcoded `PASS` verdict for every prompt in an
ungated baseline run, and no model response is assessed anywhere in the runner.
`jailbreaks_leaked` counts rows where the suite expected a block and the verdict
was `PASS`, so a baseline run reports every prompt labelled block as a leak by
construction, before any model is involved.

`leaks_delta` therefore compares a measured value against a constant. It is
arithmetically correct and it is the same fact as `provider_call_attempts_delta`,
which is the quantity that was observed: requests that did not reach the
provider because the gate stopped them.

Three claims in `docs/evidence-perimeter.v2.md` rested on that comparison and
were circular. The sharpest was that model selection did not change attack
outcomes while SIR did; the baseline outcome is independent of the model by
construction, so a paired comparison cannot speak to model differences. Those
claims are rewritten, and two explicit exclusions are added stating what the
baseline does not establish.

What is not affected, and should not be read as weakened: a gated run's own
`jailbreaks_leaked` is a genuine gate-conformance measure. On
`eu_ai_act_compliance_pressure` it fell from 100 of 150 labelled-block prompts
allowed through in April 2026 to 26 in September 2026, with 0 harmless blocked
throughout. That is a comparison of gated runs across rule versions and it is
the substantive measured improvement in that document.

`docs/benchmark-cycle.v1.md` now states what `leaks_delta` means alongside the
field list.

Assessing whether an ungated model would have complied is not attempted here.
The ungated runs already make the provider calls and
`--capture-downstream-evidence` already exists, so the missing pieces are a
retention decision and an assessment method, not budget. Both want designing
rather than rushing, and efficacy is a pilot's question.

## Certificates name a model that was never invoked

Every evidence contract requires `model` and `provider` with a minimum length of
one, and the publishing workflow supplies a default when none was selected. An
ordinary push-triggered audit, in which nobody chose a model and none was
called, therefore signs a certificate naming a specific commercial product.

135 published certificates name a model and record zero model calls, and a
further 37 older ones name a model without carrying the counter. The products
named belong to vendors who took no part in those runs.

The proof page already carried the call counters, eight rows below the model
row. It now states on the model row itself that no provider call was made when
the counters are zero, so the two facts are read together.

The field semantics are not fixed here. A certificate for a run that invoked no
model should not name one, and that needs a new evidence contract because the
current ones require a non-empty value. Recorded as E6 in
`docs/archive-errata.md`.

## Proof class name

`docs/terminology.md` gave a reason for freezing `FIREWALL_ONLY_AUDIT` that does
not hold: it said changing the enum would fail contract validation on every
archived certificate. The contract validator selects a contract from the
certificate's own version, and each contract file carries its own enum and
applicability floor, so a new name in a new contract version would leave every
archived certificate validating exactly as it does now.

The name still stands, for the reason that does hold: 131 published runs carry
it permanently, and renaming creates dual naming across every document and proof
page rather than a one-time migration. The decision and the conditions under
which it would be revisited are recorded in `docs/terminology.md`.

## Freeze

The freeze continues. This release corrects claims and presentation. The gate,
the verifier, the contracts and the artefact schemas are unchanged.
