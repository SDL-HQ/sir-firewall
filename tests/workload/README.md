# Legitimate workload corpus

Independently authored text, used to measure how often SIR blocks a request it
should allow.

Run it:

```bash
python3 tools/measure_legitimate_workload.py
```

## Attribution and licence

This directory contains public sector information licensed under the
[Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).

| Source | Publisher | Version | Retrieved |
|---|---|---|---|
| [Phishing attacks: defending your organisation](https://www.ncsc.gov.uk/guidance/phishing) | National Cyber Security Centre | 2.0, reviewed 13 February 2024 | 8 October 2026 |
| [10 Steps to Cyber Security: Incident management](https://www.ncsc.gov.uk/collection/10-steps/incident-management) | National Cyber Security Centre | 1.0, reviewed 11 May 2021 | 8 October 2026 |
| [Personal data breaches: a guide](https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/) | Information Commissioner's Office | no published version | 8 October 2026 |

Publishers' own rights statements:
[NCSC](https://www.ncsc.gov.uk/terms-and-conditions) ·
[ICO](https://ico.org.uk/global/copyright-and-re-use-of-materials/).

**No endorsement.** The Open Government Licence requires that the information is
not used in a way that suggests official status, or that the licensor endorses
the user or their use of the information. **Neither the NCSC nor the ICO has
reviewed, approved or endorsed SIR, Structural Design Labs, or any result
produced from this corpus.** These documents are reproduced solely as
independently authored examples of legitimate text.

**Exclusions are recorded, not implied.** The licence does not extend to logos,
images, or third-party material inside a licensed document, so those are dropped
and each omission is listed per source in
`spec/workload/legitimate_workload.v1.json`. The ICO guide quotes UK GDPR
Recital 85, which is legislative text the ICO does not license, so that
quotation is excluded rather than relied upon.

**No third-party corporate text appears anywhere in this repository**, at any
length. That is a deliberate line rather than a reading of fair dealing: a
public tree heading into technical diligence should be able to answer the
question in one sentence.

## Why this corpus exists

The seven domain suites hold 160 allow-prompts and have never produced a single
harmless block. That is not a clean gate; it is an unrepresentative benign
corpus. Those allow-prompts are our own prose and inherit our blind spots, and
the one thing that provokes a false positive is absent from all of them.

## What it can and cannot support

These are documents a security or privacy function **reads**. They are not that
function's own internal control prose, which it **writes**. A result from this
corpus must not be described as measuring the latter.

## How to read the result

There is no combined false-positive rate, deliberately. SIR blocks a request
containing attacker wording whether or not the surrounding request is
defensive, so the rate for any real team is the proportion of their requests
that quote such wording. A single figure would measure the mix of the sample
rather than the behaviour of the gate.

Measured on 8 October 2026, 528 requests over 44 passages:

| Stratum | Blocked | Rate |
|---|---|---|
| Published guidance, five task shapes | 0 of 220 | 0.0% |
| The same text in a defensive training task | 0 of 44 | 0.0% |
| That same task plus one quoted injection string | **264 of 264** | **100.0%** |

The first two strata carry no caveat about authorship: the text is the
publishers'. The third is bounded by the injection strings we chose, listed in
`injection_strings.v1.json`, and is the rate for those strings rather than for
injection phrasing in general.

## The behaviour this shows, and why it may be correct

The gate draws no distinction between using attacker wording and quoting it.
Every one of the 264 blocked requests was an explicitly defensive staff-training
task.

There is a real argument that this is correct rather than a defect. SIR is a
pre-inference gate, and a quoted injection payload is still an injection payload
at the point of inference: the wording reaches the model either way, and a model
may act on it regardless of the sentence wrapped around it. Allowing it because
the request looks defensive would mean inferring intent from framing, which is
what a deterministic gate is built not to do, and what an attacker would
imitate.

The cost is real and falls on exactly the function SIR is sold to. It is
recorded in `docs/failure-modes.md` under the boundaries, and it is a disclosure
rather than a defect pending a decision to the contrary.

If the rules are ever changed to allow a defensive frame, the test to beat is
the third stratum above: it must stay blocked for an attacker who copies the
frame.
