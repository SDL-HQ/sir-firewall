# SIR Terminology Note

## Rule coverage and gate ordering

`deterministic_rules.py` is one component of the content gate, not the whole
gate. After normalisation, `_check_jailbreak()` evaluates the legacy
`_HIGH_RISK_KEYWORDS` path, the legacy danger-word plus safety-phrase
conjunction, and the structural override/exposure path before evaluating
`find_rule_hits()` from `deterministic_rules.py`. It passes content only when
none of those paths blocks. Published full-gate coverage includes all four
paths; deterministic-rule coverage includes only `find_rule_hits()`. See the
[published rule coverage report](rule-coverage.md).

Use **governance gate** in public/operator-facing descriptive text.

Keep canonical technical identifiers unchanged, including repository/package/module names (`sir-firewall`, `sir_firewall`), file paths, URLs, commands, proof class names, schema keys, and historical artefact labels.

Do not do blind global replacement of legacy “firewall” text; preserve it where it is part of a stable identifier or truthful historical reference.

## Why canonical identifiers are frozen

`FIREWALL_ONLY_AUDIT` is a `proof_class` value inside signed certificate
payloads. It appears in 262 archived certificate files across the two mirrored
archives, representing 131 distinct runs.

An earlier version of this note said that changing the enum would make contract
validation fail on every archived certificate. That is wrong, and the correction
matters because the claim was the stated reason for freezing the name.
`tools/validate_certificate_contract.py` selects the contract from the
certificate's own `sir_firewall_version`: 2.3.5 and above against v3, 2.3.4
against v2, anything older against v1. Each contract file carries its own
`proof_class` enum and its own applicability floor under
`x_contract_rules.applicability`. A new name introduced in a new contract
version therefore leaves v1 to v3 untouched, and every archived certificate
continues to validate exactly as it does today. Only editing the enum inside an
existing contract would break them, and nothing requires that.

Signature verification is unaffected either way, because the verifier
reconstructs each certificate's stored payload and does not consult the
contract.

What is true, and is the actual reason the name stands: 131 published runs will
carry `FIREWALL_ONLY_AUDIT` for as long as the archive exists. Renaming creates
permanent dual naming across every document, glossary and proof page, not a
one-time migration. The name is imprecise rather than untrue, since the value
does convey that only the gate ran and no model was called. The word also
survives in the repository, package and module names, and `sir_firewall_version`
is a required contract property inside every signed certificate, so renaming one
enum while the word remains everywhere else buys inconsistency rather than
clarity.

## Decision on the proof class name

Decided 2 October 2026: `FIREWALL_ONLY_AUDIT` stands.

If it is ever renamed, the moment is a release that bumps the evidence contract
anyway, because a later rename costs an additional contract version for a name
alone. A rename would require the new value in the new contract only, the old
value left intact in earlier contracts, a mapping recorded here, and both names
shown wherever archived certificates are displayed.

Published run indexes filter, count and display `proof_class` as a comparison
dimension. Pair grouping keys on model and pack, not on `proof_class`.

The filed patent specification does not use the word firewall anywhere and names
no repository or URL, so none of this has any bearing on the patent, and a
repository rename would carry no patent consequence.

## The two signed documents

Added 15 October 2026, with SIR 2.5. Until then an archive held one kind of
signed document and every reader assumed it.

**Audit certificate** (`audit.json`). A gated run. It carries a `result`, a
`proof_class`, and the gate's counters. It says what the gate decided over a
named prompt set.

**Ungated baseline record** (`baseline.json`). A run with the gate out of the
path. It carries one claim: that this prompt set was forwarded to the named
provider with no gate in it, and what came back at the transport level. It
carries **no result and no proof class**, because a run with no gate in it has
nothing to say about the gate, and a document with a verdict-shaped field is
read as a verdict whatever is written beside it.

An archive holds exactly one of them. One holding both cannot be read as either
kind and is refused everywhere: the verifiers, the exports, the publisher and
the benchmark job's admission check. One holding neither has no kind.

### `FORWARDED`

A row status in a baseline ledger. It means a provider call was attempted with
that row's content. It is **not a gate decision**: the gate returns `PASS` or
`BLOCKED` and nothing else, so a `FORWARDED` row cannot have come from a gated
run.

Before 2.5 a baseline run recorded `PASS` on every row, because the runner had
only the gated vocabulary to write in. `PASS` on a row no gate saw is what made
every prompt labelled for blocking count as a leak, and the run's result
compute as a failed audit. `docs/archive-errata.md` records the 54 published
certificates that resulted.

### What a baseline record's counters count

Six, all recomputed from the rows by `tools/verify_baseline_record.py` and none
of them asserted by the runner:

- `prompts_forwarded`: rows in the ledger
- `expected_block_prompts_forwarded`: rows the prompt set labels `block`
- `expected_allow_prompts_forwarded`: rows it labels `allow`
- `provider_call_attempts`
- `provider_call_successes`
- `provider_call_failures`

Successes plus failures equals attempts equals rows. That holds because the row
rules enforce it, not because a run measured it: `tools/itgl.py` refuses a
baseline row whose `provider_call_attempted` is not `true` and refuses one whose
`provider_call_outcome` is neither `success` nor `failure`. A ledger that would
break the identity is not a baseline ledger. Read it as a shape check, not as a
finding about a run.

### What `provider_call_outcome` means

**Whether the call raised.** `red_team_suite.py` writes `success` when the
provider call returns and `failure` when it raises. Nothing about the response
is inspected to decide it.

Two consequences, both of which a reader will otherwise guess wrongly:

- A response carrying the provider's own content-policy refusal is a
  **success**. The call returned.
- A refusal the provider returns as an error is a **failure**, and is not
  distinguishable from an outage, a timeout, a rate limit or a bad credential.

So the outcome says the call completed at the transport level. It does not say
the provider processed the prompt, and a baseline is therefore not a control for
the provider's own safety layer. Telling a provider-side refusal apart from a
transport failure would change the row's outcome values, the exact key set, the
counters, the schema and the verifier, which is a chain-version change; it is
not in 2.5.

**What the counters do not mean.** Nothing about the provider's responses beyond
that outcome. No response is judged, and no counter and no pair figure is
derived from one. A run started with `--capture-downstream-evidence` in live
mode writes a response hash, and an excerpt if one is requested, to
`proofs/downstream_evidence.jsonl`, which is archived beside the document;
nothing recomputed by `tools/verify_baseline_record.py` reads it.
`expected_block_prompts_forwarded` is a count of the prompt set's own labels,
not a count of anything that happened.

In a scenario a row is a turn, and the provider call for a turn carries the
cumulative history of every earlier turn. So in a baseline each call carries all
earlier content, and these counters count calls and turns rather than distinct
content exposures. The record's schema says so in its own description.

## What the counters count

Added 13 October 2026, because no surface defined these and the figures appear
in the repository description, in every signed certificate and on every
published run page. An independent review raised it as the single terminology
change most likely to improve the project's credibility, and it is right: the
names import meanings the mechanism cannot support.

**SIR never observes model output.** It is a pre-inference gate. It decides on a
request before a model sees it and, when the decision is `PASS`, forwards the
approved request unchanged. Nothing downstream is read back, so no counter here
can be a statement about what a model said or disclosed.

### `jailbreaks_leaked`

**What it counts:** benchmark rows labelled `block` in their suite that the gate
allowed.

**What it does not mean:** that anything was disclosed, exfiltrated, or reached a
model's output. The word "leak" ordinarily means a downstream disclosure, which
is a category of event this system is structurally incapable of observing. Read
the figure as *expected-block inputs the gate allowed*, which is a statement
about the rule set's coverage against a labelled corpus and nothing else.

The name is kept rather than corrected because it is a field in the evidence
contract and a signed counter inside 292 published certificates. Renaming it is
a contract change with an archive migration behind it, which is recorded as a
candidate rather than done. Defining it costs nothing and removes the misreading
now. The same reasoning as the proof class name above.

**On the 54 published ungated baselines this counter equals the number of
prompts labelled `block`, every time.** There was no gate, so nothing was
allowed by a gate and nothing was blocked by one; the runner recorded `PASS` on
every row and the counter fired on each labelled prompt. From 2.5 a baseline
record does not carry this counter at all.

### `harmless_blocked`

**What it counts:** benchmark rows labelled `allow` in their suite that the gate
blocked.

**What it does not mean:** a false-positive rate for any real workload. The
denominator is the allow-labelled rows of a named corpus. The 2.4.0 measurement
of requests that quote attacker wording is the reason this distinction matters:
the proportion of a team's legitimate requests that SIR blocks is not a property
of their domain, it is a property of how often their requests contain attacker
phrasing, and no benchmark corpus predicts that for them.

### `AUDIT PASSED`

**What it means:** the counters for this run were zero and the certificate's own
checks were satisfied. It is a property of a gated run. A baseline record has
no result, and no surface may supply one for it, by computing it from counters
or otherwise.

**What it does not mean:** that the rule set is adequate, or that the
configuration enforces what its name suggests. A run over a corpus the rules
already cover produces this verdict, and so does a run over a corpus that
exercises nothing. `docs/rule-coverage.md` publishes what is covered and
`docs/claims-register.md` records what the evidence does and does not establish.
A verdict is a statement about one run, not an endorsement of the gate.
