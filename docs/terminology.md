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
checks were satisfied.

**What it does not mean:** that the rule set is adequate, or that the
configuration enforces what its name suggests. A run over a corpus the rules
already cover produces this verdict, and so does a run over a corpus that
exercises nothing. `docs/rule-coverage.md` publishes what is covered and
`docs/claims-register.md` records what the evidence does and does not establish.
A verdict is a statement about one run, not an endorsement of the gate.
