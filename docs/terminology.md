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
