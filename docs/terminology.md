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

`FIREWALL_ONLY_AUDIT` is a `proof_class` value inside signed certificate payloads and appears in 210 archived certificate files across the mirrored archives, representing 105 distinct runs. If the enum changed, signature verification would continue to pass because the verifier reconstructs each certificate’s stored payload and does not consult the contract, while contract validation would fail on every one of those archived certificates. Published run indexes filter, count and display `proof_class` as a comparison dimension; pair grouping keys on model and pack, not on `proof_class`. `sir_firewall_version` is a required evidence contract property inside the signed payload, so the `sir_firewall` package name appears in every published certificate. The `sir-firewall` repository name appears in published verification instructions and archived generated HTML. Changing any of these creates permanent dual naming, not a one-time migration.
