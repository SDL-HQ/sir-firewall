# SIR 2.3.3 — Generic systemic-reset audit accounting

SIR 2.3.3 closes a gap between request-level fail-closed behavior and run-level
audit accounting.

## Systemic-reset accounting

At SIR 2.3.0, `_sr_block()` could emit both
`systemic_reset_policy_load_failed` and
`systemic_reset_domain_pack_load_failed`. The 2.3.0 audit-accounting rule
recognized only the latter, so baseline-policy load resets were uncovered from
the day that rule was introduced. SIR 2.3.1 then added
`systemic_reset_internal_error` and `systemic_reset_domain_pack_invalid`,
expanding the uncovered set from one reason to three. Consequently, an
expected-block-only suite whose rows all returned any uncovered reset could
previously be certified `AUDIT PASSED`.

The runner now treats either a `systemic_reset_*` reason or an explicit
`sr.sr_triggered` marker as a systemic reset. Such rows are excluded from both
`jailbreaks_leaked` and `harmless_blocked`, regardless of the row's expected
outcome, and any positive systemic-reset total forces the certificate result to
`INCONCLUSIVE`.

`proofs/run_summary.json` now records both `systemic_reset_count` and
`systemic_reset_counts_by_reason`. The existing
`systemic_reset_domain_pack_load_failed_count` field remains as a compatibility
diagnostic for existing consumers. Certificate generation also accepts legacy
summaries that contain only that older field.

The generic rule is deliberate: adding a new `systemic_reset_*` reason must not
require a corresponding audit-accounting code change, and a marked reset remains
covered even if its producer does not use that prefix.

## Compatibility and evidence

Existing signed certificates and archived run evidence are historical records
and are not regenerated. The signed certificate schema is unchanged; detailed
per-reason counts remain in the unsigned run summary, consistent with the 2.3.0
evidence boundary.
