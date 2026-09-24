# SIR 2.3.5 release notes

SIR 2.3.5 closes verification and policy-binding gaps without rewriting or
re-signing any published certificate, ledger, or index and without changing
firewall gate decisions.

## Certificate and ledger verification

`tools/verify_certificate.py` now verifies certificate-to-ledger binding by
default. For `docs/runs/<run_id>/audit.json`, it discovers
`docs/runs/<run_id>/proofs/itgl_ledger.jsonl`. `--ledger` remains available for
an explicit path or replay, and `--no-ledger` is the explicit opt-out. If no
ledger can be found and no opt-out was given, exit code 9 reports that binding
was not checked; exit code 7 remains the binding-failure result.

Evidence contract v2 applies from `sir_firewall_version` 2.3.4 and requires
`itgl_row_count` and `detached_ledger`. Contract v1 remains unchanged and governs
2.2.0 through 2.3.3. Certificates below 2.2.0 continue to return the distinct
not-applicable exit code 8 rather than failing validation. Published 2.3.4
certificates already contain both v2-required fields, so the contract change
makes no published certificate non-compliant.

The published historical census remains frozen: 29 in-scope certificates carry
an `itgl_final_hash` shared with another in-scope run, and 295 certificates fall
below the 2.2.0 floor and are reported as not applicable rather than failed.

## `STRICT_ISC_ENFORCEMENT` decision

Two options were considered before implementation:

1. **Wire it up.** The flag could have gated structural ISC rejection. That
   would have required defining the disabled behavior, routing every structural
   rejection through the flag, and testing both modes. A `false` value would
   create a configuration path that accepts structurally invalid ISC input,
   changing gate decisions and weakening the fail-closed boundary. Existing
   published certificates all assert `true`, so they would describe the enabled
   path, but any pack using `false` would acquire new security-sensitive behavior.
2. **Remove the non-behavioral assertion.** Remove the flag from required pack
   fields and newly generated certificate flags while retaining unconditional
   structural rejection. Existing packs may still carry the legacy extra key,
   and historical signed certificates remain unchanged and valid under their
   applicable contract.

The release takes option 2. It avoids inventing a bypass solely to give an
otherwise unused flag meaning, preserves every gate decision, and stops new
certificates from asserting a control state with no behavioral referent.

## Signed-policy correspondence

`tools/verify_policy.py` now requires the signed policy payload to equal the
contents of `policy/isc_policy.json` in addition to checking its hash and
signature. CI runs this verifier. Certificate generation refuses to sign on a
mismatch and new certificates include the signed assertion
`enforced_policy_matches_signed_policy: true`.

The negative verifier fixtures in `examples/verifier-negatives/` are now a
published conformance suite with expected rejection categories for third-party
verifier implementations.
