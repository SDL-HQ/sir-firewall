# SIR 2.3.4 release notes

SIR 2.3.4 corrects certificate-to-ITGL evidence binding. The runner now assigns
a run ID and writes the canonical ledger beneath that run's archive directory.
Certificate generation verifies the identity-matched ledger identified by the
current run summary (or explicit replay `--ledger` argument), signs the run ID,
computed chain head, row count, and detached-ledger status. A non-canonical
replay requires `--allow-detached-ledger` and is visibly signed as detached. It fails
closed on missing or invalid input, a row-count mismatch, or a mismatched
`ITGL_FINAL_HASH` cross-check.

The certificate verifier adds optional `--ledger` verification. Ledger chain,
terminal-hash, and row-count binding failures use exit code 7. Evidence contract
v1 accepts the new optional integer `itgl_row_count`, preserving validation of
archived certificates.

Paired-benchmark CI verifies both newly archived certificates against their own
ledgers. Index writers continue to source new row hashes from their certificates;
published historical certificates, ledgers, and index rows are not rewritten.
See [Evidence-binding correction](evidence-binding-correction.md) for the defect,
measured published scope, and archival interpretation.

At the 2.3.4 release, of the 49 archived certificates at or above the
evidence-contract 2.2.0 floor, all 49 passed contract-shape validation, while 29
carried a ledger-hash value shared with another in-scope run. These are
different properties: contract validity does not establish that a certificate
names its own ledger.
