# SIR 2.3.6 release notes

SIR 2.3.6 closes one certificate provenance gap. It does not change firewall
gate decisions, does not alter any evidence contract, and does not rewrite or
re-sign any published certificate, ledger, or index.

Certificates produced by this release declare `sir_firewall_version` 2.3.6 and
are governed by evidence contract v3, whose applicability floor remains 2.3.5.

## Certificate run provenance

`proofs/run_summary.json` is committed to the repository, so it is present on
disk in any job, including one in which the audit never executed. The
certificate generator read it without establishing that it belonged to the
current execution. A comment stated the assumption directly: the summary is
written by the same runner invocation. That was never checked.

In a job whose audit died, the generator would read the previous run's summary,
find the counters recorded in it, compute a passing result, and sign a
certificate carrying the previous run's identifier alongside the current job's
CI URL and commit. Because a passing certificate is written to the canonical
latest-pass path, the archive step would then have republished the earlier run's
directory from it.

`tools/generate_certificate.py` now refuses to sign in that case. Run
identifiers embed the continuous integration run that produced them, so the
generator compares the identifier carried by the summary against the current
execution and raises rather than signing when the two disagree. The refusal
occurs before signing. Every later step then declines on its own existing
conditions: the archive step skips because no certificate path was produced, the
latest-pass publication step skips because its path gate is unsatisfied, and the
run fails. Work outside continuous integration carries no such identity and is
unaffected.

## Published archive verification result

The published archive was swept for this defect at the time of release. It holds
288 certificates. Of these, 20 carry a run identifier from which the producing
integration run can be read, and in all 20 that run agrees with the
certificate's own `ci_run_url`. The remaining 268 carry no run identifier, so
the question cannot be asked of them; they are the population already reported
as non-binding. No instance of this defect is present in the published record.

## Verdict computation on absent counters

The tree tagged 2.3.5 also contains a change to the audit workflow that the
2.3.5 notes do not describe. It is recorded here rather than by amending them.

The step computing the audit verdict read its counter files with a shell
fallback that treated an absent file as a zero count, so a job that produced no
counters reported a passing verdict. A run whose checkout failed did exactly
that. The step now requires both counter files to be present and to hold
non-negative integers, reports the run as inconclusive when they are not, and
exits non-zero. The proof commit message used the same fallback and now reports
the counters as unknown rather than as zero when none were read.

## Freeze

Development pauses at this release. The gate, the verifier, and the evidence
contracts are unchanged from here until work resumes, and the absence of commits
should be read as a deliberate freeze rather than as an abandoned project. The
audit runs on pushes to the default branch, so no new certificates are expected
to be published during the freeze.
