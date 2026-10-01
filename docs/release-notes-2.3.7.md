# SIR 2.3.7 release notes

SIR 2.3.7 repairs published evidence and corrects claims made about it. It does
not change firewall gate decisions, does not alter any evidence contract, and
does not rewrite or re-sign any published certificate, ledger, or index.

Certificates produced by this release declare `sir_firewall_version` 2.3.7 and
are governed by evidence contract v3, whose applicability floor remains 2.3.5.

## Published run archives were incomplete against their own signed manifests

The continuous integration publication step passed `leaks_count.txt` and
`harmless_blocked.txt` to `tools/publish_run.py`, which copied both into the run
directory and hashed them into `manifest.json`. The repository's `.gitignore`
carried patterns for those two filenames with no leading slash, so they matched
at every depth and git never committed the archived copies. A `git add` cannot
override an ignore rule, and nothing checked afterwards.

Ninety-nine published archives therefore name two files in a signed manifest
that are not present in the archive. For those runs
`tools/verify_archive_receipt.py` fails for everyone, including SDL. The
certificate, the ledger, and the ledger binding are unaffected. The missing
files hold single integers that the certificate already carries as signed
fields, so no evidence was lost, but the archives cannot be verified as
published.

The two ignore patterns are now anchored to the repository root, so the mutable
root-level copies stay out of version control while archived copies commit.
A new fail-closed check, `tools/check_archive_staged.py`, compares each signed
manifest against the git index after staging and before the publishing commit,
and fails the workflow when a named file would not be published. It runs in both
publishing jobs and also verifies the archive receipt. The defect was a silent
one, so the fix is a gate rather than a correction.

Affected runs are not retrofitted. Repairing them would mean rebuilding and
re-signing manifests for runs that already happened, replacing published signed
records with new ones carrying the same identities. They stay as published and
are listed in `docs/archive-errata.md`.

## Six published certificates do not verify

A sweep of every published archive found six certificates that fail signature
verification with exit code 5, in two clusters of three, on 5 April and 16 April
2026. None carries a CI run URL and none has a CI segment in its run identifier,
so none was produced by the published workflow. Each cluster is the same set of
three local runs seconds apart. They were signed with a key that is not the
registered key, while asserting `signing_key_id: default`.

Their payload hash checks pass, so the payloads are internally consistent and
unaltered since they were written. Verification stops at the signature. Nothing
about the runs themselves is established, and they should not be counted as
verified records.

They are not withdrawn. Removing published evidence because it fails
verification would defeat the purpose of publishing it.

## The archive result is three-valued, and was reported as two

The 2.3.6 notes reported that the archive held 288 certificates, of which 20
carried a readable run identifier and 268 did not. Those figures were correct
for the question asked. They did not separate records that cannot be checked
from records that fail.

Measured now across 289 archives, `tools/verify_certificate.py` returns exit 0
for 21, exit 9 for 262, and exit 5 for 6. The 262 and the 6 together are the
268 previously reported as carrying no run identifier, and the extra archive and
extra verified record are the run published since. Nothing changed in the
archive. What changed is that the six failures are now reported as failures
rather than folded into a count of records that could not be checked.

`tools/archive_verification_report.py` derives these figures by running the
repository's verifiers over every archive. Published counts should come from it
rather than from hand counting. It writes nothing and needs no network.

## Claims corrected

`docs/standards_alignment.md` section 4 said each run records a structured
decision trace and a hash chain so the log history is tamper evident, offered
the step trace as logging evidence, and said the ledger supports reconstruction
and independent verification that the recorded run matches the claimed outcome.

The published chain is computed as `sha256(prev_hash + final_hash)`. It
establishes that rows are complete and in order and that none has been removed,
inserted or reordered. It does not cover the remaining fields of a row, so it is
not by itself evidence that a row's recorded decision is the decision the gate
made. That property comes from the signed archive receipt, which covers the
ledger file byte for byte, and it holds only when
`tools/verify_archive_receipt.py` is actually run. The gate's internal step
trace is not published, and the per-prompt terminal hash incorporates a capture
timestamp, so reconstruction of a run's internal decision steps from published
artefacts is not possible. Section 4 now says this.

`docs/assurance-kit.md`, `docs/evaluator-technical-explainer.md` and
`docs/minimal-pilot-runbook.md` each told a reader that a
`file listed in manifest is missing` error meant their download was incomplete
and did not mean the archived evidence was broken. For 99 published archives
that explanation was wrong and pointed the reader at themselves. All three now
name both causes and link the errata.

The standalone verifier bundle in `README.md` omitted
`tools/verify_archive_receipt.py`, so a reviewer who copied the listed files
could not run the receipt check at all. The bundle now includes it, and the
README states which of the three checks establishes which property.

## New files

- `docs/archive-errata.md`, the published record of defects in the archive, with
  every affected run identifier.
- `tools/check_archive_staged.py`, the publication gate.
- `tools/archive_verification_report.py`, the archive figures, re-derivable.

## Known limitation, not addressed here

The ledger chain covers the per-prompt terminal hash and the link to the
previous row, and does not cover a row's other fields. Changing that is an
evidence format change rather than a repair, and it is held for a separate
decision rather than taken in a patch release.

## Freeze

The freeze described in the 2.3.6 notes continues. This release repairs
published evidence and the claims made about it. The gate, the verifier, and the
evidence contracts are unchanged.
