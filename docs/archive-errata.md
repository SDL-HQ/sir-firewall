# Published archive errata

Last updated 2 October 2026, at SIR 2.3.8.

This document records defects in SIR's own published evidence archive. It
exists because the archive is offered for independent verification, and a
reviewer who runs the verifiers over it will find records that do not verify.
Those records are listed here with their cause, rather than left for the
reviewer to discover and interpret alone.

Nothing listed here has been withdrawn. Removing published evidence because it
fails verification would defeat the purpose of publishing it.

## Reproducing these figures

```bash
python3 tools/archive_verification_report.py
```

The script runs `tools/verify_certificate.py` and
`tools/verify_archive_receipt.py` over every archive under `proofs/runs/` and
reports the exit-code distribution. It writes nothing. Add `--json-out PATH`
for the full per-run result. No network is required.

## Current figures

Measured across all 290 published run archives under `proofs/runs/`:

| Check | Result | Count |
|---|---|---|
| `verify_certificate.py` | verified (exit 0) | 22 |
| `verify_certificate.py` | ledger binding not checked (exit 9) | 262 |
| `verify_certificate.py` | signature verification failed (exit 5) | 6 |
| `verify_archive_receipt.py` | verified (exit 0) | 146 |
| `verify_archive_receipt.py` | incomplete archive or failed signature (exit 2) | 105 |
| `verify_archive_receipt.py` | no receipt, legacy archive (exit 3) | 39 |

Verification is three-valued. A record that cannot be checked and a record that
fails are different outcomes, and earlier descriptions of this archive did not
distinguish them.

The exit 2 count is 105: 99 archives that are incomplete, described in E1, and
6 whose receipt signature does not verify, described in E2.

## E1. Ninety-nine archives are incomplete against their own signed manifest

**Symptom.** `tools/verify_archive_receipt.py` exits 2 with
`file listed in manifest is missing: harmless_blocked.txt`.

**Cause.** The CI publication step passed `--copy leaks_count.txt` and
`--copy harmless_blocked.txt` to `tools/publish_run.py`, which copied both into
the run directory and hashed them into `manifest.json`. `.gitignore` carried
repo-wide patterns for those two filenames, so git never committed them, and a
`git add` cannot override an ignore rule. The archives were published without
two files their signed manifests name.

**Effect.** For these runs the receipt cannot be verified by anyone, including
SDL. The certificate, the ledger and the ledger binding are unaffected and
verify normally where the certificate carries a run identity. The missing files
are `leaks_count.txt` and `harmless_blocked.txt`, single-integer compatibility
files whose values are also carried as signed fields in the certificate as
`jailbreaks_leaked` and `harmless_blocked`. No evidence is lost. The archive is
nonetheless unverifiable as published.

**Fixed in 2.3.7.** The two `.gitignore` patterns are now anchored to the
repository root, so run-directory copies commit. A new fail-closed CI gate,
`tools/check_archive_staged.py`, compares each signed manifest against the git
index before the commit and fails the workflow if any named file would not be
published.

**Not retrofitted.** Repairing these archives would mean rebuilding and
re-signing manifests for runs that already happened, which would replace
published signed records with new ones carrying the same run identities. The
records stay as published.

Affected runs: 99, from 5 April 2026 to 29 September 2026. Unchanged by the
fix, because those files were never committed to either published tree. Listed
in Appendix A.

## E2. Six certificates fail signature verification

**Symptom.** `tools/verify_certificate.py` exits 5 with
`signature verification failed (InvalidSignature)`. The archive receipts for the
same six runs fail the same way.

**Cause.** Two clusters of three local runs, on 5 April and 16 April 2026. None
carries a `ci_run_url`, and their run identifiers contain no CI run segment, so
none was produced by the published CI workflow. Each cluster is the same set of
three: a 152-prompt firewall-only audit, an 8-prompt firewall-only audit, and a
6-prompt scenario audit, seconds apart. They record `sir_firewall_version`
`unknown` and `1.0.2`. They were signed locally with a key that is not the
registered `default` key, while asserting `signing_key_id: default`.

**What is established.** The payload hash check passes on all six, so each
payload is internally consistent and has not been altered since it was written.
Verification stops at the signature.

**What is not established.** Nothing about the runs themselves. These six are
not CI-produced evidence, cannot be verified against the published key
registry, and should not be counted as verified records.

**Not withdrawn.** They remain at their published locations under
`proofs/runs/` and `docs/runs/`. They are absent from `docs/runs/index.json`
only because that index is capped at 200 entries.

Affected runs:

- `20260405-040319-000000-702b336916d3`
- `20260405-040322-000000-aed41b22e195`
- `20260405-040324-000000-2c99d5f16574`
- `20260416-003923-000000-ef03803fc756`
- `20260416-003924-000000-001dcbab3e95`
- `20260416-003926-000000-049b1e770f3d`

## E3. Thirty-nine legacy archives carry no receipt

**Symptom.** `tools/verify_archive_receipt.py` exits 3 with
`missing archive_receipt.json (legacy archive without receipt)`.

**Cause.** These archives predate the archive receipt mechanism. They were
published before `publish_run.py` wrote `manifest.json` and
`archive_receipt.json`.

**Effect.** Archive-level integrity cannot be checked for these runs. All 39
are also among the records whose certificate ledger binding cannot be checked,
described in E4.

Affected runs are listed in Appendix B.

## E4. Two hundred and sixty-two certificates cannot have their ledger binding checked

**Symptom.** `tools/verify_certificate.py` exits 9 with
`certificate-to-ledger binding was not checked`.

**Cause.** Certificates emitted before SIR 2.3.4 carry no `run_id` and no
`itgl_row_count`, so a ledger sitting in the same directory cannot be bound to
the signed identity. This is the verifier behaving correctly. A tool that
reported success here would be asserting a check it did not perform.

**Effect.** For these records the signature and payload integrity are checked
and the ledger binding is not. This is a property of the certificates, not a
defect introduced later, and it is not repairable without re-signing historical
evidence.

## E5. Three April archives were completed as a side effect of the fix

The first publishing run after the ignore patterns were anchored to the
repository root added `leaks_count.txt` and `harmless_blocked.txt` to three
April 2026 archives under `docs/runs/`:

- `20260405-040319-000000-702b336916d3`
- `20260405-040322-000000-aed41b22e195`
- `20260405-040324-000000-2c99d5f16574`

Those three carried both files under `proofs/runs/` from before the ignore
patterns existed, and lacked them under `docs/runs/`. The publication step
rebuilds `docs/runs` from `proofs/runs`, so once the files were no longer
ignored they were staged into the second tree.

This is recorded rather than left silent because it is a change to published
evidence that arrived as a side effect of a fix. It is a strict improvement in
completeness: both trees now hold every file their manifests name. It does not
change what those archives establish, because their receipts fail on signature,
for the reason given in E2, both before and after.

## E6. Certificates name a model that was never invoked

**Symptom.** A certificate records `model` and `provider` naming a specific
commercial product while recording `model_calls_made: 0` and
`provider_call_attempts: 0`.

**Cause.** All three evidence contracts make `model` and `provider` required
with a minimum length of one, so every certificate must name something. The
publishing workflow supplies a default when no model was selected, so an
ordinary push-triggered audit, in which nobody chose a model and none was
called, records the default in the signed payload.

**Counts.** 135 published certificates name a model and explicitly record zero
model calls: 131 `FIREWALL_ONLY_AUDIT`, 2 `SCENARIO_AUDIT`, and 2
`LIVE_GATING_CHECK`. A further 37 older certificates name a model and do not
carry the counter at all. The products named are xAI's `grok-3-beta`,
`grok-4.3` and `grok-4-1-fast`, and OpenAI's `gpt-5.4-mini`. None of those
vendors took part in the runs concerned.

**The two live-mode records are not defects.** `LIVE_GATING_CHECK` is defined as
live mode where passing prompts may call the provider. A live run in which every
prompt blocked legitimately makes no calls, the call counters are signed and
visible, and the live pointer correctly refuses to advance without a successful
call.

**What a reader should rely on.** The call counters, which are signed and shown
on the proof page. `proof_class: FIREWALL_ONLY_AUDIT` means the gate ran and no
provider was contacted, whatever the model field says.

**Partly addressed.** The proof page now states on the model row itself that no
provider call was made when the counters are zero, rather than leaving a reader
to reconcile that row with counters further down the table. The field semantics
are not fixed: a certificate for a run that invoked no model should not name one
at all, and changing that requires a new evidence contract, because the current
contracts require a non-empty value. Historical certificates cannot be
re-signed.

## What a reviewer should do

Choose a run whose `audit.json` records `sir_firewall_version` 2.3.4 or later,
and verify the certificate, the ledger and the receipt from the same archive
directory. `docs/assurance-kit.md` gives a worked example with a named run and
its actual output. Treat any record listed in E1 or E2 as not independently
verifiable.

## Appendix A. Archives incomplete against their manifest (99)

- `20260405-091359-000000-gh23998470665-ef03803fc756`
- `20260405-093653-000000-gh23998834390-ef03803fc756`
- `20260405-093855-000000-gh23998862605-ef03803fc756`
- `20260405-103045-000000-gh23999649896-ef03803fc756`
- `20260405-112821-000000-gh24000557057-049b1e770f3d`
- `20260405-113555-000000-gh24000674687-001dcbab3e95`
- `20260405-114319-000000-gh24000772239-ef03803fc756`
- `20260416-041502-000000-gh24491708116-ef03803fc756`
- `20260416-041705-000000-gh24491763797-ef03803fc756`
- `20260416-041945-000000-gh24491822923-ef03803fc756`
- `20260416-043704-000000-gh24492315874-ef03803fc756`
- `20260416-053656-000000-gh24494032448-ef03803fc756`
- `20260416-065826-000000-gh24496649909-ef03803fc756`
- `20260416-070115-000000-gh24496723682-ef03803fc756`
- `20260417-021357-000000-gh24544221238-ef03803fc756`
- `20260417-021642-000000-gh24544278628-ef03803fc756`
- `20260417-030934-000000-gh24545662578-b98bfa0d0ae9`
- `20260417-031151-000000-gh24545721767-b98bfa0d0ae9`
- `20260418-111708-000000-gh24603498949-e132aad59b18`
- `20260418-112207-000000-gh24603544870-e132aad59b18`
- `20260418-112519-000000-gh24603628770-e32b39da51ad`
- `20260418-112716-000000-gh24603659170-e2c5be4f5bd6`
- `20260418-131652-000000-gh24605510815-e132aad59b18`
- `20260418-132138-000000-gh24605546590-e132aad59b18`
- `20260418-145427-000000-gh24607218181-e132aad59b18`
- `20260418-151650-000000-gh24607623708-e132aad59b18`
- `20260419-010708-000000-gh24617829779-e132aad59b18`
- `20260419-050925-000000-gh24621525989-e4521a64ce34`
- `20260419-060126-000000-gh24622376085-e132aad59b18`
- `20260420-001414-000000-gh24642600963-12e841f4ea97`
- `20260420-014257-000000-gh24644549078-12e841f4ea97`
- `20260422-031957-000000-gh24758391053-12e841f4ea97`
- `20260422-043806-000000-gh24760451962-12e841f4ea97`
- `20260422-061421-000000-gh24763282107-12e841f4ea97`
- `20260422-061720-000000-gh24763382908-9c21ca56197d`
- `20260422-061838-000000-gh24763426198-12e841f4ea97`
- `20260422-070952-000000-gh24765230496-12e841f4ea97`
- `20260422-074922-000000-gh24766752751-12e841f4ea97`
- `20260422-082108-000000-gh24768036771-12e841f4ea97`
- `20260425-010558-000000-gh24918824635-c818ae4214c7`
- `20260425-013608-000000-gh24919434478-c818ae4214c7`
- `20260425-020624-000000-gh24920026445-c818ae4214c7`
- `20260429-082912-000000-gh25098693913-101d1cb8c53e`
- `20260505-073935-000000-gh25363913666-2a34a2fa7204`
- `20260505-081104-000000-gh25365122483-888ee2eb0696`
- `20260505-081827-000000-gh25365435708-3d8ca0abf017`
- `20260505-093614-000000-gh25368812619-2a34a2fa7204`
- `20260505-101357-000000-gh25370454878-2a34a2fa7204`
- `20260505-112236-000000-gh25373392117-2a34a2fa7204`
- `20260505-112912-000000-gh25373643419-2e97cf396337`
- `20260530-030344-000000-gh26672729017-2e97cf396337`
- `20260530-031312-000000-gh28067376330-7cad8b6e1b91`
- `20260624-005401-000000-gh28067505814-2e97cf396337`
- `20260802-082748-000000-gh30739805945-944fa7b2601f`
- `20260802-084107-000000-gh30740238081-c501e8667d34`
- `20260802-084507-000000-gh30740330813-c501e8667d34`
- `20260802-084935-000000-gh30740520548-d12687a63bff`
- `20260802-090121-000000-gh30740862634-3a92a0f1e59c`
- `20260804-052156-000000-gh30880440115-944fa7b2601f`
- `20260804-052528-000000-gh30880614202-944fa7b2601f`
- `20260804-053017-000000-gh30880746115-944fa7b2601f`
- `20260805-074830-000000-gh30986422787-c8b702d636fb`
- `20260805-075025-000000-gh30986538158-c8b702d636fb`
- `20260805-075449-000000-gh30986620526-5eb85599ff0d`
- `20260805-082453-000000-gh30988883180-c8b702d636fb`
- `20260809-100650-000000-gh31307350164-c8b702d636fb`
- `20260813-052928-000000-gh31670468310-c8b702d636fb`
- `20260816-122227-000000-gh31946863637-c8b702d636fb`
- `20260825-095047-000000-gh32834081820-c8b702d636fb`
- `20260825-100352-000000-gh32835240932-c8b702d636fb`
- `20260825-104228-000000-gh32838528129-bfb29ba63890`
- `20260908-232901-000000-gh34290814593-bfb29ba63890`
- `20260909-002059-000000-gh34294599303-bfb29ba63890`
- `20260912-071815-000000-gh34680359363-1a06195e614e`
- `20260914-025456-000000-gh34800768322-bfb29ba63890`
- `20260918-115921-000000-gh35342297813-bfb29ba63890`
- `20260920-072912-000000-gh35496976451-bfb29ba63890`
- `20260920-090209-000000-gh35501172013-774d1658103c`
- `20260920-091821-000000-gh35501918193-774d1658103c`
- `20260921-105952-000000-gh35591638331-5645e1c49ddb`
- `20260921-112828-000000-gh35594195233-91aaccd3b5e9`
- `20260921-115616-000000-gh35596666642-8fd2a7ec1688`
- `20260921-134234-688792-gh35607304829-b3a0326b0dee`
- `20260921-145017-067275-gh35614789190-fd9b15bc38e6`
- `20260921-234804-260192-gh35669156589-646fbe2f0ddb`
- `20260922-113219-272729-gh35721959953-5bd2fbb92837`
- `20260922-114022-042082-gh35722713131-63e490a6abc6`
- `20260922-120936-139224-gh35725488453-1debd174a7fd`
- `20260923-120113-018497-gh35857863063-57d3a78f9a7f`
- `20260923-140303-645170-gh35871293906-593ac9e7e55e`
- `20260924-045247-182959-gh35957484722-878440772f1b`
- `20260924-052502-633821-gh35959817515-5e60326ce3d5`
- `20260924-234354-317046-gh36074147961-c602e09956e9`
- `20260925-000832-936778-gh36076125057-0f3f202d2913`
- `20260926-020536-528864-gh36209364591-ec7e07a26989`
- `20260926-023707-102269-gh36212237148-40ad62c36cf8`
- `20260928-033445-334926-gh36374235904-054901b87dfe`
- `20260929-033614-123778-gh36517838192-2b481ff874e6`
- `20260929-053038-713723-gh36526474724-57f87ce7b86f`

## Appendix B. Legacy archives without a receipt (39)

- `20260111-023031-211ac186f758`
- `20260111-023208-211ac186f758`
- `20260111-025806-211ac186f758`
- `20260111-044856-211ac186f758`
- `20260111-045110-211ac186f758`
- `20260111-052154-211ac186f758`
- `20260111-052423-211ac186f758`
- `20260111-053733-211ac186f758`
- `20260111-053912-211ac186f758`
- `20260111-055720-211ac186f758`
- `20260111-072752-211ac186f758`
- `20260111-081359-211ac186f758`
- `20260111-082228-211ac186f758`
- `20260111-094524-211ac186f758`
- `20260113-074124-211ac186f758`
- `20260113-090415-211ac186f758`
- `20260114-235440-211ac186f758`
- `20260122-232957-211ac186f758`
- `20260123-031908-211ac186f758`
- `20260123-031953-211ac186f758`
- `20260123-212219-211ac186f758`
- `20260125-072800-211ac186f758`
- `20260125-075012-211ac186f758`
- `20260125-091626-211ac186f758`
- `20260125-095249-211ac186f758`
- `20260127-214831-211ac186f758`
- `20260131-065736-211ac186f758`
- `20260211-035509-211ac186f758`
- `20260211-054935-000000-gh21894262479-211ac186f758`
- `20260211-055221-000000-gh21894312521-211ac186f758`
- `20260211-063751-000000-gh21895255663-211ac186f758`
- `20260211-064638-000000-gh21895439457-211ac186f758`
- `20260211-074032-000000-gh21896642017-211ac186f758`
- `20260225-034444-000000-gh22381207350-211ac186f758`
- `20260225-040821-000000-gh22381734220-211ac186f758`
- `20260301-051248-000000-gh22536564696-ef03803fc756`
- `20260301-095023-000000-gh22540846663-ef03803fc756`
- `20260402-151409-000000-gh23907562600-ef03803fc756`
- `20260403-023419-000000-gh23931201262-ef03803fc756`
