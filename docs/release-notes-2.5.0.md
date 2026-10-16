# SIR 2.5.0 release notes

SIR 2.5.0 gives an ungated baseline run a document of its own.

Until this release a paired benchmark was two audit certificates. The ungated
half carried a `result`, a `proof_class` and a leak count describing a gate
that was not in the request path, and the comparison between the two halves was
read at result level. Fifty-four published certificates are in that shape. The
defect was not that they were wrong about what happened; it was that a
certificate is a statement about a gated run, and half of every pair was not
one.

From this release the ungated half produces a `baseline.json`, a signed
baseline record with `record_kind: sir_ungated_baseline`, no result and no
proof class. Those fields are forbidden rather than nullable, so a reader
cannot find an empty one and supply a value. The pair's figures are counted
from the gate's own decisions instead of inferred from a synthetic baseline
result.

The ten acceptance conditions in `release-checklist.json` are all met, and
`tools/check_release_checklist.py` refuses the merge path unless every one
carries evidence that resolves: a test that exists, an artefact that exists, or
a command that runs to its stated exit code. Prose is not evidence.
The suite was 1477 tests at the v2.5.0 tag, held against that figure by `tests/test_release_notes_suite_size.py`.

No published archive is rewritten or re-signed. The 54 stay published, with
what they are recorded as E7 in `docs/archive-errata.md`.

## The two documents, and what separates them

An archive holds exactly one signed document: `audit.json` for a gated run, or
`baseline.json` for an ungated one. `tools/verify_certificate.py` verifies the
first and `tools/verify_baseline_record.py` the second, and each refuses the
other kind rather than reporting it as a verified instance of its own.

A baseline row carries `FORWARDED`, meaning a provider call was attempted with
that row's content. It is not a gate verdict. The gate returns `PASS` or
`BLOCKED` and nothing else, so a ledger of `FORWARDED` rows cannot have come
from a gated run and has no run publication status at all.

`BASELINE_ROW_VERSION` is introduced at 1 while the format is still free to
change, and is covered by the ledger chain. It is deliberately not covered by
`ungated_row_final_hash`, which is a separate digest over the row contents.

## What this release found about itself

The two paired benchmarks dispatched on 15 October exposed five defects, every
one of them a reader that assumed no baseline record existed, because until
09:25 that morning none did. Each was caught by the release gate before
anything merged:

- the benchmark job moved `proofs/latest-audit.json` without the root ledger,
  so the documented one-command check reported LEDGER BINDING FAILED from two
  files that merely described different runs;
- three published figures counted a baseline record as a certificate;
- two tests enumerated archives assuming one document kind;
- the perimeter's INCONCLUSIVE rule was untrue of a run that also leaked.

That last one is worth stating plainly. The document said a live run is
INCONCLUSIVE when `provider_call_failures` is greater than zero. The code
checks the gate verdict first, so a run that leaked is AUDIT FAILED however
many of its provider calls failed, and the sentence was never true of such a
run. The second paired benchmark produced exactly that case. The ordering in
the code is deliberate and unchanged: `jailbreaks_leaked` is computed from the
gate's own decisions and reads no provider response, so a leak is established
whatever the provider did, and reporting such a run as INCONCLUSIVE would file
a demonstrated failure under "not known".

A sixth was found on 16 October by the full claims-register re-examination, and
it is the same defect as the third above, one function away. A generated bullet
gave the number of published archives as the denominator in a sentence about
certificates. The sibling renderer had been corrected the day before and
carried a comment saying why; this one was missed. The test that should have
caught it had been built on the same wrong denominator, so the test and the
defect agreed with each other and neither showed.

## The two paired benchmarks

Both are `valid_complete`, both on `grok-4.3`, and both are recorded in
`docs/evidence-perimeter.v6.md` with their pair IDs, run IDs, pack versions,
prompt-set hashes and commits.

| pack | labelled block | blocked | passed | reset | gated result | provider |
|---|---|---|---|---|---|---|
| `data_exfiltration_pressure` | 27 | 27 | 0 | 0 | AUDIT PASSED | complete |
| `eu_ai_act_compliance_pressure` | 100 | 74 | 26 | 0 | AUDIT FAILED | incomplete |

The perimeter leads with the failing pair rather than the clean one. It is the
only published pair with a non-zero `expected_block_prompts_passed_by_gate`,
the only one whose gated half is AUDIT FAILED and the only one whose provider
evidence is incomplete, so it is the first pair that exercises both paths these
documents describe. Two of its 76 gated provider calls were refused by a rate
limiter, which is an absent observation and not a prevention; conflating the
two would have inflated the gate's apparent effect by two.

What two pairs on one model do not support is stated in the perimeter at the
same length as what they do.

## Two policy packs renamed

`pci_payments` is now `pci_template_reduced_limits` and `hipaa_mental_health`
is now `hipaa_template_reduced_limits`. A pack configures admissible templates,
per-template token ceilings, enforcement flags and whether a structured request
schema is declared. It does not change which phrases the gate blocks, because
the deterministic rules are one global set, so a pack named for a payment
standard or a class of clinical workload claimed a property it has no mechanism
to deliver.

Neither identifier appears in any published archive, and `policy_hash` is
computed over the baseline policy document rather than over the pack directory,
so there is no archive migration and no dual-naming obligation. The mapping is
in `docs/terminology.md`. The four pack names that are signed into published
certificates are not renamed, for the opposite reason.

Measured while doing it and recorded rather than acted on: `generic_safety`,
`data_exfiltration_pressure` and `support_operator_override` are byte-identical
once `pack_id` and `description` are set aside. Six installed packs are four
distinct configurations.

## The dependency surface

`pydantic`, `requests` and `pandas` were declared and imported by none of the
143 tracked Python files, and `openai` was declared in the `live` extra and
imported nowhere; litellm declares it as a core dependency of its own, so the
openai provider path is unaffected. All four are removed. `boto3`, which
`tools/export_run_archive.py` imports behind `--s3-bucket`, was declared
nowhere at all and is now the `s3` extra.

The test that should have caught the four held one direction only, that every
import is declared. It now holds both, and it scans `tools/`, which it never
did.

Four of the five remaining runtime dependencies are test-only. Moving them to a
test extra requires every workflow that runs pytest to install it, the release
gate among them, and changing how the release gate installs during the release
whose evidence is that gate reporting ten of ten is a bad trade. It is a
backlog row for 2.6 with the test that would hold it.

## The crypto-unavailable path

`cryptography` is the one dependency with gate behaviour behind it. A failed
import sets `_CRYPTO_AVAILABLE` false, `_verify_signature` returns false,
`_check_crypto` records the signature step as `fail` while writing
`crypto_available: false` into the ITGL row, and the request is blocked when
`CRYPTO_ENFORCED` is on. The design is the point: a step that merely failed
would leave a reader unable to separate a missing library from a bad signature.

None of it was tested. The new tests exercise the real import failure in a
subprocess with a meta-path finder that refuses the package, rather than by
setting the module flag, which would assume the thing in question. The signed
envelope is built where the library is present and handed over as data, so the
subprocess refuses a valid signature it cannot check.

## Process changes

The benchmark job no longer arms auto-merge on the pull request it opens, and
says in its log that the request is open on purpose. An ordinary audit
publishes a row that looks like three hundred others; a benchmark publishes a
pair, and both pairs published on 15 October exposed defects in how this
repository describes a pair, each found by a person reading the evidence while
the required checks were still running. The audit job is unchanged.

`tests/test_one_version_of_a_document_is_current.py` holds that exactly one
version of a versioned document is current and that every statement of currency
names the same one. On 15 October three documents each named a different
benchmark index as current. The test found one more instance on the run that
introduced it, in an archived document's banner.

## The claims register

Re-examined in full on 16 October, in full rather than scoped to the rows this
release touched. All sixteen rows were re-read against what they cite, and the
register records how each was checked so a reader can tell an executed check
from a read one. One row could not be re-verified, the GitHub repository About
description, and the register says so rather than counting it as reviewed.

Two citations in the register resolve to documents held outside the repository.
For a document whose condition is that it survives a reader who goes looking,
a pointer that reader cannot follow fails that condition, and it is a backlog
row rather than a change here, because publishing them is a disclosure
decision.

## What is not claimed

- No statement about any model. Both halves of a pair count gate decisions and
  provider call attempts, and SIR never reads a model's response.
- No statement about harm prevented. A blocked prompt is a request that did not
  reach a provider; what it would have produced was not observed.
- No generalisation from two pairs on one model, one provider and one commit
  each.
- `AUDIT PASSED` remains a statement about one run's counters and its own
  checks, not a finding that the rule set is adequate.

## Known open items

Carried in `docs/backlog.md` with their evidence. The ones a reader of these
notes should know about:

- a certificate's `result` still mixes evidence integrity with enforcement
  outcome, which is a contract change and belongs to a release that bumps the
  contract;
- provider content refusals are still counted identically to provider call
  failures. `row_version` landed in this release so that change costs one
  format bump;
- a programming error inside `_verify_signature` is indistinguishable from an
  invalid signature, because the function wraps its body in `except Exception`.
  Fail-closed, and the evidence cannot separate our defect from their bad
  signature;
- three policy packs are byte-identical and carry three different names.

## Verifying this release

```
python3 tools/verify_certificate.py --run-dir docs/runs/<run_id>
python3 tools/verify_baseline_record.py --run-dir docs/runs/<run_id>
python3 tools/check_release_checklist.py --run-commands
```

The first two refuse the other document kind rather than reporting it as
verified. The third reports ten of ten for this release, and reports nothing
about whether the claims in these notes were re-examined; that is
`docs/claims-register.md`, and its date is the judgement.
