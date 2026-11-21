# Code scanning dismissals

The CodeQL alerts raised against this repository, by number, and why each one
was closed.

Dismissing a high-severity security alert is a judgement, and a judgement with
no written reasoning is indistinguishable from not having looked. This file
exists so a reviewer can check the reasoning rather than take it on trust, and
so that the dismissals rest on tests rather than on an argument made once in a
conversation.

This page covers alerts **#2 to #10**, nine of them, as at 21 November 2026. One
was fixed. Eight are the same rule raised in eight places, all dismissed as
false positives. An alert numbered above 10 was raised after this page was last
written and is not here yet.

It used to open with "Every CodeQL alert raised against this repository" and a
count of open alerts. Neither was something a page can keep true by itself:
three alerts were raised and dismissed on pull request #517 and this page went
on saying there were six. It now says which numbers it covers, and
`tests/test_the_code_scanning_page_covers_what_it_says.py` holds that sentence
to the table below. Whether the table is the whole list is a question for
GitHub, and the first command under "Where to check this" asks it. Nothing runs
that command automatically.

| Alert | Rule | Location | Closed as |
|---|---|---|---:|
| #2 | Clear-text logging of sensitive information | `tools/verify_archive_receipt.py:155` | false positive |
| #3 | Clear-text logging of sensitive information | `tools/verify_certificate.py:260` | false positive |
| #4 | Clear-text logging of sensitive information | `tools/rotate_keys.py:158` | **fixed** |
| #5 | Clear-text logging of sensitive information | `tools/rotate_keys.py:169` | false positive |
| #6 | Clear-text logging of sensitive information | `tools/verify_certificate.py:233` | false positive |
| #7 | Clear-text logging of sensitive information | `tools/verify_baseline_record.py:317` | false positive |
| #8 | Clear-text logging of sensitive information | `tools/verify_archive_receipt.py:361` | false positive |
| #9 | Clear-text logging of sensitive information | `tools/verify_baseline_record.py:633` | false positive |
| #10 | Clear-text logging of sensitive information | `tools/verify_certificate.py:574` | false positive |

## #8, #9 and #10, raised on pull request #517, the key-file check

The same rule at three more places, one in each verifier, and they turn on a
different fact from the five before them.

Each flagged line prints why a document whose signature verified under a key
from a public key file is not honoured. The sentence comes back from
`key_registry.key_file_refusal`, which is handed the key that verified so that
it can ask the registry whether any entry holds that key. The key is compared
with each entry's key and is never formatted into anything. What comes back
names a registry `key_id` and the rule that refused, and where the anchored set
refuses, the document's own payload hash, which the document states. The scanner
marks the key parameter as sensitive and follows it to the print. It does not
follow what the function does with it. The key is also a public key.

Dismissed as false positives before pull request #517 merged on 21 November
2026.

Unlike #7, the test that states why did not land with the code that raised the
alerts. It landed with the change after it:
`test_no_key_material_reaches_anything_the_two_functions_hand_back_to_be_printed`
in `tests/test_one_key_resolution_for_every_verifier.py`, which collects every
sentence the key resolution can hand a verifier to print and asserts that no
line of a public or a private key is in any of them.

**The three lines above no longer exist.** That same change replaced the three
call sites: each verifier now prints what `key_registry.refusal_after_signature`
returns, and what a refused `key_registry.resolve_keys` says. Both take key
material and return a sentence, which is the shape this rule follows, so the
finding is expected again at the new lines. Those alerts get rows here when they
have numbers, and the test above is what a disposition of them would rest on.

## #7, raised and dismissed 15 October 2026, baseline record verifier

The same finding as #2, #3 and #6, at a fifth place, and it turns on the same
fact. The ungated baseline record is the second kind of signed document SIR
issues, and `tools/verify_baseline_record.py` refuses one whose signing key was
revoked by printing the revocation reason, exactly as the certificate verifier
does. The printed value names the rule that fired and the anchor it was
compared against, and that anchor, `last_trusted_run_id`, is committed in
plaintext in `spec/pubkeys/key_registry.v1.json`.

The suggested remediation is to delete the reason from the message. That would
leave a consumer holding exit code 10 with no way to tell which revocation rule
refused their archive, which is the distinction exit 10 exists to draw.

Three tests were added with the alert, so this disposition rests on the same
footing as the others rather than on the paragraph above: the record verifier
refuses a revoked key at exit 10, that refusal explains which rule fired, and
no line of key material reaches its output. They are in
`tests/test_no_key_material_in_diagnostics.py` beside the certificate's.

Dismissed as a false positive on 15 October 2026 by the repository owner, after
checking the flagged expression and finding no secret in it. The tests above
landed with the code that raised the alert rather than after the dismissal, so
a reviewer can check the basis rather than the conclusion.

## The four false positives of #2, #3, #5 and #6

All four sit in code that handles signing keys, and CodeQL's taint analysis
treats a value that has passed through key-handling code as sensitive. In each
case the value printed is not key material.

**#2, #3 and #6 print a revocation reason.** When a verifier refuses a
certificate because its signing key was revoked, it prints why. That reason
names the revocation rule that fired and the anchor it was compared against,
which is a published run identifier: `last_trusted_run_id` is committed in
plaintext in `spec/pubkeys/key_registry.v1.json` and is served from the public
site. A value already published cannot be leaked by printing it.

#6 is the same refusal on the path where a certificate carries no
`signing_key_id` and is therefore resolved as the implicit key, so the message
also names that key id. A key identifier is not a key.

**#5 prints the new key id and the key size** at the end of a rotation, so the
operator can confirm which key was created. Repository variables carry the key
id in the clear by design, because an identifier is not a secret and
`SDL_SIGNING_KEY_ID` is readable by anyone who can read Actions logs.

### The dismissals rest on tests, not on the argument above

`tests/test_no_key_material_in_diagnostics.py` holds the property in both
directions, across eleven tests, the last three added for #7:

- no key material reaches a revocation reason, on every refusal path,
- every refusal still explains itself, so the fix for the alert cannot be to
  stop saying anything,
- an allowed proof carries no reason at all,
- the flagged value is published in the repository, which is the fact the
  dismissal turns on,
- the keyless-certificate path is refused when the implicit key is revoked, that
  refusal names the rule that fired, and no key material reaches it either.

If a future change does route key material into one of those messages, those
tests fail. The dismissal is then wrong and the alert should be reopened rather
than re-dismissed.

## The one that was fixed

**#4, `tools/rotate_keys.py:158`.** This was not a false positive and was not
argued away. The rotation tool now refuses to write a private key into the
repository at all: `--private-out` is required, and the path it writes is the
public half only. The fix landed with the key custody work, in the commit that
also added the diagnostics tests.

## What this file does not claim

It does not claim the eight dismissals are correct because CodeQL is noisy. Each
one turns on a specific fact, that the printed value is already published, is
an identifier rather than a secret, or is a sentence no key was formatted into,
and that fact is asserted by a test.

It does not claim no future alert will be genuine. The standing rule is that a
clear-text-logging alert on this codebase is investigated on its own facts, and
dismissed only when a test can state why.

## Where to check this

```
gh api repos/SDL-HQ/sir-firewall/code-scanning/alerts
python3 -m pytest tests/test_no_key_material_in_diagnostics.py -q
```

The alert list is also at **Security**, then **Code scanning**, in the
repository. Filter on closed alerts to see the dispositions above.
