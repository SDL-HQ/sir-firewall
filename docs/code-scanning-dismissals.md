# Code scanning dismissals

Every CodeQL alert raised against this repository, and why each one was closed.

Dismissing a high-severity security alert is a judgement, and a judgement with
no written reasoning is indistinguishable from not having looked. This file
exists so a reviewer can check the reasoning rather than take it on trust, and
so that the dismissals rest on tests rather than on an argument made once in a
conversation.

As at 15 October 2026: **1 open, 5 closed.** One was fixed. Five are the same
finding in five places, four of them dismissed as false positives and one
raised on 15 October against the new baseline record verifier, awaiting the
same disposition.

| Alert | Rule | Location | Closed as |
|---|---|---|---:|
| #2 | Clear-text logging of sensitive information | `tools/verify_archive_receipt.py:155` | false positive |
| #3 | Clear-text logging of sensitive information | `tools/verify_certificate.py:260` | false positive |
| #4 | Clear-text logging of sensitive information | `tools/rotate_keys.py:158` | **fixed** |
| #5 | Clear-text logging of sensitive information | `tools/rotate_keys.py:169` | false positive |
| #6 | Clear-text logging of sensitive information | `tools/verify_certificate.py:233` | false positive |
| #7 | Clear-text logging of sensitive information | `tools/verify_baseline_record.py:317` | open, false positive |

## #7, raised 15 October 2026 against the baseline record verifier

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

## The four false positives

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

It does not claim the four dismissals are correct because CodeQL is noisy. Each
one turns on a specific fact, that the printed value is already published or is
an identifier rather than a secret, and that fact is asserted by a test.

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
