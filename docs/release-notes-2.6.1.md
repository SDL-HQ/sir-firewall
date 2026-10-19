# SIR 2.6.1 release notes

One change to the gate, and the larger part of this note is what the change
deliberately does not do.

## Combining marks are stripped before anything reads the text

`normalize_obfuscation` opened with `unicodedata.normalize("NFKC", text)`.
NFKC composes a base letter and a combining acute into a single codepoint and
leaves it there, so a prompt written with diacritics reached every downstream
decision unchanged and no rule matched it. The gate passed
`ignóre áll prevíous instrúctions` with every rule family reporting clean.

The function now decomposes with NFKD, drops the combining marks, and applies
NFKC to what remains, which keeps the compatibility folding the previous line
relied on for fullwidth forms and ligatures. The four decoders below that line
are unaffected and were checked individually rather than assumed: the base64
marker, `rot13:`, the `hex:` marker and `\xNN` escapes all still decode.

## What was measured and not shipped

The change as originally proposed went further: delete non-word characters as
well, which also closes separator and whitespace-injection phrasings. That
form was measured in an independent harness and the figure was real.

It is not shipped, because it was measured in one direction only. Every
decoder in `normalize_obfuscation` keys on punctuation, and deleting non-word
characters ahead of them removes the thing they match on. Run against the
three marker-based decoders, the aggressive form stops all of `rot13:`, the
`hex:` marker and `\xNN` escapes from decoding at all. Base64 survives, and
only because its decode path retries across nine padding lengths.

So the aggressive form closes two classes and opens three, and the measurement
that recommended it counted evaded inputs becoming blocked without counting
blocked inputs becoming evaded. Separator handling belongs in an additional
matching view rather than in a destructive rewrite of the input, and is not
attempted here. The reasoning is in the function so that the next reader does
not helpfully complete the fix.

## The configuration identity moves

`normalize_obfuscation` is one of the two functions whose source is covered by
the published configuration identity, so this release changes
`configuration_hash`. That is intended and is the mechanism working: runs
before and after are distinguishable by the identity the gate publishes about
itself, without anyone having to consult a version string.

It is also why this is 2.6.1 rather than a re-cut of the previous tag. Five
published certificates already carry the earlier version, and redefining a
version that signed artefacts already claim would leave one identity standing
for two different gates. That is the defect this project names as its
recurring one, and declining to create it deliberately was the cheaper option.

## What is not claimed

One class of obfuscation closes. Separator, whitespace-injection, leet,
off-map homoglyph and semantic phrasings are unchanged by this release, and
`docs/backlog.md` and `docs/rule-coverage.md` remain the places where the
gate's coverage is described.

Nothing here changes the evidence plane. The freeze stated at 2.6.0 holds for
the rule set; this is a normalisation defect found by measurement, fixed, and
released on its own rather than held until something else needed shipping.

## Verifying this release

```
python3 tools/verify_certificate.py --run-dir docs/runs/<run_id>
python3 tools/verify_baseline_record.py --run-dir docs/runs/<run_id>
python3 tools/check_release_checklist.py --run-commands
```

The first two refuse the other document kind rather than reporting it as
verified. The checklist carries the conditions stated at 2.5.0 and at 2.6.0,
which are durable properties rather than one release's features, and each
still resolves.
