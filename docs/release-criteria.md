# What blocks a release tag

Written 13 October 2026, after 2.4.0 went through three independent review
rounds without a written rule for when it was finished.

## Why this exists

The rounds found roughly four, then six, then eight items. The distribution
across all three:

| | round 1 | round 2 | round 3 |
|---|---:|---:|---:|
| behavioural defects in the gate or its tooling | 1 | 1 | 2 |
| tests passing under the mutation they exist to prevent | 0 | 2 | 3 |
| published descriptions of mechanisms nobody had executed | 2 | 3 | 3 |

It is not converging, and that is not a sign the code is getting worse. A
narrative review of a codebase this size will always find something, so "tag
when a review comes back clean" is not a reachable condition. Without a written
rule, review stops supplementing the release process and becomes it: three days
of 2.4.0 were spent that way.

The rule below is deliberately short, and three of its four parts are things a
person can check rather than argue about.

## The four blockers

A release tag is blocked by any of these, and by nothing else.

**1. A false statement on a public surface.** Any sentence on a surface a reader
can reach that is not true of the tagged revision. The README, the repository
description, the website, the release notes, the claims register, the assurance
kit, the specification, and any generated figure.

**2. A test that stays green under a mutation of the behaviour it names.** If a
test is named for a behaviour, mutating that behaviour must fail it. A test that
passes while the thing it describes is broken is worse than no test, because it
reports coverage that does not exist. Five such tests were found across the
three rounds of 2.4.0.

**3. A verification command that fails from a clean clone.** The commands in
`docs/assurance-kit.md` and the release-notes verification section must work
with no credentials, no network and no local state. If a reader cannot reproduce
the evidence, the evidence is a claim.

**4. A sentence that invites an inference the archive does not support.** Even
when every word is defensible.

The fourth is the one that was paid for. "Produce verifiable evidence that a
given governance configuration actually enforces what it claims" was not a false
sentence, and it was corrected in 2.4.0 anyway, because a reader skims a goal
line and takes from it that a policy-shaped input was shown to produce a
verdict. The pack measurement does not support that. Without this clause, that
episode becomes a precedent for shipping the inference and fixing the footnote.

## Who decides the fourth

The founder, named here because an unowned judgment criterion loses to shipping
every time. The first three can be settled by anyone who runs the check. The
fourth cannot, and a disagreement about it is escalated rather than resolved by
whoever is holding the commit.

Anything raised that does not meet one of the four gets a row in
`docs/backlog.md` and the tag proceeds. A row is not a lesser outcome: it is the
difference between a release that ships with its limits recorded and a release
that waits for a condition nobody wrote down.

## What this does not cover

Not a definition of done for a feature, and not a code review standard. It
governs one question: whether a version number may be attached to a revision.

It is also not a claim that a release meeting these four is correct. The 2.4.0
review rounds found two behavioural defects that all four criteria would have
caught and six wrong descriptions that criterion 1 would have caught, and they
were found by someone reading the code rather than by the criteria. These are a
floor, not a method.
