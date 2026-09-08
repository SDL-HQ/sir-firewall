# SIR mapping to the OWASP LLM Top 10 for LLM Applications 2026

Mapping basis: OWASP GenAI Security Project, *LLM Top 10 for LLM Applications 2026*, version 1.0, published 4 August 2026.

Date of SIR mapping (UTC): 2026-09-08

The source material is licensed under [Creative Commons Attribution-ShareAlike 4.0](https://creativecommons.org/licenses/by-sa/4.0/). This document is a project-authored mapping of the current SIR implementation. It is not produced or endorsed by OWASP or the OWASP GenAI Security Project. OWASP names and control identifiers are used only to identify the source framework.

## Implemented

### LLM01 Control 5: defined invisible-character handling

LLM01 Control 5 identifies stripping tag-block characters `U+E0000` through `U+E007F`, variation selectors `U+FE00` through `U+FE0F`, and the zero-width characters `U+200B`, `U+200C`, `U+200D`, and `U+2060`.

`normalize_obfuscation()` replaces all of those code points with a space before rule evaluation. The implementing regular expression is in [`src/sir_firewall/core.py`](../src/sir_firewall/core.py) and covers:

- `U+200B` through `U+206F`;
- `U+2800`;
- `U+202A` through `U+202F`, redundantly included within `U+200B` through `U+206F`;
- `U+3000`;
- `U+3164`;
- `U+FFFC`;
- `U+FE00` through `U+FE0F`;
- `U+E0000` through `U+E007F`;
- `U+E0100` through `U+E01EF`; and
- characters matched by Python's Unicode `\s` class.

SIR's implemented set is broader than the set named by this OWASP control. In particular, SIR replaces the full `U+200B` through `U+206F` interval plus the additional listed ranges, rather than only the four named zero-width code points. This is a statement of implementation scope, not a claim of stronger security coverage. The normaliser remains bounded and does not provide general Unicode-confusable handling.

### LLM01 Common Example 8: encoded instructions

LLM01 Common Example 8 names Base64, ROT13, and emoji encodings. SIR conditionally decodes:

- Base64 candidates of 20 through 2,000 characters when the decoded UTF-8 text is longer than 15 characters and contains one of a fixed set of security markers;
- payloads in a `ROT13 ...:` wrapper matching the implemented bounded character class;
- hexadecimal following a `hex:` marker when at least four bytes are present after separator removal and the digit count is even; and
- runs of at least four `\xNN` byte escapes.

SIR does not decode emoji encodings. It also does not decode URL encoding, Morse, Caesar shifts other than ROT13, reversed text, or steganography. Some of those words occur only in the obfuscation-signal vocabulary; recognizing a word that describes an encoding is not decoding content represented with that encoding.

## Partially addressed

### LLM08:2026 Hidden Context Exposure — Prevention and Mitigation Strategies 2 and 3

Prevention and Mitigation Strategy 2 states that critical behaviours should be enforced through independent and deterministic systems outside the model. Strategy 3 states that authorization and access controls should be enforced in a deterministic and auditable manner rather than delegated to the model.

SIR is an independent deterministic pre-inference gate. It evaluates declared ingress content outside the model, returns a rule-derived decision, and can produce run summaries, a hash-linked ledger, signed certificates, and signed archive receipts. It maps to the enforcement mechanism described in Strategy 2 and to the deterministic and auditable property described in Strategy 3. It does not perform authorization or access control, so Strategy 3 is referenced for its enforcement property only.

This is partial coverage only. SIR governs content declared through its ISC, structured-request, or tool-result ingress. It does not govern content it does not receive, bind the evaluated payload to the request later sent downstream, mediate execution-time capabilities, or validate model output.

## Not addressed

### LLM01 Controls 4 and 8

SIR does not implement least-privilege enforcement or capability budgeting.

LLM01 Control 4's deterministic policy-engine function concerns authorization of privileged calls at execution time. SIR's deterministic rules are input-gating rules. They do not authorize individual tool calls, constrain credentials, enforce resource permissions, or mediate execution.

SIR also does not:

- require human confirmation before consequential actions;
- validate model output against an output schema;
- govern writes to agent or application memory;
- mediate tool execution;
- bind a `PASS` decision to a capability token; or
- limit the number, cost, duration, scope, or privilege of downstream actions.

## Control categorisation

The OWASP 2026 material distinguishes controls intended to reduce injection success from controls that bound blast radius after an attacker can probe and adapt to a system. The first category is expected to degrade against adaptive attackers. For agentic deployments, least-privilege and capability-budgeting controls in the second category are load-bearing.

SIR's content normalization and deterministic input filtering are in the first category. SIR does not claim that input filtering is a blast-radius control, and it does not implement the execution-time controls in the second category.

This mapping is version-stamped to OWASP LLM Top 10 for LLM Applications 2026, version 1.0. It does not automatically apply to later OWASP revisions.
