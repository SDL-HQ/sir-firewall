# Additional Phase 1 repository findings

Date reviewed: 2026-09-18

This note answers review questions 8–12 against the current repository tree.  A
statement about authorship, an external URL, or an external transparency system
is marked **not determinable from the tree** where repository contents cannot
establish it.

## 8. `deterministic_rules.py`

**Verdict: inaccurate.**  The module does contain compiled regular expressions
for phrase families, but it is not only a bag of expressions.  It declares seven
stable family names, associates hit codes with those families, exposes family
and obfuscation-signal helpers, and implements the deterministic decision
procedure `find_rule_hits()`.  That procedure lowercases its input, applies
single-pattern rules, conjunctive rules (for example exfiltration verb plus
target and obfuscation signal plus obedience signal), false-positive exclusions,
and ordered de-duplication.  It returns hit codes whose docstring explicitly
says the matching text “should be blocked.”  That is policy-bearing blocking
logic, even though the file has no numeric scoring and keeps no cross-request or
conversation state.  Its only transient state is the per-call hit/seen lists and
sets.

## 9. `generic_safety` and the published 2.2.1 evidence

**Mixed verdict.**  The suite at
`tests/domain_packs/generic_safety.csv` has exactly 150 data rows: 50 labelled
`allow` and 100 labelled `block`.  The current 2.2.1 certificate records that
path, 150 prompts, zero leaks, and zero harmless blocks.  The Git history says
the file was created and subsequently changed by the `SDL-HQ` Git identity.
That supports “committed in this repository under the SDL-HQ identity,” but a
tree and Git metadata cannot establish who actually wrote the prompts or who
had authority to assign the labels.  The stronger “authored by SDL” claim is
therefore **not determinable from the tree**.

Using a reproducible mechanical meaning of “matched by a regex”—pass each
expected-`block` prompt through the current `normalize_obfuscation()` and then
`find_rule_hits()`, and count rows with at least one hit—**89 of 100** block rows
match.  The same 89 match without normalisation.  The 11 non-matching rows are
`gs-014` through `gs-019` and `gs-021` through `gs-025`; they are blocked by the
older policy-keyword path in `core.py`, not by a regular expression in
`deterministic_rules.py`.  “Near-literal” is not a repository-defined metric, so
89 is the auditable direct-regex count rather than a subjective similarity
score.

## 10. The cited 100-to-26 paired result

**The figures exist, with a version-label caveat.**  The pair is
`proofs/runs/pairs/20260422-092700-649c31ee0b06.json`.  It covers
`eu_ai_act_compliance_pressure` v1.0.0 on provider `xai`, requested model
`grok-4-1-fast`, at commit `05107b2252a3c5623435d3e32733eae6fd418198`:

- ungated baseline: 100 leaks, run
  `20260422-092233-000000-gh24770156695-02c9b1dbef40`, certificate at
  `proofs/runs/20260422-092233-000000-gh24770156695-02c9b1dbef40/audit.json`;
- SIR-gated: 26 leaks, run
  `20260422-092659-000000-gh24770156695-7d50e5cca234`, certificate at
  `proofs/runs/20260422-092659-000000-gh24770156695-7d50e5cca234/audit.json`.

Both certificates say `sir_firewall_version: 1.0.2`, not 2.0.0, and both are
`LIVE_GATING_CHECK` results for 150 prompts.  Thus “the result discussed in the
v2.0 release/evidence line” is accurate, but “a run whose certificate says
v2.0” is inaccurate.  Both JSON certificates contain non-empty RSA signatures
and `signing_key_id: default`, and both are mirrored under the equivalent
`docs/runs/...` paths together with the pair record.  The tree therefore shows
that signed certificates exist and are staged for the public documentation
site.  Public reachability is **not determinable in this review environment**:
an attempted request to each raw GitHub mirror was denied by the environment's
network proxy before an HTTP response was received.

## 11. Current backlog and implementation claims

| Claim | Verdict | Current repository evidence |
|---|---|---|
| No multi-turn state | **Accurate, with scope qualification.** | The product boundary excludes deep stateful conversational governance, and deterministic rules receive one string and retain no state between calls. Scenario runners can evaluate ordered turns, but that is not a stateful conversation-policy engine. |
| Incoming crypto enforcement is off by design | **Accurate.** | Built-in and every current ISC pack set `CRYPTO_ENFORCED` false; key-governance documentation says this remains false by design pending readiness work. Checksums remain enforced separately. |
| Pack content hash is not computed at load | **Accurate.** | `load_domain_pack()` parses JSON and returns it without hashing it. `validate_sir()` only records a `pack_hash` supplied by `pack_identity_context`; backlog item “Pack hash self-computation” records the gap. |
| Signing uses PKCS#1 v1.5 rather than PSS | **Accurate.** | Certificate/policy/archive signing and verification use `padding.PKCS1v15()`; migration to RSA-PSS is a planned backlog item. |
| Some published packs return 404 at runtime | **Inaccurate literally; substantially accurate if “404” means missing local policy pack.** | Runtime pack loading performs no HTTP request and returns no HTTP 404. Four active registry suites (`account_recovery_fraud`, `mental_health_clinical`, `scenario_injection_chain`, and `scenario_tool_injection`) lack same-named ISC policy-pack files. Selecting them through `--pack` raises local `FileNotFoundError`, which the execution path turns into systemic-reset blocks. |
| Parser work occurs before size checks | **Accurate for raw structured/tool-result JSON, not for every ingress mode.** | The two string JSON ingress modes call `json.loads()` before validating the extracted content length. The backlog records that parser cost remains attacker-proportional. |

The v2.2.1 payload fast path did **not** eliminate that last parser-order issue.
It rejects an already-extracted string ISC payload when its character length is
greater than four times the selected template limit, before normalisation and
crypto work.  Raw structured/tool-result envelopes must still be parsed to
extract their content before the content limit can run, and non-string ISC
payloads still incur `str()` coercion before rejection.  Moreover, the 2.2.1
release notes say that release did not change runtime behaviour; the size fix is
documented as an already-current bounded improvement, not a raw-envelope parser
cap.

## 12. External anchoring

**No external transparency-log or timestamp-authority publication is evidenced
by the repository.**  Certificates contain payload hashes and timestamps, and
the repository and Pages mirrors publish those artefacts, but the release notes
explicitly describe independent timestamp anchoring and external immutable
storage as planned/optional rather than the current default.  No inclusion
proof, TSA token, transparency-log identifier, or third-party anchoring receipt
appears in the tree.  Absolute absence from every external service is not
provable from a source tree; the bounded finding is that the repository neither
implements nor records one.

The remaining attestation is more precisely described as **SDL-signed and
verified against SDL-controlled trust material** (`spec/sdl.pub` and
`spec/pubkeys/key_registry.v1.json`), not “self-signed against the registry.”
The registry is a public-key lookup and revocation-policy source; it is not an
independent signer or witness.  Local and CI ephemeral-key artefacts are also
possible and are explicitly classified as non-authoritative.  Consequently,
signature verification establishes integrity against the selected key, but no
third-party transparency or trusted-time assertion.
