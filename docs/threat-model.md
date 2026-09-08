# SIR threat model

Date (UTC): 2026-09-08

## Scope and adversary model

SIR is a deterministic pre-inference gate for declared ingress content. It evaluates ISC text, structured-request content, or tool-result content and returns `PASS` or `BLOCKED` with rule and trace metadata.

The adversary may control the content presented to the gate, including formatting, encoding, Unicode characters, declared tool-result content, and fields accepted by an ingress schema. An adversary may adapt inputs after observing gate outcomes. SIR does not assume that input filtering remains effective against every adaptive transformation.

The adversary is not assumed to control the process executing SIR, its loaded policy and rule files, its signing key at signing time, or the evidence producer at capture time. **The evidence producer is trusted at capture time.** SIR does not independently establish that the producer executed the recorded run, supplied truthful metadata, or captured a real event. Its evidence guarantees are post-signing tamper-evidence and reproducibility from retained inputs and repository state, not authenticity of the recorded event.

Compromise of the evidence producer, runtime, policy source, suite source, signing key, or integration path is outside this trust boundary.

## Derived versus asserted evidence fields

The certificate signs both derived and asserted fields. The signature makes both classes tamper-evident after signing. Only derived fields are computed by SIR from something it observed. A verifier reading a certificate cannot currently distinguish the two classes from the certificate schema alone.

### Derived fields

| Field | Derivation boundary |
|---|---|
| Payload hash | Computed over the reconstructed certificate payload before signing. |
| ITGL final hash | Computed by the ITGL verifier from the run ledger, then supplied to certificate generation through `ITGL_FINAL_HASH` or `proofs/itgl_final_hash.txt`. Certificate verification does not recompute it from a ledger. |
| Suite hash | Computed from decoded suite content by the run harness; certificate generation prefers the value in `run_summary.json`. |
| Rule evaluation results | Computed by the gate for the declared ingress content and aggregated by the run harness. |
| Policy hash | Computed from the canonical policy file by certificate generation. |

### Asserted fields

| Field | Assertion source |
|---|---|
| `pack_version` | Registry or caller-supplied pack identity context. |
| `pack_hash` | Caller-supplied pack identity context; core does not compute it. |
| `tool_name` | Caller-supplied tool-result ingress. |
| `key_id` / `signing_key_id` | Caller or producer selection. Key resolution can validate that a signature matches a registered key; it does not establish that the asserted event occurred. |
| Run metadata | Producer, environment, CLI, registry, or summary values, including model, provider, suite path/name, repository, commit SHA, timestamps, run URL, pack identity, and benchmark role. |

Some aggregate certificate fields are derived from `run_summary.json`, but certificate generation trusts that producer artifact rather than replaying the run. Their arithmetic can be contract-checked without establishing the truth of the underlying event.

## The integration boundary

SIR evaluates a payload and returns a decision. It does not return an approved payload, a sealed request, or a capability token. Nothing binds the payload SIR evaluated to the payload an integrator subsequently forwards to a model, agent, tool, or other downstream system.

The integrator is responsible for ensuring that only the exact evaluated payload proceeds after `PASS`, that a `BLOCKED` result cannot be bypassed, and that no alternate model or tool path bypasses the gate.

## What verification establishes

### `tools/verify_certificate.py`

The certificate verifier reconstructs the signed payload, checks its SHA-256 `payload_hash`, verifies the RSA signature, resolves registered key material when available, and applies the implemented revocation-time rule when registry verification is used.

It does not establish that a run occurred, that asserted fields are true, that the policy or rule result was correct, that a model is safe, that the certificate satisfies the evidence contract, or that a certificate's `itgl_final_hash` corresponds to a supplied ledger.

### `tools/verify_itgl.py`

The ITGL verifier establishes limited structure and chain linkage. It requires a non-empty JSONL ledger, required linkage fields, a non-empty per-prompt final hash, `GENESIS` on the first entry, continuous `prev_hash` values, and `ledger_hash == sha256(prev_hash + final_hash_raw)` for every entry.

It does not validate the semantic contents of an entry or establish authenticity. A fabricated ledger with valid hash arithmetic passes it. Timestamps and prompt indexes are required fields but are not covered by the ledger hash and are not checked for type, order, monotonicity, or truth.

The terminal ledger hash must be compared with an `itgl_final_hash` covered by a valid signed certificate for the chain to be meaningful as certificate-linked evidence. That comparison is not automatic. Certificate generation can embed the output of an earlier ITGL verification step, but neither verifier independently opens and compares both artifacts.

### `tools/validate_certificate_contract.py`

The contract validator checks required fields, defined field types and constraints, flag structure, fingerprint aliases, proof-class conditionals, counter relationships, suite/scenario hash presence, scenario consistency, and limited signing-key identifier expectations.

It does not verify a signature, authenticate field values, recompute source-artifact hashes, validate a ledger, replay gate decisions, or establish that the asserted run occurred.

### `tools/verify_archive_receipt.py`

The archive verifier checks required manifest and receipt structures, key resolution and applicable revocation rules, the canonical manifest hash, the existence, size, and SHA-256 of every manifest-listed file, the run-folder hash, the receipt payload hash, and the receipt signature.

It does not establish the semantic truth of archived files, detect files that should have been included but were omitted, validate an archived certificate, validate an ITGL chain, compare a ledger with a certificate, or establish that the archived run occurred.

## The published surface

The GitHub Pages surface performs no client-side certificate-signature verification. It is a display convenience, not a trust anchor. Viewing `latest-audit.html`, `latest-run.html`, or their JSON data does not execute the offline verifiers.

Verification requires fetching the artifact and running the applicable verifier locally with trusted public-key or key-registry material.

## What SIR retains

There are two operating boundaries. A direct `validate_sir()` library call returns evidence in memory and does not itself write files. The audit runner and certificate/archive tools create persistent artifacts.

| Artifact | Path or surface | Contents | Can raw caller content appear? | Enablement | Default? |
|---|---|---|---|---|---|
| Per-request ITGL step log | Returned as `result["itgl_log"]`; no automatic file path | Timestamped pipeline components, outcomes, bounded inputs and outputs, per-step hashes, and previous hashes | The raw payload is generally not included. Caller fields such as `key_id`, supplied `pack_version`, supplied `pack_hash`, and `tool_name` can appear. Error strings can contain producer or runtime detail. | Every `validate_sir()` call | Returned by default; not persisted by core |
| Run ledger | `proofs/itgl_ledger.jsonl` | Timestamp, prompt index and ID, category, note, expected and actual status, prompt hash, suite path, pack/template fields, per-prompt final hash, linkage fields, and optional explainability | The prompt is hashed rather than stored. Raw suite metadata such as ID, category, note, scenario role, and turn identifiers is stored. | `red_team_suite.py` / `sir run` | Written by runner executions |
| Attempts log | `proofs/latest-attempts.log` | Run header, model, suite path/hash/count, row IDs, expected/actual results, mismatches, and provider error type/message | Prompt text is not intentionally written. A provider exception string may contain caller or provider content. | Runner execution | Written by runner executions |
| Run summary | `proofs/run_summary.json` | Run time, proof class, model/provider, pack identities, suite path/hash, outcome and call counts, flags, governance scope, crypto state, and benchmark role | No prompt or response body. Caller- and producer-selected metadata appears. | Runner execution | Written by runner executions |
| Signed certificate | `proofs/archive/audit-certificate-<timestamp>.json` and selected current certificate targets | Version, suite/pack/model/provider/run metadata, hashes, counts, flags, result, repository/commit/key metadata, signature, and payload hash | No prompt or provider response body. Producer-supplied and asserted metadata is signed as provided. | Separate certificate generation with signing key | Not written by a bare library call or runner alone |
| Downstream evidence sidecar | `proofs/downstream_evidence.jsonl` | Timestamp, prompt index/ID, provider/model, call outcome, response-storage mode, response hash, artifact reference, optional response excerpt, and bounded error detail | Prompt text is not written. Raw model output can appear in `response_excerpt`; provider error text can appear up to 200 characters. | Live mode plus `--capture-downstream-evidence`; an excerpt additionally requires a positive `--downstream-evidence-excerpt-chars` | Off by default; enabled success capture is hash-only by default |

With default runner capture, SIR persists prompt hashes, row and run metadata, decisions, chain values, summaries, and provider error strings, but not prompt bodies or successful model-response bodies. With every optional downstream capture enabled, it additionally persists bounded raw model-response excerpts. Archiving can retain each copied artifact under `proofs/runs/<run_id>/`.

## Normalisation scope

`normalize_obfuscation()` is bounded. It applies NFKC and lowercase handling, replaces a defined set of whitespace, invisible, tag, and variation-selector characters, recognizes two fixed phrase aliases, conditionally decodes Base64, ROT13, marked hexadecimal, and repeated `\xNN` escapes, and performs fixed marker recovery over compacted punctuation, repeated characters, leetspeak, and nine Cyrillic/Greek homoglyph mappings. It does not perform semantic rewriting or general Unicode-confusable resolution.

The homoglyph translation feeds fixed marker detection only. The translated compact text is not returned as evaluated content. Evaluated content retains the original homoglyph characters, with only detected canonical marker phrases appended in ASCII. Multi-token rules can therefore be bypassed when marker recovery does not restore every token the rule requires. This limitation is recorded in [`docs/backlog.md`](backlog.md).

Whole-payload substitutions using only the nine claimed mappings changed `ignore all safety checks` and `reveal the system prompt` from `BLOCKED` to `PASS`. `suppress the audit log` remained `BLOCKED` because that complete phrase is one of the canonical multi-word markers.

The published `generic_safety` zero-leak result is not evidence of resistance to homoglyph substitution. No row in any suite contains actual homoglyph-substituted text. Row `gs-111` mentions “Unicode homoglyph” in ASCII prose and blocks on the unrelated `JB_EVADE_FILTERS` rule because it says `disable moderation`; marker recovery is not involved.

The existing Hypothesis homoglyph property substitutes a non-empty subset of eligible characters only within one selected marker word. It does not apply substitution throughout the payload and does not cover this bypass.

## Out of scope

SIR does not:

- prevent all prompt injection;
- provide semantic attack detection;
- resolve general Unicode confusables;
- decode arbitrary nested or unsupported encodings;
- control downstream agent behavior;
- bind evaluated content to content forwarded by an integrator;
- replace application-level security controls;
- evaluate content it does not receive;
- validate API message ordering;
- establish least privilege;
- budget capabilities;
- require human-in-the-loop confirmation;
- validate model-output schemas;
- govern memory writes;
- mediate tool execution;
- prove model safety;
- prove that a signed or archived run occurred;
- make producer-asserted evidence fields true by signing them; or
- make a hash-linked but unsigned ledger authentic.
