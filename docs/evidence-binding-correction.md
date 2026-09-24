# Evidence-binding correction

SIR 2.3.4 corrects a certificate-generation defect. This is a correction, not
a hardening improvement.

Before 2.3.4, `tools/generate_certificate.py` selected `itgl_final_hash` from the
`ITGL_FINAL_HASH` environment variable or, when it was absent, from the mutable
`proofs/itgl_final_hash.txt` file. The ordinary audit workflow exported the
current verifier result, but the paired-benchmark path did not. Consequently,
paired certificates could sign a hash left by an earlier run instead of the
chain head of the ledger they certified.

As measured on 20 September 2026, 145 of the 200 runs indexed in
`docs/runs/index.json` carried an `itgl_final_hash` also used by another run.
The largest group contained 13 runs across three packs whose leak counts
included 0, 26, 27, and 100. In the paired run on 20 September 2026, baseline run
`20260920-092345-000000-gh35502041779-6b9fd67c75c0` has ledger head
`sha256:8e16a1e487aa0bd5cf3fde7c416a3a33c1d0ef80dd59d9a86ff0035c3dc437c7`,
and gated run `20260920-092456-000000-gh35502041779-ecfffeda49c8` has ledger
head `sha256:c769ec1e5d44185f11ca36bdaba4653ce9f6562d854194e8b1cf615ab5ebcd47`.
Both published certificates instead assert
`sha256:53c0eedf004dc29db8e4097d9c4694933301094e113486466915c35fcf6bf8c8`.
On each of `docs/runs/index.json`, benchmark index v1, and benchmark index v2,
all 200 comparison values were present: there were 87 distinct values, 32
values were shared by multiple runs, and 145 runs carried a shared value. This
count declines over time because affected runs age out of the rolling 200-run
index window, not because any archived certificate has been corrected; the
archived certificates remain exactly as originally signed.

In that measurement, the retained index spanned 2026-04-04T06:40:30Z through
2026-09-21T12:03:18Z. Runs carrying a colliding certificate hash spanned
2026-04-04T12:48:34Z through 2026-09-21T12:03:18Z: the defect is visible from
the first day represented in the published index through its most recent run.
It was not introduced only by a recent change. The introducing version or
commit was not determined from the retained artifacts.

From SIR 2.3.4, certificate generation loads the identity-derived canonical
ledger recorded by the current `run_summary.json`, verifies the chain, and
signs the run ID, computed head, and row count. An explicit non-canonical
`--ledger` is refused unless `--allow-detached-ledger` is also supplied; that
exception is signed as `"detached_ledger": true`, while ordinary bound
certificates carry `"detached_ledger": false`. Generation fails before emitting a
certificate if the ledger is missing, unreadable, invalid, differs from an
optional `ITGL_FINAL_HASH` cross-check, or has a row count different from
`prompts_tested`.

The incorrect value is also mirrored in three published index surfaces:
`docs/runs/index.json`, and `comparison.itgl_final_hash` in the per-run
`entries` arrays of `proofs/runs/benchmark_index.v1.json` and
`proofs/runs/benchmark_index.v2.json`. In the benchmark indexes,
`evidence.itgl_final_hash` is instead a path to the per-run archived hash file;
all 200 such paths are distinct and were not affected. The archived per-run
evidence paths always identified the correct run ledger. What was wrong was the
value in the signed certificate and the comparison value mirrored beside those
correct paths. Writers obtain a new comparison value from the certificate being
indexed, so corrected 2.3.4 certificates flow into new rows. Existing rows are
not rewritten.

Archived certificates and ledgers are **not** regenerated, modified, or
re-signed. The certificates remain valid signatures over exactly what they
assert, including an incorrect ledger-hash assertion where the defect occurred.
Pre-2.3.4 certificates are therefore signatures over an unbound evidence
package: their signatures can be checked, but the certificate does not reliably
identify its ledger. This correction does not establish that the evidence plane
as a whole is sound.
The per-run archived ledgers at
`proofs/runs/<run_id>/proofs/itgl_ledger.jsonl` are individually chain-valid and
are the authoritative evidence for those runs.

Pair records in `proofs/runs/pairs/*.json` never carried a ledger hash. They
bind the two sides by explicit baseline and gated run IDs plus `pair_key`, so
pairing identity was not affected and those records are unchanged.

Evidence contract v1 applies from `sir_firewall_version` 2.2.0. The contract
validator reports earlier and unversioned archive certificates as not
applicable, rather than presenting their older shapes as current-contract
violations. It does not relax the contract for certificates at or above 2.2.0.


As at 24 September 2026, there are 357 certificates under `proofs/runs/` and
`proofs/archive/`; 62 are in scope for evidence contract v1 and pass. A closed
set of 29 in-scope certificates carry an `itgl_final_hash` shared with another
in-scope run (at versions 2.2.0, 2.2.1, 2.3.0, and 2.3.3). Contract-shape
validity and ledger binding are different properties: passing the contract says
nothing about whether a certificate names its own ledger.

A separate closed set of 295 certificates predates the 2.2.0 applicability
floor and is reported with the distinct not-applicable exit code; these are not
current-contract failures. Of that set, 185 have exactly the two missing
governance fields, while 110 have additional missing or legacy fields and, in
some cases, legacy result values. No new certificate can join either closed
set: version 2.3.4 fixed certificate generation, and certificates below the
2.2.0 applicability floor will not be created again.

The root-level `proofs/itgl_ledger.jsonl`, `proofs/itgl_final_hash.txt`,
`proofs/run_id.txt`, and `proofs/run_summary.json` files are mutable
compatibility copies. They are not evidence. Per-run archived artifacts and the
signed certificate fields are the evidence surfaces.
