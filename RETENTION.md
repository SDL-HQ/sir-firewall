# SIR Proof Retention & Audit Durability

This document defines SIR retention semantics in plain technical language.

It separates:

- what is retained and verifiable in this repository today
- what is public/shared versus local/operator-local
- what current durability does and does not guarantee
- what hardening options are planned but not yet guaranteed by repo-only retention

The version-selected machine-readable certificate contracts are `spec/evidence_contract.v1.json` (2.2.0–2.3.3), `spec/evidence_contract.v2.json` (2.3.4), `spec/evidence_contract.v3.json` (2.3.5–2.3.x), and `spec/evidence_contract.v4.json` (2.4.0+). An ungated baseline record is not a certificate and is governed by `spec/baseline_record.v1.schema.json` instead.

---

## 1) Current retention truth (repository reality today)

Current retained artefacts are in version control under `proofs/` and `docs/`, including:

- latest passing certificate pointer:
  - `proofs/latest-audit.json`
  - `proofs/latest-audit.html`
- latest run status pointer:
  - `docs/latest-run.json` (served at `/latest-run.json` on Pages)
- run evidence files:
  - `proofs/run_summary.json`
  - `proofs/latest-attempts.log`
  - `proofs/itgl_ledger.jsonl`
  - `proofs/itgl_final_hash.txt`
- per-run archive folders:
  - `proofs/runs/<run_id>/manifest.json`
  - exactly one signed document: `proofs/runs/<run_id>/audit.json` for a gated
    run, or `proofs/runs/<run_id>/baseline.json` for an ungated baseline record
  - `proofs/runs/<run_id>/archive_receipt.json`
  - copied run evidence for that run
- archive indexes:
  - `proofs/runs/index.json`
  - `proofs/runs/index.html`

What can be verified now:

- certificate signature + payload hash verification (`sir verify cert ...` / `tools/verify_certificate.py`)
- archive receipt verification for a run bundle (`sir verify archive ...` / `tools/verify_archive_receipt.py`)
- ITGL chain verification (`tools/verify_itgl.py`)
- file/history presence in Git and published Pages surfaces

This is the current retention truth. It is evidence-retaining and reviewable now, but it is not the same as external immutable retention controls.

### Transparency-log posture (current, bounded)

For external reviewers, treat `proofs/runs/` as SIR's current **append-only public evidence history posture**:

- each published run is stored under `proofs/runs/<run_id>/` with run-scoped evidence + receipt files
- `proofs/runs/index.json` and `proofs/runs/index.html` provide a navigable run history view
- integrity checks are grounded in per-run signatures/receipts and ITGL verification, not in a claim of storage-level immutability

This posture means the archive is designed to accumulate attributable run evidence over time for public technical review. It does **not** claim WORM/object-lock immutability from GitHub/Git alone.

#### Append-only, and what that word is worth here

Added 13 October 2026. Nothing enforces append-only on the published archive.
There is no continuous integration check, no test, and no schema constraint
preventing a published run from being removed. Append-only is a convention, not
a control, and a reader should treat it that way. The same sentence appears in
[`docs/key-custody.md`](docs/key-custody.md) about the key registry, for the
same reason and with the same force.

The disclaimers above concern storage-level immutability and adversarial or
legal threat models. The ordinary case is simpler and none of them covers it. A
branch cut before a run is published, and merged after it, carries a tree in
which that run's directory and its index entry are both absent. No adversary is
involved, every test passes, and `index.json` agrees with the archive on disk
because both were reverted together, so a consistency check between them finds
nothing wrong.

That state arose here on 13 October 2026. A documentation branch was prepared
whose tree, merged as a merge commit or a rebase, would have removed one
published run. The squash merge this repository uses would not have, because a
squash applies only the branch's own changes rather than its whole tree. The
branch was rebuilt rather than relying on that distinction, because a merge
strategy is a setting and not a control, and nothing in the repository would
have reported the difference.

Two things follow for a reader. Every run published today is present and
verifies, which `python3 tools/archive_verification_report.py` re-derives from
the files rather than asserting, with the known defects recorded in
[`docs/archive-errata.md`](docs/archive-errata.md). Whether any run was ever
published and later removed is **not** established by anything in this
repository. That history is in git, and a reader who needs the property should
read it there rather than take this posture's name for it.

Closing the gap needs a check against history outside the branch being merged,
because any baseline committed inside the repository is reverted by the same
merge that removes the run. Recorded in [`docs/backlog.md`](docs/backlog.md).

Known defects in the published archive, including runs whose receipts or certificates do not verify, are recorded in [`docs/archive-errata.md`](docs/archive-errata.md) and can be re-derived with `python3 tools/archive_verification_report.py`.

Where the signing key lives, what can sign with it, and which properties are conventions rather than enforced controls, are recorded in [`docs/key-custody.md`](docs/key-custody.md).

---

## 2) Public/shared vs local/internal surfaces

### A) Public/shared truth surfaces (reviewable by third parties)

Primary shared surfaces:

- repository artefacts in `proofs/` (GitHub repository)
- published Pages views that render those artefacts (`latest-audit.*`, `latest-run.json`, `runs/index.*`)

Use these for shared review, reproducibility, and independent technical inspection.

### B) Local/dev or operator-local artefacts

Local runs and local signing workflows may produce artefacts that are useful for engineering verification but are not automatically SDL/public-authoritative.

Examples:

- locally generated certificates signed by non-authoritative keys
- locally exported bundles before any external retention upload
- local temporary run directories and test outputs

Local artefacts can still be cryptographically checked, but trust source and authority are distinct from published SDL/public surfaces.

---

## 3) Durability boundaries (explicit)

### What current repo + Pages retention does provide

- durable evidence snapshots as long as artefacts remain in Git history/repository
- transparent public access to current published proof surfaces
- offline cryptographic verification independent of hosting runtime

### What current repo + Pages retention does not guarantee by itself

- WORM/object-lock immutability controls
- retention-period enforcement by storage policy (for example, mandated N-year lock)
- legal-hold controls
- independent third-party timestamp anchoring
- long-window auditor-grade durability guarantees on their own

In short: current retention supports technical review and cryptographic verification, but does not by itself claim external immutable archival guarantees.

---

## 4) Evidence that survives now

Today, the following evidence survives in-repo when retained and committed:

- signed document payloads and signatures: certificates (`latest-audit.json`,
  per-run `audit.json`) and ungated baseline records (per-run `baseline.json`).
  Each archive holds one of the two, and the manifest and receipt cover it
  either way, so retention is by archive rather than by document kind
- hash-linked run evidence (`itgl_ledger.jsonl`, `itgl_final_hash.txt`)
- run manifests and archive receipts (`manifest.json`, `archive_receipt.json`)
- pass/fail/inconclusive run-state surfaces (`latest-run.json` + per-run archives)

This is enough for current technical auditors/reviewers to validate run integrity and signature integrity.

It is not, by itself, a claim that evidence cannot ever be removed or rewritten under all governance/legal threat models.

---

## 5) Planned hardening options (future, optional, not current default)

The options below are **not current repo-default guarantees**. They are explicit future hardening paths.

### Tier B (planned option): external immutable retention

- mirror per-run archives to external storage with immutability controls
- typical implementation: S3 + Versioning + Object Lock (Compliance mode)
- define explicit retention windows (for example 7 years)
- optional legal hold and cross-region replication

### Tier C (planned option): independent timestamp anchoring

- anchor selected hashes periodically to a timestamp authority or equivalent append-only mechanism
- goal: prove evidence existed at/after a specific time and detect later rewriting attempts

### Longer-lived archive/export path (planned/partial tooling)

- exported run bundles can be produced and verified offline
- these exports only become stronger durability controls when paired with external immutable storage policy

Planned options must be treated as planned until deployed and operated with enforceable controls.

---

## 6) Reviewer/auditor usability: what can be checked now vs later hardening

### Checkable now (current state)

1. Verify latest published certificate signature and payload hash.
2. Verify specific run archive receipt(s).
3. Verify ITGL integrity chain.
4. Confirm latest-pass vs latest-run semantics are separate.
5. Confirm per-run archive includes both passing and non-passing runs.

### Requires future hardening controls (not guaranteed by repo-only retention)

- enforceable WORM immutability over declared retention windows
- legal hold guarantees
- independent timestamp/notarization guarantees over long windows
- independent archival survivability outside GitHub/platform retention behavior

---

## 7) Minimal verification procedure (offline)

From a clean checkout:

```bash
sir verify cert proofs/latest-audit.json
sir verify archive proofs/runs/<run_id>/
python3 tools/verify_itgl.py
```

Expected successful outputs include valid certificate signature/payload hash and valid archive receipt/ITGL verification.

For published certificate verification from upstream:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py - --no-ledger
```

---

## 8) Current status summary

- Current default (Tier A): repository + Pages transparency with cryptographic verification.
- Planned hardening (Tier B/Tier C): external immutable retention and timestamp anchoring are optional future controls, not current default guarantees.

This statement is intentionally conservative and technically bounded.
