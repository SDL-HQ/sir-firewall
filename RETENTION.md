# SIR Proof Retention & Audit Durability

SIR produces **cryptographically verifiable audit proofs** (signed certificates + hash-bound run logs) and maintains a **truth-preserving per-run archive**. This document explains how those proofs are retained long-term in a way that is **auditor-friendly**, **repeatable**, and **durable**.

This is intentionally written in plain language for auditors, regulators, and security teams.

---

## 1) What SIR retains

Each audit run can produce:

### A) Signed certificate (authoritative proof)
- `proofs/latest-audit.json` — signed JSON certificate (latest passing pointer)
- `proofs/latest-audit.html` — human view (loads JSON at runtime)

The certificate binds to:
- `payload_hash` (hash of the signed payload)
- `signature` (issuer signature over the payload)
- governance anchors (when present), including:
  - `policy_hash` / `policy_version`
  - `suite_hash`
  - `itgl_final_hash`
  - `safety_fingerprint`

### B) Run evidence (how the run unfolded)
- `proofs/latest-attempts.log` — attempt-by-attempt log
- `proofs/run_summary.json` — suite summary
- `proofs/itgl_ledger.jsonl` + `proofs/itgl_final_hash.txt` — hash-chained ITGL run ledger

### C) Truth-preserving archive (immutable per-run folder)
Each run is archived into:
- `proofs/runs/<run_id>/manifest.json` (inventory + metadata)
- `proofs/runs/<run_id>/audit.json` (the certificate/snapshot used for that run)
- plus copied evidence files (ITGL, attempts, summary, counters, etc.)

There is also:
- `proofs/runs/index.json` — machine index of all archived runs
- `proofs/runs/index.html` — human viewer (loads index.json)

---

## 2) Two trust surfaces (why there are two)

SIR uses two trust surfaces on purpose:

### Trust Surface 1 — Public transparency (GitHub Pages)
GitHub Pages provides a human-readable view:

- Latest passing audit:
  - `/latest-audit.html`
  - `/latest-audit.json`

- Run archive:
  - `/runs/index.html`
  - `/runs/index.json`
  - `/runs/<run_id>/manifest.json`

This surface is excellent for:
- public transparency
- independent engineering review
- quick sharing of proofs

But it is not a regulator-grade retention guarantee by itself (platform policies and hosting constraints can change).

### Trust Surface 2 — Offline verification (auditor-grade logic)
The authoritative proof is the signed JSON certificate, which can be verified offline:

- Verify signature and payload hash:
  - `python tools/verify_certificate.py proofs/latest-audit.json`

Offline verification is:
- provider-independent
- hosting-independent
- durable so long as the signed JSON and the public key are retained

---

## 3) Retention tiers

SIR supports a tiered retention model. You can use Tier A alone for open-source transparency, but auditors typically want Tier B for durability.

### Tier A — Public transparency (default today)
Storage location:
- GitHub repository (`proofs/`)
- GitHub Pages (`docs/`)

What it gives:
- Public audit proof viewing
- Simple reproducibility and verification
- Strong community trust surface

What it does not guarantee:
- WORM immutability controls
- formal retention policy enforcement
- legal hold controls

### Tier B — Auditor-grade immutable retention (recommended)
Mirror all per-run archives to a WORM-capable store with retention controls.

Recommended implementation:
- **Amazon S3 with Object Lock (WORM) + Versioning**
- Lifecycle transition to Glacier / Deep Archive for cost control
- Optional cross-region replication for disaster recovery

What Tier B provides in auditor language:
- immutability enforced by policy (Compliance mode Object Lock)
- defined retention periods (e.g., 7 years)
- optional legal hold
- durable, independent retention beyond GitHub

### Tier C — Independent timestamp anchoring (optional)
Periodically anchor a small set of hashes externally so an auditor can prove:
- the archive existed at/after a specific time
- the archive was not rewritten later

Two audit-friendly options:
- RFC3161 timestamping (traditional and widely understood)
- Signed “weekly ledger snapshot” file (your own append-only file, signed, committed + mirrored)

Tier C is optional. Tier B already satisfies most auditors if configured correctly.

---

## 4) What auditors/regulators typically want (checklist)

Auditors usually care less about “cool crypto” and more about control design.

### A) Immutability controls
- Is there a WORM retention mechanism?
- Can someone rewrite or delete evidence?
- Is retention duration defined and enforced?

Tier A: partial (GitHub history helps, but not WORM)
Tier B: yes (Object Lock Compliance mode)

### B) Provenance and accountability
- Who issued the certificate?
- What public key verifies it?
- Is key rotation documented?

SIR provides:
- issuer signature over certificate payload
- public key stored in repo (`spec/sdl.pub`)
- verification tool (`tools/verify_certificate.py`)

### C) Repeatability
- Can a third party reproduce the audit process?
- Can they re-run the suite locally?

SIR provides:
- deterministic firewall-only audit path (`tools/local_audit.py`)
- suite schema validation (`tools/validate_domain_pack.py`)
- offline verification without model calls

### D) Completeness
- Are failures archived or discarded?
- Is there evidence of negative outcomes?

SIR policy:
- per-run archive is truth-preserving (failures included)
- latest pointer remains “latest passing audit”

### E) Change control
- Are policy versions and suite versions hashed and bound to proof?
- Can drift occur silently?

SIR binds:
- `policy_hash` + `policy_version` (when available)
- `suite_hash`
- `itgl_final_hash`
- `safety_fingerprint`

---

## 5) Recommended retention implementation (Tier B)

### Storage layout
Mirror the archive folder structure directly:

- `s3://<bucket>/sir/proofs/runs/<run_id>/...`
- `s3://<bucket>/sir/proofs/runs/index.json`
- optionally mirror:
  - `proofs/latest-audit.json` (latest passing pointer)
  - `proofs/latest-audit.html`

### Bucket configuration (auditor-friendly defaults)
- Enable **Versioning**
- Enable **Object Lock**
  - **Compliance mode**
  - retention period: define (example: 7 years)
- Enable **lifecycle rules**
  - transition to Glacier / Deep Archive after N days
- Enable access logging / CloudTrail events (if required)

### Operational policy
- Every CI run uploads the run folder + manifest to S3
- CI uploads updated `index.json`
- Deletes are prohibited (Object Lock policy + IAM)

This yields:
- public transparency via GitHub Pages
- durable immutability via S3 Object Lock

---

## 6) Key management and verification durability

### Authoritative signing key
The “real” proofs are the certificates signed by SDL’s CI key.

- Private signing key: held as a CI secret
- Public key: stored in repo (`spec/sdl.pub`)

### Local signing keys
Local mode can generate a test keypair and sign locally.
These proofs are explicitly **non-authoritative** and intended for:
- developer testing
- proof format validation
- offline reproducibility checks

### Key rotation (required for long-lived systems)
When rotating the authoritative signing key:
- keep old public keys in the repo (do not delete)
- record validity date ranges
- ensure the verifier can select the correct key for historical proofs

Recommended future state:
- `spec/pubkeys/` (multiple public keys)
- `spec/keyring.json` (public key registry + metadata)

---

## 7) What “auditability” means for SIR (plain statement)

A proof is considered auditor-verifiable if:
1) the signed JSON certificate is available
2) the verifier confirms:
   - signature valid
   - payload_hash matches
3) the certificate binds to governance anchors:
   - suite hash
   - policy hash/version (if used)
   - ITGL final hash
   - safety fingerprint
4) per-run archive exists and is retained under the declared retention controls

---

## 8) Minimal verification procedure (offline)

From a clean checkout:

```bash
python tools/verify_certificate.py proofs/latest-audit.json
````

Expected:

```text
OK: Certificate signature valid and payload_hash matches.
```

Optional deep inspection:

* open the JSON and review:

  * `policy_hash`
  * `suite_hash`
  * `itgl_final_hash`
  * `safety_fingerprint`
* verify ITGL ledger separately if required:

  * `python tools/verify_itgl.py`

---

## 9) Current status

* Tier A is live (repo + Pages + run archive)
* Tier B is the next planned implementation for auditor-grade retention
* Tier C is optional and may be added if required by stakeholders

---

## Contact

Structural Design Labs
[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com)
[info@structuraldesignlabs.com](mailto:info@structuraldesignlabs.com)
X: @SDL_HQ
