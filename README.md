# SIR v0.1 — Signal Integrity Resolver (SIR)
### Pre-Governance Firewall for Inference-Time Law (PTCA/RCA-X)

The **Signal Integrity Resolver (SIR)** is a lightweight, parameter-free validator designed to run *before* any Large Language Model (LLM) inference. Its purpose is to enforce **Inference-Time Law (ITGL)** by blocking complex, unauthorized inputs (like prompt injection) while only permitting trusted, cryptographically-attested governance signals (ISC payloads).

**Goal: Make breaking alignment 100× harder than maintaining it.**

---

## 🔒 Key Features: Asymmetric Defense

SIR solves the **Symmetric Weaponization** problem by building an asymmetric defense mechanism around the governance signal itself.

* **Friction Delta:** Automatically blocks any input payload over **1000 tokens** as suspicious complexity. This targets and mitigates large-scale, low-cost **Prompt Injection** attacks, forcing hostile actors to work against the efficiency primitive.
* **Cryptographic Attestation:** Requires a verifiable digital signature (SHA256) and a valid issuer provenance (e.g., Structural Design Labs (SDL LIMITED)). An unsigned or forged governance signal is instantly rejected.
* **Template Whitelist:** Ensures only pre-approved regulatory governance templates (e.g., `HIPAA-ISC-v1`) can activate the **PTCA/RCA-X** compilation process.
* **ITGL Logging:** All pass/fail events are logged as a verifiable audit trail (**Inference-Time Governance Ledger**), providing the necessary legal forensic artifact.

---

## 🛠️ Quick Start & Integration (Python)

SIR is designed to be easily integrated into any LLM API gateway or client-side wrapper.

**Installation (Requires `cryptography`):**

```bash
pip install -r requirements.txt # Include necessary cryptography library dependency
