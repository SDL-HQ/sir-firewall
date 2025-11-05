# SIR v0.1 — Signal Integrity Resolver (SIR)
### Pre-Governance Firewall for Inference-Time Law (PTCA/RCA-X)

The **Signal Integrity Resolver (SIR)** is a lightweight, parameter-free validator designed to run *before* any Large Language Model (LLM) inference. Its purpose is to enforce **Inference-Time Law (ITGL)** by blocking complex, unauthorized inputs (like prompt injection) while only permitting trusted, cryptographically-attested governance signals (ISC payloads).

**Goal:** Make breaking alignment **100× harder** than maintaining it.

---

## Key Features (Asymmetric Defense)

* **Friction Delta:** Automatically blocks any input payload over 1000 tokens as suspicious complexity (Prompt Injection defense).
* **Cryptographic Attestation:** Requires a verifiable digital signature (SHA256) and a valid issuer provenance.
* **Template Whitelist:** Ensures only pre-approved regulatory templates (e.g., HIPAA-ISC-v1) can activate PTCA/RCA-X.
* **ITGL Logging:** All pass/fail events are logged as a verifiable audit trail (Inference-Time Governance Ledger).

## Quick Start (Requires `cryptography` and `json` libs)

```python
from sir_firewall import validate_sir # Assuming the function is imported correctly
import json 

# EXAMPLE 1: PASS (Attested, low friction)
# In a real scenario, this JSON would be cryptographically signed
ISC_PAYLOAD = {
    # Full signed JSON payload here... 
}
# print(validate_sir(ISC_PAYLOAD)) 
# >> {'status': 'PASS', 'reason': 'Governance signal verified.', ... } 

# EXAMPLE 2: BLOCKED (Default user input)
# Note: Traditional user text is not a valid ISC JSON object, so it fails Schema/Signature
print(validate_sir("AI instantly self-aligns to governance!"))  # BLOCKED (Fails Schema Check) 
# >> {'status': 'BLOCKED', 'reason': 'Input format error...', ... }
