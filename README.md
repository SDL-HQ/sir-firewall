# SIR v1.0.2 — Signal Integrity Resolver

[![GitHub](https://img.shields.io/badge/GitHub-sdl--hq/sir--firewall-blue?logo=github)](https://github.com/sdl-hq/sir-firewall)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE.txt)
[![SIR Tests](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml/badge.svg)](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml)

**Pre-inference firewall. Enforces law. Logs proof.**

---

## What It Does

SIR runs **before** any LLM sees input. It **blocks** unsigned, complex, or unapproved prompts. Only **signed, whitelisted governance signals** pass.

| Check | Rule |
|------|------|
| **Schema** | Valid `isc` JSON |
| **Template** | `HIPAA-ISC-v1`, `PCI-DSS-ISC-v1`, `EU-AI-Act-ISC-v1` |
| **Checksum** | `sha256:` over `payload` |
| **Signature** | RSA ≥ 2048, signs **full envelope** (`version|template_id|checksum|payload|priority_lock`) |
| **Issuer** | `Structural Design Labs (SDL Limited)` |
| **Friction Delta** | `≤ 1000 tokens` (≈ 4 chars/token) — blocks jailbreak spam |
| **Audit** | ITGL log with key fingerprint |

---

## Use

```bash
pip install -r requirements.txt
```

```
from python sir_firewall import validate_sir

result = validate_sir(payload)
print(result["status"])        # PASS / BLOCKED
print(result["itgl_log"])      # Full audit
```
