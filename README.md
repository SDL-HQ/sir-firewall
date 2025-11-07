# SIR v1.0.2 — Signal Integrity Resolver

[![GitHub](https://img.shields.io/badge/GitHub-sdl--hq/sir--firewall-blue?logo=github)](https://github.com/sdl-hq/sir-firewall)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE.txt)
[![SIR Tests](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml/badge.svg)](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml)

**Pre-inference firewall for PTCA/RCA-X.**  
Blocks jailbreaks, enforces signed law, logs every decision.

---

## What It Does

| Check | Enforced |
|-------|----------|
| **Schema** | Valid ISC JSON |
| **Template** | `HIPAA-ISC-v1`, `PCI-DSS-ISC-v1`, `EU-AI-Act-ISC-v1` |
| **Checksum** | `sha256:` over payload |
| **Signature** | RSA ≥ 2048, PKCS1v15-SHA256, **envelope-signed** |
| **Issuer** | `Structural Design Labs (SDL Limited)` |
| **Friction Delta** | ≤ 1000 tokens |
| **Audit** | ITGL entry with key fingerprint |

---

## Install & Run

```bash
pip install -r requirements.txt
