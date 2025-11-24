# SIR v1.0.2 — Signal Integrity Resolver 

[![GitHub](https://img.shields.io/badge/GitHub-sdl--hq/sir--firewall-blue?logo=github)](https://github.com/sdl-hq/sir-firewall)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE.txt)
[![SIR Tests](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml/badge.svg)](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml)
[![Smoke Import](https://github.com/sdl-hq/sir-firewall/actions/workflows/smoke-import.yml/badge.svg)](https://github.com/sdl-hq/sir-firewall/actions/workflows/smoke-import.yml)

[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com)

[Grok Approves:--> https://x.com/grok/status/1992104024498450471](https://x.com/grok/status/1992104024498450471)

**Pre-inference firewall. Enforces law. Logs proof.**

---

## What It Does

SIR runs **before** any LLM sees input. It **blocks** unsigned, complex, or unapproved prompts. Only **signed, allow-listed governance signals** pass.

| Check | Rule |
|------|------|
| **Schema** | Valid `isc` JSON envelope (see below) |
| **Template** | `HIPAA-ISC-v1`, `PCI-DSS-ISC-v1`, `EU-AI-Act-ISC-v1` |
| **Checksum** | `sha256:` over the **payload string** |
| **Signature** | RSA ≥ 2048, signs **full envelope** (`version|template_id|checksum|payload|priority_lock`) |
| **Issuer** | `Structural Design Labs (SDL Limited)` (in `provenance.issuer`) |
| **Friction Delta** | `≤ 1000 tokens` (≈ 4 chars/token) — blocks jailbreak spam |
| **Audit** | ITGL-style pass/fail log with key fingerprint |

> **Token note:** Token counts are tokenizer-specific; the ~4 chars/token heuristic is a default.

---

## Quickstart (run from repo root)

```bash
git clone https://github.com/sdl-hq/sir-firewall
cd sir-firewall
pip install -r requirements.txt
pytest -q
```

### Use in Python
```python
from sir_firewall import validate_sir

# payload: top-level dict with an "isc" envelope (see example below)
result = validate_sir(payload)
print(result["status"])   # PASS / BLOCKED
print(result["itgl_log"]) # Full audit (hash-chained)
```
