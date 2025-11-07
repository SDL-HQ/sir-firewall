# SIR v1.0.2 — Signal Integrity Resolver

[![GitHub](https://img.shields.io/badge/GitHub-sdl--hq/sir--firewall-blue?logo=github)](https://github.com/sdl-hq/sir-firewall)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE.txt)
[![SIR Tests](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml/badge.svg)](https://github.com/sdl-hq/sir-firewall/actions/workflows/test.yml)

**Pre-inference firewall. Enforces law. Logs proof.**

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
