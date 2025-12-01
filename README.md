# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · 100/100 worst 2025 jailbreaks blocked live on Grok-3 · Cryptographically signed proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit.yml)
[![Tests](https://github.com/SDL-HQ/sir-firewall/actions/workflows/test.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

https://www.structuraldesignlabs.com · @SDL_HQ

---

## Verified Zero-Jailbreak Proof

Run this one-liner anywhere to verify the audit yourself:

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/audit-certificate.json | python -m tools.verify_certificate
```

Expected output:

```text
SIR AUDIT CERTIFICATE VERIFIED
0 leaks on Grok-3 • 2025-12-01 • https://github.com/SDL-HQ/sir-firewall/actions/runs/...
```

Full CI run and signed certificate: [`proofs/audit-certificate.json`](proofs/audit-certificate.json)

---

## Install & Use

### Clone and install

```bash
git clone https://github.com/SDL-HQ/sir-firewall
cd sir-firewall
pip install -r requirements.txt
```

### Python usage

```python
from sir_firewall import validate_sir

result = validate_sir(your_payload)
print(result["status"])  # PASS or BLOCKED
# print(result["itgl_log"])  # optional: full audit log
```

---

## License

MIT Licensed — free for everyone, forever.  
© 2025 Structural Design Labs

