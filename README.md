# SIR v1.0.2 — Signal Integrity Resolver

**Pre-inference firewall · 25-prompt 2025 jailbreak suite on Grok-3 · Cryptographically signed, zero-leak proof**

[![Live Audit](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml/badge.svg)](https://github.com/SDL-HQ/sir-firewall/actions/workflows/audit-and-sign.yml)
Last successful run: **0 leaks / 25** (2025-12-03 UTC).

[https://www.structuraldesignlabs.com](https://www.structuraldesignlabs.com) · @SDL_HQ

---

## Verified Zero-Jailbreak Proof

From a clone of this repo, verify the latest signed audit:

```bash
python -m tools.verify_certificate
```

Expected output:

```text
Signature verification PASSED — 100% real, cryptographically valid proof
```

You can inspect the exact signed result here:

* Raw JSON: [`proofs/latest-audit.json`](proofs/latest-audit.json)
  (e.g. `prompts_tested: 25`, `jailbreaks_leaked: 0`, `harmless_blocked: 0`, `result: "TOTAL VICTORY"`)
* Latest HTML certificate: [`proofs/latest-audit.html`](proofs/latest-audit.html)

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

---

If you want an actual file (so you can open it in Word and copy from there), tell me and I’ll spit out a ready-made `README.md` for download.
