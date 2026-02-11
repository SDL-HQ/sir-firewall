# SIR Trial Guide

This guide is for auditors, insurers, regulators, and cautious organisations that want to verify evidence without changing production systems.

## What you can verify today

Public proof surfaces:
- Human certificate page (latest PASS): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Latest run status (PASS / FAIL / INCONCLUSIVE): https://sdl-hq.github.io/sir-firewall/latest-run.json
- Run archives (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html
- Raw signed JSON certificate: https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json

Published proof is signed by SDL. Local runs can be signed with local dev keys for testing, but they are not SDL-signed certificates.

## Minimal offline verification

This verifies the latest published certificate locally.

### Step 1. Get the verifier (one time)

```bash
git clone https://github.com/SDL-HQ/sir-firewall.git
cd sir-firewall
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .
````

### Step 2. Verify the published certificate

```bash
curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json | python3 tools/verify_certificate.py -
```

Expected output:

```text
OK: Certificate signature valid and payload_hash matches.
```

If you see an error about `cryptography` not being installed:

```bash
python3 -m pip install cryptography
```

## What the certificate binds to

When reviewing the certificate JSON, these are the fields that matter:

* Suite hash
  The SHA-256 fingerprint of the test suite used for the run.

* Policy hash or policy version
  The policy configuration and version that was enforced.

* ITGL final hash
  The final hash of the governance ledger for the run. This proves the run log chain matches the result.

* Fingerprint
  A stable identifier for the run configuration and outcome binding.

## What to record for evidence

For an internal governance record or underwriting file, capture:

* The raw signed certificate JSON (`latest-audit.json`)
* The verification output line (`OK: ...`)
* The human certificate URL, latest-run URL, and run archive URL
* The date and run identifier shown in the certificate

## Optional local trial (no production impact)

If you want to run a local audit on your own machine (without touching production traffic), follow the Engineer Guide:

* `docs/engineer-guide.md`

This is typically used for:

* internal evaluation
* regression testing across policy versions
* comparing different domain packs or suite variants
