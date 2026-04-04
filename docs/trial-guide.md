# SIR Trial Guide

This guide is for auditors, insurers, regulators, and cautious organisations that want a role-specific way to evaluate SIR evidence without changing production systems.

For the canonical run and verification workflow, use `docs/assurance-kit.md`.

## What to review first

Public proof surfaces:

- Human certificate page (latest PASS): https://sdl-hq.github.io/sir-firewall/latest-audit.html
- Latest run status (PASS / FAIL / INCONCLUSIVE): https://sdl-hq.github.io/sir-firewall/latest-run.json
- Run archives (passes + failures): https://sdl-hq.github.io/sir-firewall/runs/index.html
- Raw signed JSON certificate: https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/proofs/latest-audit.json

Semantics:

- `latest-audit.*` is latest passing proof (last known good)
- `latest-run.json` is most recent run result, including fail or inconclusive outcomes

## Trial workflow

1. Follow the canonical path in `docs/assurance-kit.md`.
2. Record verification outputs and artefact hashes in your internal review file.
3. Keep pass/fail truth explicit by capturing both latest pass and latest run surfaces.

## What to record for assurance evidence

For governance or underwriting records, capture:

- signed certificate JSON used for verification
- verification output lines (certificate and archive when applicable)
- run identifier and run timestamp
- links or paths to latest pass, latest run, and run archive surfaces
- benchmark index excerpt showing `latest_run` and `latest_passing_run`

## Questions this guide helps answer

- Was the reviewed proof signature-valid?
- Is there a clear chain from run artefacts to certificate and archive receipt?
- Are latest pass and latest run interpreted honestly?
- Is benchmark data being treated as evidence mapping rather than scoring?

## Scope boundaries

This guide does not redefine proof semantics or verification commands.

Use `docs/assurance-kit.md` as the canonical source for those details.
