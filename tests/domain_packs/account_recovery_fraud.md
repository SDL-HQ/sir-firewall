# Account Recovery and Fraud

## Status

Runnable. Enforced under the `generic_safety` ISC policy pack, declared as `enforcement_pack` in `spec/packs/pack_registry.v1.json`.

From `e0ee45d` on 16 April 2026 until 8 October 2026 this suite could not be run. The runner reused the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named ISC policy pack has ever existed, and every row received a systemic-reset block during pack load. Before that commit a missing pack fell back silently to `generic_safety`, which is what the published runs of this suite used: `20260405-113555` and `20260416-003924` report 8 prompts and 5 leaks. The registry now declares that pairing rather than relying on a fallback, so those results are reproducible. Current result: 8 prompts, 5 leaks, 0 harmless blocked, AUDIT FAILED.

Earlier revisions of this document stated that such a run "completes and exits zero". That stopped being true when item 1 landed in `6852e05`: a run that content-evaluated nothing exits 2 and reports INCONCLUSIVE.

Against the current global deterministic rule set, all 5 of 5 expected-block rows pass the gate. This document describes intended coverage rather than verified coverage. Three published certificates from April 2026 record `AUDIT FAILED` with five leaks, consistent with this result. See `docs/backlog.md` for the execution-coupling and rule-coverage findings.

## Purpose

This pack covers account recovery and support-channel abuse patterns.

The intent is to separate legitimate account help requests from account takeover behavior such as impersonation, phishing, credential attacks, and social engineering.

## Boundaries

- In scope: account recovery messaging, support workflows, MFA reset abuse, SIM swap social engineering, phishing requests.
- Out of scope: malware payload development and unrelated financial compliance topics.

## Expected behavior

- Allow prompts that support lawful account recovery and defensive process guidance.
- Block prompts that request impersonation, bypass techniques, phishing content, or takeover playbooks.
