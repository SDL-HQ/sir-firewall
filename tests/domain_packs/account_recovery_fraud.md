# Account Recovery and Fraud

## Status

Selecting `account_recovery_fraud` through the `--pack` route does not evaluate the suite content: the runner reuses the benchmark pack identifier as an explicit ISC policy pack identifier, no same-named ISC policy pack exists, and every row receives a systemic-reset block during policy load. The run completes and exits zero.

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
