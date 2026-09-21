# Deliberately invalid verifier examples

**Every JSON file in this directory is deliberately invalid. None is real evidence, and none may be treated as an audit result.** These fixtures demonstrate that certificate verification refuses representative tampering modes and preserve the exact diagnostic contract in tests.

Run both certificate tools when relying on a certificate:

- `tools/validate_certificate_contract.py` establishes certificate shape, required fields, and contract rules. It does **not** establish payload integrity or signature authenticity. A falsified leak count can remain structurally contract-valid.
- `tools/verify_certificate.py` establishes that the payload hash matches the reconstructed payload and that the signature authenticates it with trusted key material. It does **not** replace contract validation.

Cases 1–4 pass the contract validator. Case 5 demonstrates the validator's required-field check. All five fail the verifier.

## Case 1: falsified leak count

`tampered-leak-count.json` changes `jailbreaks_leaked` from 26 to 0 without changing the signed hash or signature.

Verifier exit code: `3`

```text
ERROR: payload_hash mismatch
  cert: sha256:f6496562750bd5b12c20c56abdb1f762b9b34ac685d8169ded9671129be51b62
  calc: sha256:315631c293a45f6a9316d2438d549da7e2b35da46ff1fdad45e31ba9b06b888e
```

Contract-validator exit code: `0`

```text
OK: certificate satisfies evidence contract v1.
```

This contrast is intentional: the falsified count has a valid shape but is not authentic.

## Case 2: falsified leak count with a recomputed hash

`tampered-leak-count-rehashed.json` makes the same change and recomputes `payload_hash`, leaving the original signature.

Verifier exit code: `5`

```text
ERROR: signature verification failed (InvalidSignature)
```

Contract-validator exit code: `0`

```text
OK: certificate satisfies evidence contract v1.
```

## Case 3: signature copied from another certificate

`tampered-signature-swap.json` replaces the signature with a valid signature taken from a different archived certificate.

Verifier exit code: `5`

```text
ERROR: signature verification failed (InvalidSignature)
```

Contract-validator exit code: `0`

```text
OK: certificate satisfies evidence contract v1.
```

Cases 2 and 3 produce identical verifier output **by construction**. In both cases the presented payload hash is self-consistent, but the presented signature does not authenticate that payload. At the cryptographic verification boundary, an altered payload paired with its old signature and an unchanged payload paired with another certificate's signature both reduce to `InvalidSignature`. This is a documented diagnostic limit, not an open defect: rejection is authoritative, but the verifier cannot infer which history produced the non-authenticating signature.

## Case 4: unregistered signing key

`tampered-unregistered-key.json` was re-hashed and re-signed using a temporary key whose `signing_key_id` is not present in the repository key registry.

Verifier exit code: `1`

```text
ERROR: signing_key_id not found in key registry: phase1-unregistered-temp-key
```

Contract-validator exit code: `0`

```text
OK: certificate satisfies evidence contract v1.
```

## Case 5: required field removed

`tampered-required-field-removed.json` removes the required `prompts_tested` field without changing the signed hash or signature.

Verifier exit code: `3`

```text
ERROR: payload_hash mismatch
  cert: sha256:f6496562750bd5b12c20c56abdb1f762b9b34ac685d8169ded9671129be51b62
  calc: sha256:56ee344dd20d482a2bff0440ea05bad51b01181e5f8fcbcfd1ef3d8aa416e62f
```

Contract-validator exit code: `2`

```text
ERROR: certificate contract validation failed:
 - missing required field: prompts_tested
```
