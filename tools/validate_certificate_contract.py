#!/usr/bin/env python3
"""Validate SIR certificate JSON against evidence contract v1 (offline, deterministic)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_CERT = Path("proofs/latest-audit.json")
DEFAULT_CONTRACT = Path("spec/evidence_contract.v1.json")
DEFAULT_KEY_SCHEMA = Path("spec/pubkeys/key_registry.v1.schema.json")
DEFAULT_KEY_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")


TS_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate SIR certificate against evidence contract v1.")
    ap.add_argument("cert", nargs="?", default=str(DEFAULT_CERT), help="Path to certificate JSON.")
    ap.add_argument("--contract", default=str(DEFAULT_CONTRACT), help="Path to evidence contract JSON.")
    ap.add_argument(
        "--key-schema",
        default=str(DEFAULT_KEY_SCHEMA),
        help="Optional key registry schema path used for verifier-expectation enforcement.",
    )
    ap.add_argument(
        "--key-registry",
        default=str(DEFAULT_KEY_REGISTRY),
        help="Optional key registry JSON path (for signing_key_id revocation checks when present).",
    )
    return ap.parse_args()


def _load_json(path: Path, label: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # parse/read errors are input failures
        raise RuntimeError(f"failed to read/parse {label}: {path} ({e})") from e

    if not isinstance(obj, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return obj


def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or TS_Z_RE.match(ts) is None:
        raise ValueError("timestamp must be UTC ISO-8601 with Z suffix")
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _validate_required(cert: Dict[str, Any], contract: Dict[str, Any], errors: List[str]) -> None:
    required = contract.get("required", [])
    if not isinstance(required, list):
        errors.append("contract.required must be a list")
        return
    for key in required:
        if key not in cert:
            errors.append(f"missing required field: {key}")


def _validate_properties(cert: Dict[str, Any], contract: Dict[str, Any], errors: List[str]) -> None:
    props = contract.get("properties", {})
    if not isinstance(props, dict):
        errors.append("contract.properties must be an object")
        return

    for field, schema in props.items():
        if field not in cert or not isinstance(schema, dict):
            continue
        val = cert[field]

        expected_type = schema.get("type")
        if expected_type == "string" and not isinstance(val, str):
            errors.append(f"field {field} must be string")
            continue
        if expected_type == "integer" and not isinstance(val, int):
            errors.append(f"field {field} must be integer")
            continue
        if expected_type == "boolean" and not isinstance(val, bool):
            errors.append(f"field {field} must be boolean")
            continue
        if expected_type == "object" and not isinstance(val, dict):
            errors.append(f"field {field} must be object")
            continue

        enum = schema.get("enum")
        if isinstance(enum, list) and val not in enum:
            errors.append(f"field {field} must be one of {enum!r}, got {val!r}")

        minimum = schema.get("minimum")
        if isinstance(minimum, int) and isinstance(val, int) and val < minimum:
            errors.append(f"field {field} must be >= {minimum}")

        min_length = schema.get("minLength")
        if isinstance(min_length, int) and isinstance(val, str) and len(val) < min_length:
            errors.append(f"field {field} must have minLength {min_length}")

        pattern = schema.get("pattern")
        if isinstance(pattern, str) and isinstance(val, str) and re.match(pattern, val) is None:
            errors.append(f"field {field} fails pattern {pattern!r}")

    # Nested flags checks (required booleans)
    flags = cert.get("flags")
    if isinstance(flags, dict):
        for key in ("CRYPTO_ENFORCED", "CHECKSUM_ENFORCED"):
            if key not in flags:
                errors.append(f"flags missing required key: {key}")
            elif not isinstance(flags[key], bool):
                errors.append(f"flags.{key} must be boolean")


def _validate_contract_rules(cert: Dict[str, Any], contract: Dict[str, Any], errors: List[str]) -> None:
    rules = contract.get("x_contract_rules")
    if not isinstance(rules, dict):
        errors.append("contract missing x_contract_rules object")
        return

    alias = rules.get("legacy_aliases", {})
    if isinstance(alias, dict):
        canonical = alias.get("canonical", "trust_fingerprint")
        legacy = alias.get("legacy", "safety_fingerprint")

        c_val = cert.get(canonical)
        l_val = cert.get(legacy)

        if c_val is None and l_val is None:
            errors.append(f"either {canonical} (preferred) or {legacy} must be present")
        if c_val is not None and not isinstance(c_val, str):
            errors.append(f"{canonical} must be string")
        if l_val is not None and not isinstance(l_val, str):
            errors.append(f"{legacy} must be string")
        if c_val is not None and l_val is not None and c_val != l_val:
            errors.append(f"{canonical} and {legacy} differ (fail closed)")

    proof_class = cert.get("proof_class")
    conditionals = rules.get("proof_class_conditionals", {})
    if isinstance(conditionals, dict) and isinstance(proof_class, str):
        expected = conditionals.get(proof_class)
        if isinstance(expected, dict):
            for key, exp_val in expected.items():
                got = cert.get(key)
                if got != exp_val:
                    errors.append(f"proof_class={proof_class} requires {key}={exp_val}, got {got!r}")

    if cert.get("model_calls_made") != cert.get("provider_call_attempts"):
        errors.append("model_calls_made must equal provider_call_attempts")

    if isinstance(cert.get("provider_call_attempts"), int) and isinstance(cert.get("provider_call_successes"), int):
        if cert["provider_call_successes"] > cert["provider_call_attempts"]:
            errors.append("provider_call_successes cannot exceed provider_call_attempts")


def _enforce_key_expectations_if_relevant(
    cert: Dict[str, Any], key_schema: Dict[str, Any], key_registry_path: Path, errors: List[str]
) -> None:
    # Enforce only when certificate declares a signing key id.
    signing_key_id = cert.get("signing_key_id")
    if signing_key_id is None:
        return
    if not isinstance(signing_key_id, str) or not signing_key_id:
        errors.append("signing_key_id must be non-empty string when present")
        return

    x_exp = key_schema.get("properties", {}).get("x_verifier_expectations")
    if x_exp is None:
        errors.append("key schema missing x_verifier_expectations")

    if "timestamp_utc" not in cert:
        errors.append("timestamp_utc missing in proof (fail closed for revocation checks)")
        return

    try:
        cert_ts = _parse_utc(str(cert["timestamp_utc"]))
    except Exception:
        errors.append("timestamp_utc must be UTC ISO-8601 with Z suffix")
        return

    if not key_registry_path.exists():
        errors.append(f"key registry file required for signing_key_id checks but not found: {key_registry_path}")
        return

    try:
        reg = _load_json(key_registry_path, "key registry")
    except RuntimeError as e:
        errors.append(str(e))
        return

    keys = reg.get("keys")
    if not isinstance(keys, list):
        errors.append("key registry keys must be a list")
        return

    selected = None
    for entry in keys:
        if isinstance(entry, dict) and entry.get("key_id") == signing_key_id:
            selected = entry
            break
    if selected is None:
        errors.append(f"signing_key_id not found in key registry: {signing_key_id}")
        return

    status = selected.get("status")
    revoked_utc = selected.get("revoked_utc")
    if status == "revoked":
        if not isinstance(revoked_utc, str):
            errors.append(f"revoked key missing revoked_utc for key_id={signing_key_id}")
            return
        try:
            revoked_ts = _parse_utc(revoked_utc)
        except Exception:
            errors.append(f"revoked_utc invalid for key_id={signing_key_id}")
            return

        if cert_ts >= revoked_ts:
            errors.append(
                f"proof timestamp_utc {cert['timestamp_utc']} is at/after revoked_utc {revoked_utc} for key_id={signing_key_id}"
            )


def main() -> int:
    args = _parse_args()

    try:
        cert = _load_json(Path(args.cert), "certificate")
        contract = _load_json(Path(args.contract), "evidence contract")
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    errors: List[str] = []
    _validate_required(cert, contract, errors)
    _validate_properties(cert, contract, errors)
    _validate_contract_rules(cert, contract, errors)

    # Optional key-governance expectation checks when cert carries signing_key_id.
    if cert.get("signing_key_id") is not None:
        try:
            key_schema = _load_json(Path(args.key_schema), "key schema")
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 3
        _enforce_key_expectations_if_relevant(cert, key_schema, Path(args.key_registry), errors)

    if errors:
        print("ERROR: certificate contract validation failed:", file=sys.stderr)
        for e in errors:
            print(f" - {e}", file=sys.stderr)
        return 2

    print("OK: certificate satisfies evidence contract v1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
