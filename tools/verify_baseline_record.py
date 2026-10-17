#!/usr/bin/env python3
"""Verify a signed SIR ungated baseline record offline.

The record says a named prompt set was forwarded to a named provider with the
gate out of the path, and what came back at the transport level. This tool
establishes that the document is that kind of document, that it was signed by a
key the registry still honours for it, and that what it claims is what its
ledger's rows support.

Checks, in this order, and the order is the point:

  1. type. record_kind before anything else, so a document of another kind is
     never reported on by this tool. tools/verify_certificate.py refuses this
     record for the same reason from the other side.
  2. structure, against the rules shipped in this file, which
     tests/test_baseline_record.py holds equal to
     spec/baseline_record.v1.schema.json. Forbidden fields are refused
     explicitly rather than ignored.
  3. signature, key resolution through the registry, and revocation.
  4. the bound ledger: chain, minimum chain version 2, terminal hash and row
     count as signed.
  5. classification: every row is a baseline row, by tools/itgl.py.
  6. counters, recomputed from the rows, and the provider-call partition.

There is no freshness or age check here, and there is none for certificates
either. An earlier draft of the 2.5 specification said there was; that was
wrong, and nothing in this tool pretends otherwise.

What a verified record does not establish, stated because a reader will
otherwise supply it: that no gate ran. The rows authenticate what the producer
encoded. A producer who wanted to could write baseline-shaped rows for a run it
gated, and nothing here would know. What this rules out is a baseline record
being read as an audit, and an audit's ledger being read as a baseline's.

Exit codes:
  0  verified
  2  not a baseline record, or structurally invalid
  3  payload_hash does not match the signed payload
  4  the signature is not valid base64
  5  signature verification failed
  6  the signature check could not be performed, so the signature is neither
     established nor refuted
  7  the bound ledger does not support the record
  10 the signing key is revoked for this record
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parent))

from document_signing import payload_hash as compute_payload_hash  # noqa: E402
from document_signing import signing_payload  # noqa: E402
from itgl import (  # noqa: E402
    CHAIN_VERSION_V2,
    SUPPORTED_BASELINE_ROW_VERSIONS,
    LedgerVerificationError,
    baseline_ledger_defects,
    derive_counters,
    load_and_verify_ledger,
    load_ledger,
)
from key_registry import (  # noqa: E402
    find_registry_key,
    public_key_pem_from_entry,
    revocation_allows_proof,
)

NOT_A_BASELINE_RECORD = 2
PAYLOAD_HASH_MISMATCH = 3
SIGNATURE_NOT_BASE64 = 4
SIGNATURE_FAILED = 5
#: The check itself broke. Mirrors verify_certificate.py's 6, which already
#: draws this line, rather than inventing a second vocabulary for the same
#: fact. This file already printed a different message for the two cases
#: and then returned SIGNATURE_FAILED from both, so a person reading stderr
#: could tell them apart and nothing else could.
SIGNATURE_CHECK_RAISED = 6
LEDGER_BINDING_FAILURE = 7
REVOCATION_FAILURE = 10

RECORD_KIND = "sir_ungated_baseline"
# The record version that goes with each baseline row format. The two move
# together: a row format permitting a new provider outcome gives the document a
# counter and the fields needed to read it.
RECORD_VERSION_BY_ROW_VERSION = {1: 1, 2: 2}

# What this release writes. Readers below take the version from the record's own
# declared row format instead.
RECORD_VERSION = RECORD_VERSION_BY_ROW_VERSION[2]

DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")
DEFAULT_KEY_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")

# The shipped copy of spec/baseline_record.v1.schema.json's required set, so a
# minimal verification bundle needs no spec file to apply it.
# tests/test_baseline_record.py fails if the two disagree, rather than this copy
# drifting, which is the pattern CONTRACT_V4_ADDED_FIELDS already uses.
REQUIRED_FIELDS = (
    "record_kind",
    "record_version",
    "run_id",
    "timestamp_utc",
    "sir_firewall_version",
    "commit_sha",
    "repository",
    "ci_run_url",
    "mode",
    "provider",
    "model",
    "pack_id",
    "pack_version",
    "suite_path",
    "prompt_set_hash",
    "prompt_set_hash_kind",
    "ledger",
    "counters",
    "signing_key_id",
    "payload_hash",
    "signature",
)

# What each row format adds to the required set above. v2 records carry the
# rule that decided their declined count and the output ceiling their calls
# were made under; a v1 record must not carry either, because it has no
# declined count for them to qualify.
REQUIRED_FIELDS_ADDED_BY_ROW_VERSION = {
    1: (),
    2: ("refusal_detection", "provider_output_limit"),
}


def required_fields_for_row_version(row_version):
    """The top-level fields a record of this format must carry, or () if unknown."""
    if isinstance(row_version, bool) or not isinstance(row_version, int):
        return ()
    added = REQUIRED_FIELDS_ADDED_BY_ROW_VERSION.get(row_version)
    if added is None:
        return ()
    return REQUIRED_FIELDS + added


OPTIONAL_FIELDS = ("scenario_id",)

# Fields a certificate carries that this document must not. Each is a statement
# about enforcement, and a baseline enforces nothing. Refused by name, so the
# reason a record was rejected is the claim it tried to make.
FORBIDDEN_FIELDS = (
    "result",
    "proof_class",
    "policy_hash",
    "policy_version",
    "enforced_policy_matches_signed_policy",
    "configuration_hash",
    "configurations_observed",
    "trust_fingerprint",
    "safety_fingerprint",
    "benchmark_execution",
    "jailbreaks_leaked",
    "harmless_blocked",
    "content_evaluated",
    "content_allow_prompts",
    "content_block_prompts",
    "content_false_positive_rate",
    "systemic_reset_count",
    "legitimate_requests_denied_by_system_failure",
    "prompts_tested",
    "model_calls_made",
    "audit",
)

LEDGER_FIELDS = ("path", "chain_version", "row_version", "row_count", "itgl_final_hash")

# The counters a record carries, per baseline row format version.
#
# Version-conditional because the set grew. A version 1 record must not carry
# `provider_call_declined`: when it was written the value did not exist and
# `failure` was the only thing a declining provider could produce, so a v1
# record carrying the field would be asserting a measurement its own format had
# no way to take. And a version 2 record must carry it, or its provider
# outcomes do not partition its attempts.
#
# Judged by the version in the `ledger` block, which is covered by the chain and
# chained to the terminal hash the record signs, and which this tool has already
# checked against the versions its rows carry. Not by `record_version`, which
# the document asserts about itself: that is the artefact choosing the rule that
# judges it, which is the defect
# tests/test_contract_floor_is_not_self_asserted.py exists for one level down.
COUNTER_FIELDS_BY_ROW_VERSION = {
    1: (
        "prompts_forwarded",
        "expected_block_prompts_forwarded",
        "expected_allow_prompts_forwarded",
        "provider_call_attempts",
        "provider_call_successes",
        "provider_call_failures",
    ),
    2: (
        "prompts_forwarded",
        "expected_block_prompts_forwarded",
        "expected_allow_prompts_forwarded",
        "provider_call_attempts",
        "provider_call_successes",
        "provider_call_failures",
        "provider_call_declined",
    ),
}

# What this release writes. Readers below take the set from the record's own
# declared row version instead, so this is for the writer's sake only.
COUNTER_FIELDS = COUNTER_FIELDS_BY_ROW_VERSION[2]


def counter_fields_for_row_version(row_version):
    """The counters a record of this format must carry, or () if unknown.

    Empty rather than the current set, so a format this release does not read
    cannot have its counters judged by rules written for another one. The
    version check reports that separately.
    """
    if isinstance(row_version, bool) or not isinstance(row_version, int):
        return ()
    return COUNTER_FIELDS_BY_ROW_VERSION.get(row_version, ())

PROMPT_SET_HASH_KINDS = ("suite_hash", "scenario_hash")

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

# The per-field rules the published schema states, written out so this tool
# stays readable on its own: a reviewer handed this file alone can see what it
# enforces without fetching spec/baseline_record.v1.schema.json.
#
# Until 15 October 2026 the only field rules here were the three constants
# below (record_version, mode, prompt_set_hash_kind), so a record with an
# empty run_id, an object for provider, an empty model and "not-a-hash" for
# prompt_set_hash produced no structural defect and verified. The docstring
# claimed the shipped rules were held equal to the schema; the test held the
# required and forbidden sets equal and nothing held the field rules at all.
# An independent review found it by handing the verifier a record the schema
# rejects on five fields.
#
# record_version is the sharp one. The check was `!= RECORD_VERSION`, and in
# Python True == 1, so record_version: true passed a check for 1.
#
# (type, minimum length for a string, compiled pattern, exact value)
FIELD_RULES: Dict[str, tuple] = {
    "record_kind": (str, 1, None, RECORD_KIND),
    # The exact value is filled in per record from its declared row format,
    # because the two move together. None here means "an integer, checked
    # against the row format below" rather than "any integer".
    "record_version": (int, None, None, None),
    "run_id": (str, 1, None, None),
    "timestamp_utc": (str, 1, None, None),
    "sir_firewall_version": (str, 1, None, None),
    "commit_sha": (str, 0, None, None),
    "ci_run_url": (str, 0, None, None),
    "mode": (str, 1, None, "live"),
    "provider": (str, 1, None, None),
    "model": (str, 1, None, None),
    "pack_id": (str, 1, None, None),
    "pack_version": (str, 0, None, None),
    "suite_path": (str, 1, None, None),
    "prompt_set_hash": (str, None, SHA256, None),
    "signing_key_id": (str, 1, None, None),
    "payload_hash": (str, None, SHA256, None),
    "signature": (str, 1, None, None),
    "scenario_id": (str, 1, None, None),
}

LEDGER_FIELD_RULES: Dict[str, tuple] = {
    "path": (str, 1, None, None),
    "chain_version": (int, None, None, CHAIN_VERSION_V2),
    "row_version": (int, None, None, None),
    "row_count": (int, None, None, None),
    "itgl_final_hash": (str, None, SHA256, None),
}

# Baseline row version 2 fields. Shape only: what the rule says and which
# library version decided it are facts about the run, not values this tool can
# check against anything.
REFUSAL_DETECTION_RULES: Dict[str, tuple] = {
    "rule": (str, 1, None, None),
    "litellm_version": (str, None, None, None),
}

PROVIDER_OUTPUT_LIMIT_RULES: Dict[str, tuple] = {
    "kind": (str, 1, None, None),
    "value": (int, None, None, None),
}


def _field_defects(scope: str, values: Dict[str, Any], rules: Dict[str, tuple]) -> List[str]:
    """Every field rule the schema states, applied to what is present."""
    defects: List[str] = []
    for field, (expected_type, min_length, pattern, exact) in rules.items():
        if field not in values:
            continue
        value = values[field]
        label = f"{scope}{field}"
        # bool is a subclass of int, and True == 1, so an exact check alone
        # accepts true where 1 is required.
        if expected_type is int and isinstance(value, bool):
            defects.append(f"{label} is {value!r}, not an integer")
            continue
        if not isinstance(value, expected_type):
            defects.append(
                f"{label} is {value!r}, not {'an integer' if expected_type is int else 'a string'}"
            )
            continue
        if exact is not None and value != exact:
            defects.append(f"{label} is {value!r}, not {exact!r}")
            continue
        if min_length is not None and len(value) < min_length:
            defects.append(f"{label} is empty")
        if pattern is not None and not pattern.match(value):
            defects.append(f"{label} is {value!r}, which is not a sha256 digest")
        if expected_type is int and exact is None and value < 0:
            defects.append(f"{label} is {value!r}, not a non-negative integer")
    return defects


def _structural_defects(record: Dict[str, Any]) -> List[str]:
    defects: List[str] = []

    forbidden = [field for field in FORBIDDEN_FIELDS if field in record]
    if forbidden:
        defects.append(
            "carries fields a baseline cannot claim: "
            + ", ".join(forbidden)
            + ". A baseline runs with the gate out of the path, so it has no result, no "
            "proof class and no policy correspondence"
        )

    # The field set a record is judged against is the one its own declared row
    # format names. Applying the current release's set to a v1 record would
    # report its missing v2 fields as defects, which is the floor-predates-the-
    # field trap: both published v1 records would stop verifying.
    _declared_rows = (record.get("ledger") or {}).get("row_version") if isinstance(record.get("ledger"), dict) else None
    _expected_fields = required_fields_for_row_version(_declared_rows) or REQUIRED_FIELDS

    undeclared = sorted(set(record) - set(_expected_fields) - set(OPTIONAL_FIELDS) - set(FORBIDDEN_FIELDS))
    if undeclared:
        defects.append(f"carries undeclared fields: {undeclared}")

    missing = [field for field in _expected_fields if field not in record]
    if missing:
        defects.append(f"does not carry required fields: {missing}")
        return defects

    defects.extend(_field_defects("", record, FIELD_RULES))
    # record_version against the row format the document declares, not against
    # the one this release writes. A v1 record declaring record_version 1 is
    # correct; judging it by the current constant would refuse it.
    _expected_record_version = RECORD_VERSION_BY_ROW_VERSION.get(_declared_rows)
    if _expected_record_version is not None and record.get("record_version") != _expected_record_version:
        defects.append(
            f"record_version is {record.get('record_version')!r}, but baseline row "
            f"version {_declared_rows!r} goes with record_version "
            f"{_expected_record_version}"
        )
    if record.get("mode") != "live":
        defects.append(
            "A baseline with no provider call observes nothing its prompt set does not "
            "already state, so mode must be 'live'"
        )
    if record.get("prompt_set_hash_kind") not in PROMPT_SET_HASH_KINDS:
        defects.append(f"prompt_set_hash_kind is {record.get('prompt_set_hash_kind')!r}")

    ledger = record.get("ledger")
    if not isinstance(ledger, dict):
        defects.append("ledger is not an object")
    else:
        for field in LEDGER_FIELDS:
            if field not in ledger:
                defects.append(f"ledger does not carry {field}")
        if set(ledger) - set(LEDGER_FIELDS):
            defects.append(f"ledger carries undeclared fields: {sorted(set(ledger) - set(LEDGER_FIELDS))}")
        defects.extend(_field_defects("ledger.", ledger, LEDGER_FIELD_RULES))

    # Baseline row version 2's two objects, checked for shape where present.
    # Their presence is decided by the required set above, which is keyed on the
    # declared row version; this only says what they must look like.
    for name, rules in (
        ("refusal_detection", REFUSAL_DETECTION_RULES),
        ("provider_output_limit", PROVIDER_OUTPUT_LIMIT_RULES),
    ):
        block = record.get(name)
        if name not in record or block is None:
            continue
        if not isinstance(block, dict):
            defects.append(f"{name} is not an object")
            continue
        for field in rules:
            if field not in block:
                defects.append(f"{name} does not carry {field}")
        if set(block) - set(rules):
            defects.append(f"{name} carries undeclared fields: {sorted(set(block) - set(rules))}")
        defects.extend(_field_defects(f"{name}.", block, rules))
        if ledger.get("chain_version") != CHAIN_VERSION_V2:
            defects.append(
                "A chain version 1 row's status is not evidence, so the bound ledger must "
                f"be chain version {CHAIN_VERSION_V2}"
            )
        # Membership, not equality against the version this release writes. A
        # later release that reads two row formats extends the tuple and this
        # check needs no edit, which is the whole point of the field: a
        # verifier refuses a format it does not read instead of applying the
        # wrong rules to it.
        declared_rows = ledger.get("row_version")
        if (
            not isinstance(declared_rows, bool)
            and isinstance(declared_rows, int)
            and declared_rows not in SUPPORTED_BASELINE_ROW_VERSIONS
        ):
            defects.append(
                f"the record declares baseline row version {declared_rows}, which this "
                f"release does not read; it reads {list(SUPPORTED_BASELINE_ROW_VERSIONS)}"
            )

    counters = record.get("counters")
    if not isinstance(counters, dict):
        defects.append("counters is not an object")
    else:
        # Judged by the format the record declares, not by the one this
        # release writes. A v1 record has six counters and a v2 record has
        # seven; applying the current set to either would reject the other.
        expected_counters = counter_fields_for_row_version(
            (record.get("ledger") or {}).get("row_version")
            if isinstance(record.get("ledger"), dict)
            else None
        )
        missing_counters = [field for field in expected_counters if field not in counters]
        if missing_counters:
            defects.append(f"counters does not carry {missing_counters}")
        undeclared_counters = sorted(set(counters) - set(expected_counters))
        if undeclared_counters:
            defects.append(f"counters carries undeclared fields: {undeclared_counters}")
        for field, value in counters.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                defects.append(f"counters.{field} is {value!r}, not a non-negative integer")

    return defects


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a signed SIR ungated baseline record.",
        epilog=(
            "Examples:\n"
            "  python3 tools/verify_baseline_record.py proofs/baseline.json\n"
            "  python3 tools/verify_baseline_record.py docs/runs/<run_id>/baseline.json \\\n"
            "      --ledger docs/runs/<run_id>/proofs/itgl_ledger.jsonl --require-registry\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("record", help="Path to the baseline record JSON, or - for stdin.")
    parser.add_argument(
        "--ledger",
        help="The ledger this record binds. Defaults to the path the record names.",
    )
    parser.add_argument(
        "--no-ledger",
        action="store_true",
        help=(
            "Check the document and its signature without a ledger. The binding, the "
            "row classification and the counters are then not established, and the "
            "success line says so. Mirrors tools/verify_certificate.py."
        ),
    )
    parser.add_argument("--pubkey", default=None, help=f"PEM public key (default: {DEFAULT_PUBKEY_PATH})")
    parser.add_argument("--key-registry", default=str(DEFAULT_KEY_REGISTRY))
    parser.add_argument(
        "--require-registry",
        action="store_true",
        help="Refuse to fall back to --pubkey when the registry cannot resolve the key.",
    )
    parser.add_argument("--quiet", action="store_true", help="Only the exit code, no success line.")
    return parser.parse_args()


def _load_record(source: str) -> Dict[str, Any]:
    raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    try:
        document = json.loads(raw)
    except Exception as exc:
        raise SystemExit(f"ERROR: failed to parse {source} as JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SystemExit(f"ERROR: expected a JSON object in {source}")
    return document


def main() -> int:
    args = _parse_args()
    record = _load_record(args.record)

    # 1. Type, before anything else is said about this document.
    if record.get("record_kind") != RECORD_KIND:
        print(
            "ERROR: this document is not a SIR ungated baseline record: record_kind is "
            f"{record.get('record_kind')!r}, not {RECORD_KIND!r}. Nothing here was verified, "
            "including its signature. An audit certificate is verified with "
            "tools/verify_certificate.py.",
            file=sys.stderr,
        )
        return NOT_A_BASELINE_RECORD

    # 2. Structure.
    defects = _structural_defects(record)
    if defects:
        print("ERROR: this baseline record is not valid:", file=sys.stderr)
        for defect in defects:
            print(f"  - {defect}", file=sys.stderr)
        return NOT_A_BASELINE_RECORD

    # 3. Signature, key resolution and revocation.
    payload = signing_payload(record)
    if record.get("payload_hash") != compute_payload_hash(record):
        print("ERROR: payload_hash mismatch", file=sys.stderr)
        print(f"  record: {record.get('payload_hash')}", file=sys.stderr)
        print(f"  calc:   {compute_payload_hash(record)}", file=sys.stderr)
        return PAYLOAD_HASH_MISMATCH

    try:
        signature = base64.b64decode(str(record["signature"]), validate=True)
    except Exception as exc:
        print(f"ERROR: signature is not valid base64 ({exc})", file=sys.stderr)
        return SIGNATURE_NOT_BASE64

    signing_key_id = str(record["signing_key_id"])
    registry_path = Path(args.key_registry)
    key_source = None
    public_key = None

    entry = None
    if registry_path.exists():
        try:
            entry = find_registry_key(registry_path, signing_key_id)
        except Exception as exc:
            if args.require_registry:
                print(f"ERROR: key registry unreadable: {exc}", file=sys.stderr)
                return SIGNATURE_FAILED
            entry = None

    if entry is not None:
        allowed, reason = revocation_allows_proof(
            entry, record.get("timestamp_utc"), record.get("run_id")
        )
        if not allowed:
            print(f"ERROR: revoked-key verification failure: {reason}", file=sys.stderr)
            return REVOCATION_FAILURE
        public_key = serialization.load_pem_public_key(
            public_key_pem_from_entry(entry).encode("utf-8")
        )
        key_source = f"key registry {registry_path} entry signing_key_id={signing_key_id}"
    elif args.require_registry:
        print(
            f"ERROR: signing_key_id {signing_key_id!r} not found in {registry_path}, and "
            "--require-registry forbids falling back to a public key file",
            file=sys.stderr,
        )
        return SIGNATURE_FAILED
    else:
        pubkey_path = Path(args.pubkey or DEFAULT_PUBKEY_PATH)
        try:
            public_key = serialization.load_pem_public_key(pubkey_path.read_bytes())
        except Exception as exc:
            print(f"ERROR: failed to load public key {pubkey_path}: {exc}", file=sys.stderr)
            return SIGNATURE_FAILED
        key_source = f"--pubkey {pubkey_path}"

    try:
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print(f"ERROR: signature verification failed (InvalidSignature) against {key_source}", file=sys.stderr)
        return SIGNATURE_FAILED
    except Exception as exc:
        # Not SIGNATURE_FAILED. A malformed registry entry, an unsupported key
        # algorithm, or a programming error here all land in this branch, and
        # none of them is evidence that the record's signature is bad.
        print(
            f"ERROR: signature verification could not be performed ({exc})",
            file=sys.stderr,
        )
        return SIGNATURE_CHECK_RAISED

    # 4. The bound ledger.
    if args.no_ledger:
        if args.ledger:
            print(
                "ERROR: --no-ledger and --ledger are mutually exclusive.", file=sys.stderr
            )
            return NOT_A_BASELINE_RECORD
        if not args.quiet:
            print(
                f"OK: {record['record_kind']} for run {record['run_id']} is structurally "
                "valid and its signature verifies. No ledger was supplied, so the ledger "
                "binding, the row classification and the counters are not established, "
                "and this does not establish that no gate ran."
            )
        return 0

    # The record names its own ledger path, so without an explicit --ledger a
    # record can be verified against a ledger anywhere on disk. That is correct
    # for a reviewer checking a record they hold beside its ledger, and wrong
    # for a tool reporting on one archive directory, which is why
    # tools/verify_evidence.py now always passes one or the other.
    ledger_path = Path(args.ledger or record["ledger"]["path"])
    if not ledger_path.is_file():
        print(
            f"ERROR: the ledger this record binds was not found at {ledger_path}. Pass "
            "--ledger PATH to verify an archived record from another directory.",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE
    try:
        terminal_hash, row_count = load_and_verify_ledger(ledger_path, CHAIN_VERSION_V2)
    except (LedgerVerificationError, OSError, UnicodeError) as exc:
        print(f"ERROR: ledger verification failed: {exc}", file=sys.stderr)
        return LEDGER_BINDING_FAILURE

    if terminal_hash != record["ledger"]["itgl_final_hash"]:
        print(
            "ERROR: ledger binding failed: the record's signed terminal hash is not this "
            f"ledger's.\n  record: {record['ledger']['itgl_final_hash']}\n  ledger: {terminal_hash}",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE
    if row_count != record["ledger"]["row_count"]:
        print(
            "ERROR: ledger binding failed: the record signs "
            f"{record['ledger']['row_count']} rows and this ledger has {row_count}",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE

    rows = load_ledger(ledger_path)

    # 5. Classification: the rows decide what this run was.
    row_defects = baseline_ledger_defects(rows)
    if row_defects:
        print(
            "ERROR: ledger binding failed: these are not the rows of an ungated baseline:",
            file=sys.stderr,
        )
        for defect in row_defects[:5]:
            print(f"  - {defect}", file=sys.stderr)
        return LEDGER_BINDING_FAILURE

    # 5b. The format the document declares is the format its rows are in.
    #
    # Unreachable while exactly one row version is supported, and deliberately
    # written anyway. The check above refuses a document declaring a version
    # this release does not read, and baseline_ledger_defects refuses a row at
    # one, so with a single supported version the two cannot disagree. The
    # moment SUPPORTED_BASELINE_ROW_VERSIONS holds two, a document declaring
    # one of them over rows in the other is accepted by both checks and this
    # is the only thing between it and a figure computed by the wrong rules.
    #
    # tests/test_baseline_record.py asserts that it is unreachable today, and
    # that assertion fails when a second version is added, so the case is
    # written then rather than remembered.
    declared_row_version = record["ledger"]["row_version"]
    disagreeing = sorted(
        {row.get("row_version") for row in rows if row.get("row_version") != declared_row_version},
        key=repr,
    )
    if disagreeing:
        print(
            f"ERROR: ledger binding failed: the record declares baseline row version "
            f"{declared_row_version!r} and the ledger carries rows at {disagreeing!r}",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE

    # 6. Counters, recomputed.
    derived = derive_counters(rows)
    # Only the counters this record's format declares. A v1 record is not
    # expected to carry `provider_call_declined`, and comparing a field it
    # cannot have against a derived zero would report every published v1 record
    # as disagreeing with its own rows.
    compared_fields = counter_fields_for_row_version(record["ledger"].get("row_version"))
    disagreements = {
        field: {"record": record["counters"].get(field), "ledger": derived.get(field)}
        for field in compared_fields
        if record["counters"].get(field) != derived.get(field)
    }
    if disagreements:
        print(
            "ERROR: counter binding failed: the record's counters are not supported by the "
            f"rows it binds: {json.dumps(disagreements, sort_keys=True)}",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE

    counters = record["counters"]
    # The outcomes must partition the attempts, over whichever outcomes this
    # record's format has. A v1 record has two and a v2 record has three, so a
    # fixed two-term sum would report every v2 record whose provider declined
    # anything as failing to partition.
    _outcome_counters = [
        field
        for field in counter_fields_for_row_version(record["ledger"].get("row_version"))
        if field in ("provider_call_successes", "provider_call_failures", "provider_call_declined")
    ]
    if sum(counters[field] for field in _outcome_counters) != counters[
        "provider_call_attempts"
    ]:
        print(
            "ERROR: counter binding failed: the provider call outcomes do not partition the "
            f"attempts: {json.dumps(counters, sort_keys=True)}",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE
    if counters["provider_call_attempts"] != counters["prompts_forwarded"]:
        print(
            "ERROR: counter binding failed: every forwarded prompt is a provider call "
            f"attempt, and these disagree: {json.dumps(counters, sort_keys=True)}",
            file=sys.stderr,
        )
        return LEDGER_BINDING_FAILURE

    if not args.quiet:
        print(
            f"OK: baseline record verified against {key_source}; "
            f"{counters['prompts_forwarded']} prompts forwarded ungated "
            f"({counters['expected_block_prompts_forwarded']} labelled block), "
            f"{counters['provider_call_failures']} provider call failures; "
            f"bound to {ledger_path} at {terminal_hash}."
        )
        print(
            "NOTE: this establishes what the producer recorded, not that no gate ran. "
            "The record carries no audit result and no proof class, by design."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
