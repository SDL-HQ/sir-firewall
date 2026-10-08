#!/usr/bin/env python3
"""
SIR Firewall — Certificate Verifier

Verifies:
- payload_hash matches the reconstructed signed payload bytes
- RSA signature matches those payload bytes using resolved public key material

Inputs:
- cert path (positional arg), OR
- "-" to read JSON cert from stdin

Defaults:
- pubkey: spec/sdl.pub
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from key_registry import (
    IMPLICIT_KEY_ID,
    find_registry_key,
    public_key_pem_from_entry,
    revocation_allows_proof,
)
from itgl import (
    CHAIN_VERSION_V1,
    CHAIN_VERSION_V2,
    LedgerVerificationError,
    counter_disagreements,
    ledger_chain_version,
    load_and_verify_ledger,
    load_ledger,
)

DEFAULT_PUBKEY_PATH = Path("spec/sdl.pub")
DEFAULT_KEY_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")
# The chain version a certificate's own release is required to have written.
# Taken from sir_firewall_version, which is inside the signed payload, so a
# holder of the archive cannot lower the bar without breaking the signature.
#
# This is a policy control, not the anti-tampering mechanism. Tampering is
# defeated by chain_version 2 putting the row's contents into its own hash and
# by the signed terminal hash pinning the chain; a row downgraded inside a v2
# ledger breaks linkage whether or not a minimum is set. What the bar adds is
# that a reader requiring v2 evidence does not silently accept a v1 archive,
# which matters most where no signed terminal hash is present to pin anything.
MINIMUM_CHAIN_VERSION_FLOORS = (
    ((2, 4, 0), CHAIN_VERSION_V2),
)


def _parse_semver(value: Any) -> Optional[Tuple[int, int, int]]:
    if not isinstance(value, str) or re.fullmatch(r"\d+\.\d+\.\d+", value) is None:
        return None
    major, minor, patch = (int(part) for part in value.split("."))
    return (major, minor, patch)


def minimum_chain_version_for(sir_firewall_version: Any) -> int:
    """The chain version this certificate's release was required to write.

    An unparseable or absent version floors at v1 rather than raising. Three
    published certificates carry no version at all, and refusing them here
    would be a verification failure reported as a tampering failure, which is
    worse than reporting what the weaker rule established.
    """
    parsed = _parse_semver(sir_firewall_version)
    if parsed is None:
        return CHAIN_VERSION_V1
    required = CHAIN_VERSION_V1
    for floor, version in MINIMUM_CHAIN_VERSION_FLOORS:
        if parsed >= floor:
            required = max(required, version)
    return required


# The fields evidence contract v4 adds over v3. A certificate selects its
# contract from its own sir_firewall_version, which the signer writes, so a
# certificate can claim an older version and be judged by an older contract.
# The bound ledger cannot be restamped the same way: chain_version is covered
# by each row's own hash under chain version 2 and chained to the terminal
# hash the certificate signs. So the ledger, not the certificate, says which
# era this evidence is from, and these fields are required of any certificate
# bound to a chain version 2 ledger whatever version it claims.
#
# This constant is the shipped copy of a rule whose authority is
# spec/evidence_contract.v4.json, so that a minimal verification bundle needs
# no spec file to apply it. tests/test_contract_floor_is_not_self_asserted.py
# asserts the two agree; if the contract changes, that test fails rather than
# this copy drifting.
CONTRACT_V4_ADDED_FIELDS = (
    "configuration_hash",
    "content_evaluated",
    "counters_checked_against_ledger",
    "signing_key_id",
    "systemic_reset_count",
)

MISSING_REQUIRED_FIELDS = 2

LEDGER_BINDING_FAILURE = 7
# A signed counter the ledger does not support. Distinct from 7 because the
# chain and the terminal hash can both be intact while the numbers on the
# certificate describe a different run than the rows do.
COUNTER_BINDING_FAILURE = 11
LEDGER_BINDING_NOT_CHECKED = 9
REVOCATION_FAILURE = 10


def _require_json_object(obj: Any, source: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise SystemExit(f"ERROR: expected a JSON object for certificate from {source}, but got {type(obj).__name__}")
    # typing: we just asserted it's a dict
    return obj  # type: ignore[return-value]


def _read_json_from_stdin_strict() -> Dict[str, Any]:
    if sys.stdin is None:
        raise SystemExit("ERROR: stdin is unavailable")

    # If user explicitly asked for stdin ("-") but stdin is a TTY, fail fast with guidance.
    if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        raise SystemExit('ERROR: stdin is a TTY. Pipe JSON into stdin, or pass a certificate file path.')

    raw = sys.stdin.read()
    if raw is None:
        raise SystemExit("ERROR: failed to read stdin")

    raw = raw.strip()
    if not raw:
        raise SystemExit("ERROR: no JSON provided on stdin")

    try:
        obj = json.loads(raw)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to parse JSON from stdin: {e}") from e

    return _require_json_object(obj, "stdin")


def _load_cert_from_file(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        raise SystemExit(f"ERROR: failed to read cert file: {path} ({e})") from e

    return _require_json_object(obj, str(path))


def _load_cert(cert_arg: str) -> tuple[Dict[str, Any], str]:
    # Explicit stdin mode.
    if cert_arg == "-":
        return _read_json_from_stdin_strict(), "stdin"

    # File path mode.
    p = Path(cert_arg)
    if not p.exists():
        raise SystemExit(f"ERROR: cert file does not exist: {p}")
    return _load_cert_from_file(p), str(p)


def _load_pubkey(pubkey_path: str) -> tuple[Any, str]:
    p = Path(pubkey_path)
    try:
        data = p.read_bytes()
        return serialization.load_pem_public_key(data), f"--pubkey {p}"
    except Exception as e:
        raise SystemExit(f"ERROR: failed to load public key: {p} ({e})") from e


def _load_pubkey_with_registry(
    cert: Dict[str, Any], pubkey_path: str, key_registry_path: str, require_registry: bool = False
) -> List[Tuple[Any, str]]:
    """Public keys to try, in order, each with the source that produced it.

    One entry in every case but one: a certificate naming no signing_key_id,
    where the registry's implicit entry is tried first and the public key file
    second. main() names whichever verified.
    """
    signing_key_id = cert.get("signing_key_id")
    registry_path = Path(key_registry_path)

    if "signing_key_id" in cert and (not isinstance(signing_key_id, str) or not signing_key_id):
        raise SystemExit("ERROR: signing_key_id must be a non-empty string when present")

    # A certificate from before the field existed is resolved as IMPLICIT_KEY_ID
    # rather than falling straight through to the public key file. See the
    # comment on that constant: since the 6 October rotation the file holds a
    # key that signed none of the 43 archives in this position.
    #
    # It is a candidate rather than a replacement. A third party assembling a
    # minimal bundle signs with their own key, writes it to spec/sdl.pub, and
    # copies the approved registry in beside it; their certificate carries no
    # key id either, and was not signed by SDL. So where the certificate names
    # no key, both sources are offered and the one that verifies is named in the
    # result. Two candidates do not weaken the statement, because the statement
    # says which key verified.
    #
    # One exception, and it is the important one: if the implicit registry entry
    # exists and its revocation rules refuse this archive, that is a refusal and
    # there is no fallback. Otherwise a revoked key could be laundered back in
    # through a public key file.
    implicit = False
    if not (isinstance(signing_key_id, str) and signing_key_id) and registry_path.exists():
        try:
            entry = find_registry_key(registry_path, IMPLICIT_KEY_ID)
        except Exception:
            entry = None
        if entry is not None:
            allowed, reason = revocation_allows_proof(
                entry, cert.get("timestamp_utc"), cert.get("run_id")
            )
            if not allowed:
                print(
                    "ERROR: revoked-key verification failure: this certificate carries no "
                    f"signing_key_id, so it is resolved as key_id={IMPLICIT_KEY_ID!r}: {reason}",
                    file=sys.stderr,
                )
                raise SystemExit(REVOCATION_FAILURE)
            signing_key_id = IMPLICIT_KEY_ID
            implicit = True

    if isinstance(signing_key_id, str) and signing_key_id:
        if not registry_path.exists():
            if require_registry:
                raise SystemExit(
                    f"ERROR: key registry not found: {registry_path} (required for signing_key_id={signing_key_id})"
                )
            print(
                "WARNING: signing_key_id present but key registry unavailable; falling back to --pubkey verification only (revocation checks not enforced).",
                file=sys.stderr,
            )
            return [_load_pubkey(pubkey_path)]
        try:
            entry = find_registry_key(registry_path, signing_key_id)
            if entry is None:
                raise SystemExit(f"ERROR: signing_key_id not found in key registry: {signing_key_id}")
            allowed, reason = revocation_allows_proof(
                entry, cert.get("timestamp_utc"), cert.get("run_id")
            )
            if not allowed:
                print(f"ERROR: revoked-key verification failure: {reason}", file=sys.stderr)
                raise SystemExit(REVOCATION_FAILURE)
            pem = public_key_pem_from_entry(entry)
            described = (
                f"key registry {registry_path} entry key_id={signing_key_id} "
                "(the certificate carries no signing_key_id; the field postdates it)"
                if implicit
                else f"key registry {registry_path} entry signing_key_id={signing_key_id}"
            )
            candidates = [(serialization.load_pem_public_key(pem.encode("utf-8")), described)]
            if implicit and not require_registry:
                candidates.append(_load_pubkey(pubkey_path))
            return candidates
        except SystemExit:
            raise
        except Exception as e:
            if require_registry:
                raise SystemExit(
                    f"ERROR: failed to load required key registry {registry_path} ({e})"
                ) from e
            print(
                "WARNING: signing_key_id present but key registry unreadable; falling back to --pubkey verification only (revocation checks not enforced).",
                file=sys.stderr,
            )
            return [_load_pubkey(pubkey_path)]

    return [_load_pubkey(pubkey_path)]


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Verify certificate payload integrity and signature validity for an existing SIR certificate JSON."
        ),
        epilog=(
            "Examples:\n"
            "  python3 tools/verify_certificate.py proofs/latest-audit.json\n"
            "  python3 tools/verify_certificate.py proofs/latest-audit.json --no-ledger\n"
            "  cat proofs/latest-audit.json | python3 tools/verify_certificate.py - --no-ledger\n\n"
            "Key resolution:\n"
            "  If signing_key_id is present and key registry is readable, that key is used.\n"
            "  Otherwise verifier falls back to --pubkey unless --require-registry is set.\n\n"
            "Exit code 7 means ledger chain or certificate-binding verification failed.\n"
            "Exit code 9 means binding was not checked because no ledger was found."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--ledger",
        help="Verify this ITGL ledger and bind its chain head and row count to the certificate.",
    )
    ap.add_argument(
        "--no-ledger",
        action="store_true",
        help="Explicitly skip ledger discovery and certificate-to-ledger binding verification.",
    )
    ap.add_argument(
        "cert",
        help='Certificate JSON path, or "-" to read certificate JSON from stdin.',
    )
    ap.add_argument(
        "--pubkey",
        default=str(DEFAULT_PUBKEY_PATH),
        help="Path to PEM public key to verify signatures (default: spec/sdl.pub).",
    )
    ap.add_argument(
        "--key-registry",
        default=str(DEFAULT_KEY_REGISTRY),
        help="Path to key registry JSON used with signing_key_id if present (default: spec/pubkeys/key_registry.v1.json).",
    )
    ap.add_argument(
        "--require-registry",
        action="store_true",
        help="Fail when signing_key_id is present but key registry is missing/unreadable (disables --pubkey fallback).",
    )
    ap.add_argument("--quiet", action="store_true", help="Only exit code, no success message.")
    args = ap.parse_args()
    if args.ledger and args.no_ledger:
        ap.error("--ledger and --no-ledger are mutually exclusive")
    return args


def _discover_ledger(cert: Dict[str, Any], cert_arg: str) -> Path | None:
    """Resolve a ledger from signed run identity, never unrelated adjacency.

    The ledger beside the certificate is preferred over the canonical path.
    Both are keyed on the signed run_id, so neither is unrelated adjacency, and
    a mismatch between them is caught by the terminal hash either way. But the
    canonical path is resolved against the current working directory, so
    searching it first meant that verifying a downloaded bundle from inside a
    repository checkout checked the repository's copy and said so in a line the
    reader had no reason to read closely. An evaluator who points at a directory
    is asking about that directory.

    The cert_dir.name == run_id guard stays: a ledger is accepted from beside a
    certificate only when the directory is named for the run the certificate
    signs.
    """
    if cert_arg == "-":
        return None

    cert_dir = Path(cert_arg).parent
    run_id = cert.get("run_id")
    if not (isinstance(run_id, str) and run_id):
        return None

    beside_the_certificate = cert_dir / "proofs" / "itgl_ledger.jsonl"
    if cert_dir.name == run_id and beside_the_certificate.is_file():
        return beside_the_certificate

    try:
        from sir_firewall.evidence_paths import canonical_ledger_path

        canonical = canonical_ledger_path(run_id)
    except (ImportError, ValueError):
        canonical = None
    if canonical is not None and canonical.is_file():
        return canonical

    return None


def _rebuild_payload(cert: Dict[str, Any]) -> bytes:
    payload_obj = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> int:
    args = _parse_args()

    cert, _source = _load_cert(args.cert)
    key_candidates = _load_pubkey_with_registry(
        cert, args.pubkey, args.key_registry, require_registry=args.require_registry
    )

    if "signature" not in cert or "payload_hash" not in cert:
        print("ERROR: missing required fields: signature and/or payload_hash", file=sys.stderr)
        return 2

    payload = _rebuild_payload(cert)

    expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    if cert.get("payload_hash") != expected_hash:
        print("ERROR: payload_hash mismatch", file=sys.stderr)
        print(f"  cert: {cert.get('payload_hash')}", file=sys.stderr)
        print(f"  calc: {expected_hash}", file=sys.stderr)
        return 3

    try:
        sig = base64.b64decode(str(cert["signature"]))
    except Exception as e:
        print(f"ERROR: signature is not valid base64 ({e})", file=sys.stderr)
        return 4

    key_source = None
    raised: Optional[Exception] = None
    for candidate, source in key_candidates:
        try:
            candidate.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            continue
        except Exception as e:
            raised = e
            continue
        key_source = source
        break
    if key_source is None:
        if raised is not None:
            print(f"ERROR: signature verification failed ({raised})", file=sys.stderr)
            return 6
        # The message is unchanged where one key was tried, which is every case
        # but a certificate naming no key id outside --require-registry. Naming
        # the sources only matters when there was more than one, and this exact
        # string is a documented diagnostic pinned by the negative examples.
        suffix = ""
        if len(key_candidates) > 1:
            suffix = " against " + ", ".join(source for _, source in key_candidates)
        print(
            f"ERROR: signature verification failed (InvalidSignature){suffix}",
            file=sys.stderr,
        )
        return 5

    ledger_path = Path(args.ledger) if args.ledger else (None if args.no_ledger else _discover_ledger(cert, args.cert))
    if not args.no_ledger and ledger_path is None:
        run_id = cert.get("run_id")
        identity_detail = (
            f" for signed run_id={run_id!r}" if isinstance(run_id, str) and run_id else ""
        )
        print(
            "NOT CHECKED: certificate-to-ledger binding was not checked because no ledger "
            f"corresponding to the signed identity{identity_detail} was found. "
            "Pass --ledger PATH explicitly for replay or use --no-ledger to skip binding.",
            file=sys.stderr,
        )
        return LEDGER_BINDING_NOT_CHECKED

    if ledger_path is not None:
        try:
            ledger_hash, row_count = load_and_verify_ledger(
                ledger_path, minimum_chain_version_for(cert.get("sir_firewall_version"))
            )
        except (LedgerVerificationError, OSError, UnicodeError) as exc:
            print(f"ERROR: ledger binding verification failed: {exc}", file=sys.stderr)
            return LEDGER_BINDING_FAILURE
        cert_hash = cert.get("itgl_final_hash")
        if ledger_hash != cert_hash:
            # Before SIR 2.3.4, certificate generation took itgl_final_hash from
            # the ITGL_FINAL_HASH environment variable or the mutable
            # proofs/itgl_final_hash.txt, so a certificate could sign a hash left
            # by an earlier run. docs/evidence-binding-correction.md records this
            # and states the consequence: a pre-2.3.4 certificate is a signature
            # over an unbound evidence package, whose ledger it does not reliably
            # identify. The archives were deliberately not re-signed.
            #
            # Measured on 8 October 2026 across the 292 published certificates
            # that ship a ledger: every one from 2.3.4 onward matches, 24 of 24.
            # Below it, 105 do not. Three certificates carrying no version share
            # one itgl_final_hash between ledgers of 152, 8 and 6 rows.
            #
            # So a mismatch below the correction is a binding that was never
            # made, which is exit 9, not established. At 2.3.4 and later it is a
            # binding that was made and is wrong, which is exit 7. Reporting a
            # documented and disclosed format boundary as a tampering failure
            # would call 105 published archives broken.
            claimed = _parse_semver(cert.get("sir_firewall_version"))
            if claimed is None or claimed < (2, 3, 4):
                print(
                    "NOT CHECKED: the certificate-to-ledger binding was not established "
                    "because this certificate predates the SIR 2.3.4 evidence-binding "
                    "correction, so its itgl_final_hash does not reliably identify its "
                    f"ledger (certificate version: {cert.get('sir_firewall_version')!r}).\n"
                    f"  cert: {cert_hash}\n"
                    f"  ledger: {ledger_hash}\n"
                    "  See docs/evidence-binding-correction.md. The ledger itself is "
                    "chain-valid and the signature is unaffected.",
                    file=sys.stderr,
                )
                return LEDGER_BINDING_NOT_CHECKED
            print("ERROR: ledger binding verification failed: terminal hash mismatch", file=sys.stderr)
            print(f"  cert: {cert_hash}", file=sys.stderr)
            print(f"  ledger: {ledger_hash}", file=sys.stderr)
            return LEDGER_BINDING_FAILURE
        prompts_tested = cert.get("prompts_tested")
        signed_row_count = cert.get("itgl_row_count")
        if signed_row_count is None:
            # The field postdates SIR 2.3.4, so a certificate from before it
            # never carried one. That is a binding nobody can check, not a
            # binding that disagreed, and reporting it as a failure manufactures
            # a catastrophe out of a format change for the 219 archives in this
            # position. A certificate that claims 2.3.4 or later and carries no
            # row count is a different thing: the field should be there.
            #
            # Selecting on the producer-chosen version is safe here and only
            # here, because the version-derived outcome is the weaker one.
            # Understamping buys nothing: exit 9 establishes nothing at all,
            # where exit 7 at least records that a check was attempted.
            claimed = _parse_semver(cert.get("sir_firewall_version"))
            predates_the_field = claimed is None or claimed < (2, 3, 4)
            if predates_the_field:
                print(
                    "NOT CHECKED: the certificate-to-ledger row count was not checked "
                    "because this certificate carries no itgl_row_count, a field that "
                    "postdates SIR 2.3.4 "
                    f"(certificate version: {cert.get('sir_firewall_version')!r}, "
                    f"ledger rows: {row_count}, prompts_tested: {prompts_tested}). "
                    "The terminal hash binding above did verify.",
                    file=sys.stderr,
                )
                return LEDGER_BINDING_NOT_CHECKED
            print(
                "ERROR: ledger binding verification failed: certificate carries no itgl_row_count,\n"
                "so the signed row count cannot be bound to this ledger "
                f"(ledger rows: {row_count},\nprompts_tested: {prompts_tested}). "
                "Certificates emitted before SIR 2.3.4 do not carry this field.",
                file=sys.stderr,
            )
            return LEDGER_BINDING_FAILURE
        if row_count != prompts_tested or row_count != signed_row_count:
            print("ERROR: ledger binding verification failed: row count mismatch", file=sys.stderr)
            print(f"  prompts_tested: {prompts_tested}", file=sys.stderr)
            print(f"  signed itgl_row_count: {signed_row_count}", file=sys.stderr)
            print(f"  ledger rows: {row_count}", file=sys.stderr)
            return LEDGER_BINDING_FAILURE

        entries = load_ledger(ledger_path)

        # The era the evidence is actually from, taken from the ledger rather
        # than from the certificate's own version claim.
        if ledger_chain_version(entries) >= CHAIN_VERSION_V2:
            absent = [
                field
                for field in CONTRACT_V4_ADDED_FIELDS
                if cert.get(field) is None
            ]
            if absent:
                print(
                    "ERROR: missing required fields: this certificate is bound to a "
                    f"chain version {CHAIN_VERSION_V2} ledger, which evidence contract v4 "
                    "governs, but it does not carry "
                    + ", ".join(absent)
                    + f".\n  certificate claims sir_firewall_version="
                    f"{cert.get('sir_firewall_version')!r}, which does not lower this "
                    "requirement because the bound ledger's chain version is covered by "
                    "its own row hashes.",
                    file=sys.stderr,
                )
                return MISSING_REQUIRED_FIELDS

        # Recompute the certificate's own counters from the rows it binds.
        # The chain can be intact and the terminal hash can match while the
        # numbers on the certificate describe a different run than the rows
        # do, because until 8 October 2026 nothing connected the two.
        disagreements = counter_disagreements(cert, entries)
        if disagreements:
            print(
                "ERROR: counter binding verification failed: the certificate's "
                "counters are not supported by the ledger it binds",
                file=sys.stderr,
            )
            for field, values in sorted(disagreements.items()):
                print(
                    f"  {field}: certificate={values['claimed']}, ledger={values['ledger']}",
                    file=sys.stderr,
                )
            return COUNTER_BINDING_FAILURE
        if disagreements is None:
            print(
                "NOTE: this ledger predates the fields needed to recompute the "
                "certificate's counters, so they were not checked against it.",
                file=sys.stderr,
            )

    if cert.get("detached_ledger") is True:
        print(
            "WARNING: certificate is explicitly marked detached_ledger=true; "
            "its signed run_id does not assert the canonical location of this ledger.",
            file=sys.stderr,
        )

    if args.no_ledger:
        print(
            "NOT VERIFIED: certificate-to-ledger binding was skipped with --no-ledger.",
            file=sys.stderr,
        )

    if not args.quiet:
        if ledger_path is not None:
            print(
                "OK: payload_hash and signature verify "
                f"against {key_source}; ledger binding verifies signed itgl_final_hash="
                f"{ledger_hash} equals the ledger terminal hash from {ledger_path}, and signed "
                f"itgl_row_count={row_count} equals prompts_tested={prompts_tested}."
            )
        else:
            print(
                "OK: payload_hash and signature verify "
                f"against {key_source}; certificate integrity and signature are valid."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
