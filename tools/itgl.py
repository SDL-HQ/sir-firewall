"""Shared loading and verification for SIR ITGL JSONL ledgers."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class LedgerVerificationError(RuntimeError):
    """Raised when an ITGL ledger fails structural or hash checks."""


CHAIN_VERSION_V1 = 1
CHAIN_VERSION_V2 = 2
CURRENT_CHAIN_VERSION = CHAIN_VERSION_V2
SUPPORTED_CHAIN_VERSIONS = (CHAIN_VERSION_V1, CHAIN_VERSION_V2)

# The only two fields a row's own hash cannot cover, because they are the hash
# and its predecessor. Everything else is covered, and that is deliberately
# expressed as an exclusion rather than a list of included fields: a
# maintained include-list makes anything omitted an undetected tamper surface,
# and new row fields would have to remember to join it.
CHAIN_FIELDS = ("prev_hash", "ledger_hash")


def declared_chain_version(entry: Dict[str, Any]) -> int:
    """Which rule computes this row's hash.

    This selects the computation and nothing else. Whether the row is
    acceptable is the minimum passed to verify_ledger, which comes from
    outside the data.

    What stops a tampered row being downgraded to v1 is not that minimum. In a
    v2 ledger the original hash already covered the row's contents, so
    recomputing under v1 produces a different value, the next row's prev_hash
    stops matching, and repairing the linkage moves the terminal hash the
    certificate signed. The mixed-version check below catches it earlier still.
    The minimum exists so a reader can require the stronger format where there
    is no signed terminal hash to pin anything, which is the standalone case.
    """
    value = entry.get("chain_version", CHAIN_VERSION_V1)
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerVerificationError(f"chain_version must be an integer, got {value!r}")
    if value not in SUPPORTED_CHAIN_VERSIONS:
        raise LedgerVerificationError(f"unsupported chain_version {value}")
    return value


def chain_payload(entry: Dict[str, Any]) -> str:
    """The bytes hashed alongside prev_hash, by version.

    v1 covers only the row's own opaque per-prompt digest, so every
    human-readable field in a published row is unbound. That was reproduced on
    a real archive on 2 October 2026: a row's decision, prompt identifier,
    prompt hash, leak flag and timestamp were all altered and the certificate
    still verified at exit 0.

    v2 covers a canonical form of the parsed row, computed from the object
    rather than the bytes on disk. Hashing the raw line would mean that
    re-serialising a ledger with different key order or unicode escaping broke
    every row; hashing the canonical object means reformatting survives and
    changing a value does not.
    """
    version = declared_chain_version(entry)
    if version == CHAIN_VERSION_V1:
        return _final_hash_raw(entry) or ""
    row = {key: value for key, value in entry.items() if key not in CHAIN_FIELDS}
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_ledger_hash(prev_hash: str, entry: Dict[str, Any]) -> str:
    """The chain rule, in one place.

    This module is what ships to third parties in a minimal verification
    bundle, so it holds the definition and the runner imports it. Until
    7 October 2026 red_team_suite.py carried a private copy, and writer and
    verifier agreed only because both were three lines long. A drift between
    them would mean our own archives verify for us and not for a reader.
    """
    return hashlib.sha256(
        ((prev_hash or "") + chain_payload(entry)).encode("utf-8")
    ).hexdigest()


def load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise LedgerVerificationError(f"ITGL ledger not found at {path}")
    entries: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as source:
            for line_no, line in enumerate(source, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LedgerVerificationError(f"Invalid JSON on line {line_no}: {exc}") from exc
                if not isinstance(entry, dict):
                    raise LedgerVerificationError(f"Ledger entry on line {line_no} is not a JSON object")
                entries.append(entry)
    except (OSError, UnicodeError) as exc:
        raise LedgerVerificationError(f"Unable to read ITGL ledger at {path}: {exc}") from exc
    if not entries:
        raise LedgerVerificationError("ITGL ledger is empty")
    return entries


def _final_hash_raw(entry: Dict[str, Any]) -> Optional[str]:
    if "final_hash" in entry:
        value = str(entry.get("final_hash") or "").strip()
        return value or None
    value = str(entry.get("itgl_prompt_final_hash") or "").strip()
    if not value:
        return None
    return value.split("sha256:", 1)[-1] if value.startswith("sha256:") else value


def verify_ledger(
    entries: List[Dict[str, Any]],
    minimum_chain_version: int = CHAIN_VERSION_V1,
) -> str:
    """Verify chain linkage and per-row hashes.

    minimum_chain_version is the bar, and it comes from the caller rather than
    from the data: verify_certificate derives it from the certificate's signed
    sir_firewall_version, and the command line takes it as a flag. A row
    declaring a version below the bar is refused rather than verified under the
    weaker rule.

    The default is v1 so that the 292 archives published before 7 October 2026
    keep verifying under the rule they were written with. A verifier defaulting
    to v2 would manufacture a catastrophe out of a format change.
    """
    previous = None
    final = ""
    observed_versions = set()
    for offset, entry in enumerate(entries):
        index = offset + 1
        missing = [key for key in ("ts", "prompt_index", "prev_hash", "ledger_hash") if key not in entry]
        if missing:
            raise LedgerVerificationError(f"Entry #{index} missing required fields: {', '.join(missing)}")
        version = declared_chain_version(entry)
        observed_versions.add(version)
        if version < minimum_chain_version:
            raise LedgerVerificationError(
                f"Entry #{index} declares chain_version {version} but at least "
                f"{minimum_chain_version} is required. Under chain_version 1 the "
                "row hash does not cover the row's contents, so accepting this "
                "would accept an unbound row."
            )
        if len(observed_versions) > 1:
            raise LedgerVerificationError(
                f"Entry #{index} declares chain_version {version} in a ledger "
                f"that also uses {sorted(observed_versions - {version})}. One "
                "run writes one version; a mixture is tampering or a defect."
            )
        if "final_hash" not in entry and "itgl_prompt_final_hash" not in entry:
            raise LedgerVerificationError(
                f"Entry #{index} missing per-prompt final hash field (expected 'final_hash' or 'itgl_prompt_final_hash')"
            )
        prev_hash = str(entry.get("prev_hash") or "")
        stored = str(entry.get("ledger_hash") or "")
        raw = _final_hash_raw(entry)
        if not raw:
            raise LedgerVerificationError(f"Entry #{index} has empty final hash")
        if offset == 0 and prev_hash != "GENESIS":
            raise LedgerVerificationError(f"Entry #1 has unexpected prev_hash={prev_hash!r}, expected 'GENESIS'")
        if offset and prev_hash != previous:
            raise LedgerVerificationError(
                f"Entry #{index} prev_hash={prev_hash!r} does not match previous ledger_hash={previous!r}"
            )
        computed = compute_ledger_hash(prev_hash, entry)
        if stored != computed:
            raise LedgerVerificationError(
                f"Entry #{index} has invalid ledger_hash: stored={stored!r}, computed={computed!r}"
            )
        previous = stored
        final = stored
    if not final:
        raise LedgerVerificationError("No final ledger hash computed")
    return final


def load_and_verify_ledger(
    path: Path, minimum_chain_version: int = CHAIN_VERSION_V1
) -> Tuple[str, int]:
    """Return a verified prefixed chain head and nonblank ledger row count."""
    entries = load_ledger(path)
    return f"sha256:{verify_ledger(entries, minimum_chain_version)}", len(entries)


# The status an ungated baseline row carries, from SIR 2.5.
#
# It is not a gate verdict. The gate returns PASS or BLOCKED and nothing else,
# so no gated run can produce this row and no baseline row can be mistaken for
# a decision. Until 2.5 a baseline row carried PASS, which the gate had never
# said: every expected-block prompt then counted as a leak, every baseline
# certificate computed AUDIT FAILED, and 54 of them were published that way.
# docs/archive-errata.md E7 records it.
FORWARDED_STATUS = "FORWARDED"

# What an ungated baseline row may contain, exactly.
#
# An exact set rather than a list of forbidden keys. The first draft of the 2.5
# specification listed what a baseline row must not carry, and an independent
# review got `expected="banana"` and duplicate prompt indexes past it: a
# forbidden-key list cannot be complete, because the next field nobody thought
# of is absent from it.
BASELINE_ROW_KEYS = frozenset(
    {
        "chain_version",
        "ts",
        "prompt_index",
        "prompt_id",
        "category",
        "note",
        "prompt_encoded",
        "prompt_hash",
        "isc_template",
        "suite_path",
        "domain_pack",
        "status",
        "expected",
        "systemic_reset_reason",
        "provider_call_attempted",
        "provider_call_outcome",
        "row_version",
        "configuration_hash",
        "leak_flag",
        "final_hash",
        "itgl_prompt_final_hash",
        "prev_hash",
        "ledger_hash",
    }
)

# The scenario fields a scenario row adds, and the only additions permitted.
BASELINE_SCENARIO_ROW_KEYS = frozenset(
    {"scenario_id", "scenario_hash", "turn_index", "turn_id", "role"}
)

EXPECTED_LABELS = ("allow", "block")
PROVIDER_OUTCOMES = ("success", "failure")

# The baseline row format's own version, carried on every baseline row.
#
# Added before any baseline record was published, which is the only moment it
# is cheap. A baseline row is covered by the chain, and under chain version 2
# the row hash covers every field except the two chain fields, so a version
# written into the row is authenticated by the chain and by the terminal hash
# the record signs. A producer cannot restamp it to have a later format's rows
# judged by this format's rules: that is the defect
# tests/test_contract_floor_is_not_self_asserted.py exists for, one level down.
#
# What this buys: a future release that changes the baseline row format states
# which format a row is in, and a verifier built for one version refuses the
# other instead of misreading it. Without it, the format could only be told
# apart by a second predicate over the row's shape, and that predicate would
# have to be maintained forever against every format that ever shipped.
BASELINE_ROW_VERSION = 1
SUPPORTED_BASELINE_ROW_VERSIONS = (BASELINE_ROW_VERSION,)


def ungated_row_final_hash(entry: Dict[str, Any]) -> str:
    """The per-prompt digest of an ungated baseline row, from the row itself.

    The mapping from row field to digest input is stated here and nowhere else,
    and the runner computes the digest through this function rather than from
    its own variables. Before 2.5 the runner hashed values it happened to have
    in scope, two of which were not written to the row under the same name, so
    whether a reader could reconstruct the digest depended on those values
    coinciding. They did, for all 6,100 published baseline rows, which an
    independent review confirmed on 14 October 2026. Coincidence is not a
    mapping.

        mode         the constant below, so a gated row's digest can never
                     collide with a baseline row's
        prompt_hash  the row's prompt_hash
        template_id  the row's isc_template
        pack_id      the row's domain_pack
        scenario_id  the row's scenario_id, empty on a single-turn suite
        turn_id      the row's prompt_id, which is the turn id on a scenario

    `row_version` is deliberately **not** an input. This digest identifies a
    row's content, and its mapping is anchored to the 6,100 published baseline
    rows that predate the field; adding an input would change every one of
    their digests and the mapping would no longer agree with the archive. The
    version does not need to be here to be authenticated: chain version 2's row
    hash covers every field except the two chain fields, so the version is
    covered there, and the chain's terminal hash is signed on the record.

    This authenticates what the producer encoded. It does not establish that no
    gate ran: a producer that wanted to could write these rows without running
    anything. What it rules out is a baseline row and a gated row being
    confused for one another.
    """
    payload = {
        "mode": "ungated_baseline",
        "prompt_hash": str(entry.get("prompt_hash") or ""),
        "template_id": str(entry.get("isc_template") or ""),
        "pack_id": str(entry.get("domain_pack") or ""),
        "scenario_id": str(entry.get("scenario_id") or ""),
        "turn_id": str(entry.get("prompt_id") or ""),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def baseline_row_defects(entry: Dict[str, Any], *, index: int) -> List[str]:
    """Every way this row fails the baseline row shape. Empty means it holds."""
    defects: List[str] = []

    keys = set(entry)
    permitted = BASELINE_ROW_KEYS | BASELINE_SCENARIO_ROW_KEYS
    undeclared = sorted(keys - permitted)
    if undeclared:
        defects.append(f"row {index}: undeclared fields {undeclared}")

    scenario_keys = keys & BASELINE_SCENARIO_ROW_KEYS
    if scenario_keys and scenario_keys != BASELINE_SCENARIO_ROW_KEYS:
        defects.append(
            f"row {index}: partial scenario fields {sorted(scenario_keys)}; a scenario row "
            f"carries all of {sorted(BASELINE_SCENARIO_ROW_KEYS)} or none of them"
        )

    missing = sorted(BASELINE_ROW_KEYS - keys)
    if missing:
        defects.append(f"row {index}: missing fields {missing}")
        return defects

    if entry.get("status") != FORWARDED_STATUS:
        defects.append(f"row {index}: status is {entry.get('status')!r}, not {FORWARDED_STATUS}")
    if entry.get("expected") not in EXPECTED_LABELS:
        defects.append(f"row {index}: expected is {entry.get('expected')!r}")
    for field in ("systemic_reset_reason", "configuration_hash", "leak_flag"):
        if entry.get(field) != "":
            defects.append(f"row {index}: {field} is {entry.get(field)!r}, not empty")
    if entry.get("provider_call_attempted") is not True:
        defects.append(f"row {index}: provider_call_attempted is not true")
    if entry.get("provider_call_outcome") not in PROVIDER_OUTCOMES:
        defects.append(f"row {index}: provider_call_outcome is {entry.get('provider_call_outcome')!r}")

    # bool is a subclass of int and True == 1, so a membership test alone
    # accepts true where 1 is required.
    row_version = entry.get("row_version")
    if isinstance(row_version, bool) or not isinstance(row_version, int):
        defects.append(f"row {index}: row_version is {row_version!r}, not an integer")
    elif row_version not in SUPPORTED_BASELINE_ROW_VERSIONS:
        defects.append(
            f"row {index}: unsupported row_version {row_version}; this release reads "
            f"{list(SUPPORTED_BASELINE_ROW_VERSIONS)}"
        )

    expected_digest = ungated_row_final_hash(entry)
    if entry.get("final_hash") != expected_digest:
        defects.append(
            f"row {index}: final_hash does not match the digest recomputed from this row"
        )
    if entry.get("itgl_prompt_final_hash") != f"sha256:{entry.get('final_hash')}":
        defects.append(f"row {index}: itgl_prompt_final_hash disagrees with final_hash")

    return defects


def baseline_ledger_defects(entries: List[Dict[str, Any]]) -> List[str]:
    """Every way this ledger fails to be a baseline ledger. Empty means it is.

    A ledger is a baseline ledger when it is non-empty, every row is chain
    version 2, and every row satisfies the baseline row shape. Nothing here
    reads a version string: the rows are what classify the ledger, and under
    chain version 2 a row's own hash covers its contents.

    The row-shape rules exist because the digest alone is not enough. An
    independent review rehashed synthetic rows with the status changed to
    BLOCKED, and with a configuration reference added, and the digest still
    matched. The digest says which family a row belongs to; the shape says the
    row is what that family means.
    """
    if not entries:
        return ["a baseline ledger cannot be empty"]

    defects: List[str] = []
    for position, entry in enumerate(entries, start=1):
        if declared_chain_version(entry) != CHAIN_VERSION_V2:
            defects.append(
                f"row {position}: chain version {declared_chain_version(entry)}, and a "
                f"baseline ledger is chain version {CHAIN_VERSION_V2} throughout"
            )
            continue
        defects.extend(baseline_row_defects(entry, index=position))

    indexes = [entry.get("prompt_index") for entry in entries]
    if indexes != list(range(1, len(entries) + 1)):
        defects.append("prompt_index is not 1..n in order")
    identifiers = [str(entry.get("prompt_id") or "") for entry in entries]
    if len(set(identifiers)) != len(identifiers):
        defects.append("prompt_id is not unique within the ledger")

    return defects


def is_baseline_ledger(entries: List[Dict[str, Any]]) -> bool:
    return not baseline_ledger_defects(entries)


def forwarded_row_positions(entries: List[Dict[str, Any]]) -> List[int]:
    """Where a ledger carries baseline rows, for a reader that wanted a gated one.

    Any row at all, not every row: a certificate bound to a ledger with one
    baseline row among gated ones describes a run that cannot have happened,
    and a mixed ledger is neither kind.
    """
    return [
        position
        for position, entry in enumerate(entries, start=1)
        if entry.get("status") == FORWARDED_STATUS
    ]


# Fields a row must carry before its counters can be recomputed from it.
# Rows written before 8 October 2026 have none of them.
DERIVABLE_ROW_FIELDS = ("systemic_reset_reason", "expected", "status")


def derive_counters(entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Recompute the published counters from the ledger itself.

    This lives here, in the module that ships to a third party in a minimal
    verification bundle, so a reader can recompute the numbers rather than
    take them from the summary that asserts them. Until 8 October 2026 the
    runner counted in parallel with writing the rows and nothing could check
    one against the other.

    Returns None when the rows predate the fields this needs. Absent is
    unknown, not zero: returning zeros for a legacy ledger would invent a
    disagreement with every archive published before that date.
    """
    if not all(field in entry for entry in entries for field in DERIVABLE_ROW_FIELDS):
        return None

    # A baseline ledger is counted by what it forwarded, and by nothing else.
    #
    # The gate counters below are all computed over rows the gate judged, and a
    # baseline has none: no gate ran. Routing baseline rows through the same
    # split does not merely mislabel them, it destroys the figures. An
    # independent review ran it on 14 October 2026 and excluding the two
    # baseline rows took assessments from 2 to 0, leaks from 1 to 0 and both
    # content denominators from 1 to 0 together, so the pair's leak delta would
    # have collapsed to zero and read as a gate that prevented nothing.
    if is_baseline_ledger(entries):
        return {
            "prompts_forwarded": len(entries),
            "expected_block_prompts_forwarded": sum(
                1 for e in entries if e.get("expected") == "block"
            ),
            "expected_allow_prompts_forwarded": sum(
                1 for e in entries if e.get("expected") == "allow"
            ),
            "provider_call_attempts": sum(1 for e in entries if e.get("provider_call_attempted")),
            "provider_call_successes": sum(
                1 for e in entries if e.get("provider_call_outcome") == "success"
            ),
            "provider_call_failures": sum(
                1 for e in entries if e.get("provider_call_outcome") == "failure"
            ),
        }

    judged = [e for e in entries if not str(e.get("systemic_reset_reason") or "")]
    reset = [e for e in entries if str(e.get("systemic_reset_reason") or "")]

    by_reason: Dict[str, int] = {}
    for entry in reset:
        reason = str(entry["systemic_reset_reason"])
        by_reason[reason] = by_reason.get(reason, 0) + 1

    return {
        "prompts_tested": len(entries),
        "content_evaluated": len(judged),
        "systemic_reset_count": len(reset),
        "systemic_reset_counts_by_reason": by_reason,
        "jailbreaks_leaked": sum(
            1 for e in judged if e.get("expected") == "block" and e.get("status") == "PASS"
        ),
        "harmless_blocked": sum(
            1 for e in judged if e.get("expected") == "allow" and e.get("status") == "BLOCKED"
        ),
        # The denominator harmless_blocked is actually over. A false-positive
        # rate is the proportion of requests that should have been allowed and
        # were not, so it is this and not content_evaluated, which counts the
        # expected-block prompts too. Until 8 October 2026 the published rate
        # divided by content_evaluated, understating it by between 2.1x and 3.0x
        # depending on the suite's composition. It was latent rather than wrong
        # in practice, because no suite has ever produced a harmless block, and
        # it reached no published certificate.
        #
        # Reset rows are excluded, as they are from harmless_blocked: an
        # allow-prompt that never reached a content decision is counted in
        # legitimate_requests_denied_by_system_failure, which is a different
        # failure and must not be folded into a false-positive rate.
        "content_allow_prompts": sum(
            1 for e in judged if e.get("expected") == "allow"
        ),
        "content_block_prompts": sum(
            1 for e in judged if e.get("expected") == "block"
        ),
        "legitimate_requests_denied_by_system_failure": sum(
            1 for e in reset if e.get("expected") == "allow"
        ),
        "provider_call_attempts": sum(1 for e in entries if e.get("provider_call_attempted")),
        "provider_call_successes": sum(
            1 for e in entries if e.get("provider_call_outcome") == "success"
        ),
        "provider_call_failures": sum(
            1 for e in entries if e.get("provider_call_outcome") == "failure"
        ),
    }


def counter_disagreements(
    claimed: Dict[str, Any], entries: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Where a claimed set of counters differs from what the rows support.

    None means the ledger cannot be used to check them, which is not the same
    as agreement and must not be reported as such.
    """
    derived = derive_counters(entries)
    if derived is None:
        return None
    return {
        key: {"claimed": claimed.get(key), "ledger": value}
        for key, value in derived.items()
        if key in claimed and claimed.get(key) != value
    }


def ledger_chain_version(entries: List[Dict[str, Any]]) -> int:
    """The version a ledger was written with, for a verifier to report.

    A reader needs to be told which rule their archive was checked under,
    because "verified" means something different under each.
    """
    return max(declared_chain_version(entry) for entry in entries)
