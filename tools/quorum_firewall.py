#!/usr/bin/env python
"""
Quorum firewall orchestrator for SIR.

Usage:

    # Basic: single generic pack on the same process
    python tools/quorum_firewall.py isc.json

    # Read ISC from stdin
    cat isc.json | python tools/quorum_firewall.py -

This is a reference implementation showing how to:

    - Run multiple SIR "instances" (here via different Domain ISC packs)
    - Apply strict quorum semantics:
        * If ANY firewall BLOCKS → global BLOCK
        * If ANY firewall emits SR → global BLOCK with SR metadata
        * Only if ALL firewalls PASS and NONE emit SR → global PASS

In a real deployment you would likely:
    - Call remote SIR services over HTTP, or
    - Run separate processes / containers per firewall.
"""

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sir_firewall.sir_firewall import validate_sir  # type: ignore


@dataclass
class FirewallConfig:
    """Minimal config for a firewall participating in the quorum."""
    id: str
    domain_pack: Optional[str] = None  # maps to SIR_ISC_PACK


# Example quorum: two independent "views" using different Domain ISC packs.
# You can extend/replace this with real deployments as needed.
FIREWALLS: List[FirewallConfig] = [
    FirewallConfig(id="sir_generic", domain_pack="generic_safety"),
    # Example for a future specialised pack (kept as commented reference):
    # FirewallConfig(id="sir_clinical_nz", domain_pack="nz_mental_health_clinical"),
]


def load_isc_from_path(path: str) -> Dict[str, Any]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    data = json.loads(raw)
    if "isc" not in data:
        raise ValueError("Input JSON must contain top-level key 'isc'.")
    return data


def run_firewall(config: FirewallConfig, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a single firewall. For this reference implementation we:
      - Set SIR_ISC_PACK (if provided)
      - Call validate_sir()
      - Return the raw SIR result, annotated with firewall id
    """
    original_pack = os.getenv("SIR_ISC_PACK")

    try:
        if config.domain_pack is not None:
            os.environ["SIR_ISC_PACK"] = config.domain_pack

        result = validate_sir(payload)
    finally:
        # Restore env var to avoid bleeding state between calls
        if original_pack is None:
            os.environ.pop("SIR_ISC_PACK", None)
        else:
            os.environ["SIR_ISC_PACK"] = original_pack

    # Annotate with firewall id for debugging
    result["_firewall_id"] = config.id
    result["_domain_pack_effective"] = config.domain_pack
    return result


def aggregate_quorum(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Apply quorum semantics to per-firewall results.

    Rules:
      - If ANY result has sr.sr_triggered == True → global BLOCK with SR.
      - Else if ANY result["status"] != "PASS" → global BLOCK.
      - Else → global PASS.
    """
    global_status = "PASS"
    global_reason = "all_firewalls_passed"
    sr_events: List[Dict[str, Any]] = []
    blocked_events: List[Dict[str, Any]] = []

    for res in results:
        status = res.get("status")
        sr = res.get("sr") or {}
        sr_triggered = bool(sr.get("sr_triggered"))

        if sr_triggered:
            sr_events.append(
                {
                    "firewall_id": res.get("_firewall_id"),
                    "reason": sr.get("sr_reason"),
                    "scope": sr.get("sr_scope"),
                }
            )

        if status != "PASS":
            blocked_events.append(
                {
                    "firewall_id": res.get("_firewall_id"),
                    "status": status,
                    "reason": res.get("reason"),
                }
            )

    if sr_events:
        global_status = "BLOCKED"
        global_reason = "systemic_reset_triggered"
    elif blocked_events:
        global_status = "BLOCKED"
        global_reason = "one_or_more_firewalls_blocked"

    return {
        "status": global_status,
        "reason": global_reason,
        "quorum_size": len(results),
        "decisions": results,
        "sr_events": sr_events,
        "blocked_events": blocked_events,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python tools/quorum_firewall.py <isc.json | ->", file=sys.stderr)
        sys.exit(1)

    isc_path = sys.argv[1]

    try:
        payload = load_isc_from_path(isc_path)
    except Exception as exc:
        print(f"Failed to load ISC payload: {exc}", file=sys.stderr)
        sys.exit(1)

    per_firewall_results: List[Dict[str, Any]] = []
    for fw in FIREWALLS:
        try:
            res = run_firewall(fw, payload)
        except Exception as exc:
            # Treat internal errors as a BLOCK for quorum safety
            res = {
                "status": "BLOCKED",
                "reason": f"internal_error:{exc}",
                "_firewall_id": fw.id,
                "_domain_pack_effective": fw.domain_pack,
            }
        per_firewall_results.append(res)

    aggregated = aggregate_quorum(per_firewall_results)
    print(json.dumps(aggregated, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
