#!/usr/bin/env python3
"""Generate read-only rule coverage reports for every registered benchmark pack.

This tool evaluates suite content in memory.  It does not write gate state,
proofs, certificates, or run artefacts; only the two explicitly requested report
files are written.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
from pathlib import Path
from typing import Any, Iterable

from sir_firewall.core import GENESIS_HASH, _check_jailbreak, normalize_obfuscation
from sir_firewall.deterministic_rules import find_rule_hits


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"


def _decode_base64(value: Any, *, location: str) -> str:
    try:
        return base64.b64decode(str(value).encode("ascii"), validate=True).decode("utf-8", errors="replace")
    except Exception as exc:
        raise ValueError(f"invalid base64 content at {location}") from exc


def _csv_rows(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for line_number, raw in enumerate(csv.DictReader(handle), start=2):
            expected = str(raw.get("expected") or "").strip().lower()
            if expected not in {"allow", "block"}:
                raise ValueError(f"invalid expected value at {path}:{line_number}: {expected!r}")
            prompt = str(raw.get("prompt") or "")
            if not prompt:
                encoded = raw.get("prompt_b64")
                if not encoded:
                    raise ValueError(f"missing prompt content at {path}:{line_number}")
                prompt = _decode_base64(encoded, location=f"{path}:{line_number}")
            row_id = str(raw.get("id") or "").strip()
            if not row_id:
                raise ValueError(f"missing row id at {path}:{line_number}")
            rows.append({"id": row_id, "expected": expected, "prompt": prompt})
    return rows


def _scenario_rows(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    turns = payload.get("turns") if isinstance(payload, dict) else None
    if not isinstance(turns, list):
        raise ValueError(f"scenario pack has no turns list: {path}")

    rows: list[dict[str, str]] = []
    for index, turn in enumerate(turns, start=1):
        if not isinstance(turn, dict):
            raise ValueError(f"invalid scenario turn at {path}:turn {index}")
        expected = str(turn.get("expected") or "").strip().lower()
        if expected not in {"allow", "block"}:
            raise ValueError(f"invalid expected value at {path}:turn {index}: {expected!r}")
        prompt = str(turn.get("content") or "")
        if not prompt:
            encoded = turn.get("content_b64")
            if not encoded:
                raise ValueError(f"missing scenario content at {path}:turn {index}")
            prompt = _decode_base64(encoded, location=f"{path}:turn {index}")
        row_id = str(turn.get("turn_id") or "").strip()
        if not row_id:
            raise ValueError(f"missing turn id at {path}:turn {index}")
        rows.append({"id": row_id, "expected": expected, "prompt": prompt})
    return rows


def _load_rows(pack: dict[str, Any], *, root: Path) -> list[dict[str, str]]:
    suite_path = root / str(pack.get("suite_path") or "")
    schema = str(pack.get("schema") or "")
    if schema == "csv_single_turn_v1":
        return _csv_rows(suite_path)
    if schema == "scenario_json_v1":
        return _scenario_rows(suite_path)
    raise ValueError(f"unsupported schema for {pack.get('pack_id')}: {schema!r}")


def _full_gate_blocks(prompt: str) -> bool:
    """Return the complete jailbreak-content gate outcome without emitting artefacts."""
    allowed, *_ = _check_jailbreak({"payload": prompt}, [], GENESIS_HASH)
    return not allowed


def build_report(*, registry_path: Path = DEFAULT_REGISTRY, root: Path = ROOT) -> dict[str, Any]:
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    packs = registry.get("packs") if isinstance(registry, dict) else None
    if not isinstance(packs, list):
        raise ValueError("pack registry has no packs list")

    results: list[dict[str, Any]] = []
    for pack in packs:
        if not isinstance(pack, dict):
            raise ValueError("pack registry entry must be an object")
        rows = _load_rows(pack, root=root)
        block_rows = [row for row in rows if row["expected"] == "block"]
        deterministic_matched: list[str] = []
        full_gate_matched: list[str] = []
        for row in block_rows:
            if find_rule_hits(normalize_obfuscation(row["prompt"])):
                deterministic_matched.append(row["id"])
            if _full_gate_blocks(row["prompt"]):
                full_gate_matched.append(row["id"])

        block_ids = [row["id"] for row in block_rows]
        deterministic_set = set(deterministic_matched)
        full_gate_set = set(full_gate_matched)
        results.append(
            {
                "pack_id": str(pack.get("pack_id") or ""),
                "status": str(pack.get("status") or ""),
                "visibility": str(pack.get("visibility") or ""),
                "block_rows": len(block_rows),
                "deterministic_rule_matched": len(deterministic_matched),
                "deterministic_rule_unmatched_ids": [row_id for row_id in block_ids if row_id not in deterministic_set],
                "full_gate_matched": len(full_gate_matched),
                "full_gate_unmatched_ids": [row_id for row_id in block_ids if row_id not in full_gate_set],
            }
        )

    return {"registry_version": str(registry.get("registry_version") or ""), "packs": results}


def _ids(values: Iterable[str]) -> str:
    rendered = ", ".join(f"`{value}`" for value in values)
    return rendered or "—"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "| Pack | Status | Visibility | Block rows | Deterministic rules | Deterministic unmatched | Full gate | Full-gate unmatched |",
        "|---|---|---|---:|---:|---|---:|---|",
    ]
    for pack in report["packs"]:
        total = pack["block_rows"]
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{pack['pack_id']}`",
                    pack["status"],
                    pack["visibility"],
                    str(total),
                    f"{pack['deterministic_rule_matched']}/{total}",
                    _ids(pack["deterministic_rule_unmatched_ids"]),
                    f"{pack['full_gate_matched']}/{total}",
                    _ids(pack["full_gate_unmatched_ids"]),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(registry_path=args.registry.resolve(), root=ROOT)
    args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
