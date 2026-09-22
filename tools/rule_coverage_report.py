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
import html
import json
import re
from pathlib import Path
from typing import Any, Iterable

from sir_firewall.core import GENESIS_HASH, _check_jailbreak, normalize_obfuscation
from sir_firewall.deterministic_rules import find_rule_hits


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"
PUBLIC_STATUSES = frozenset({"active"})
PUBLIC_VISIBILITIES = frozenset({"public", "encoded"})
BEGIN = "BEGIN GENERATED FULL-GATE COVERAGE"
END = "END GENERATED FULL-GATE COVERAGE"

PUBLISHED_LOOKUP_SURFACES = {
    ROOT / "docs" / "latest-run.html": ("coverageByPack", 8),
    ROOT / "docs" / "latest-audit.html": ("coverageBySuite", 8),
    ROOT / "docs" / "latest-live-audit.html": ("coverageBySuite", 8),
    ROOT / "proofs" / "template.html": ("coverageBySuite", 8),
}


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
        pack_id = str(pack.get("pack_id") or "")
        enforcement_policy_pack_path = (
            root / "src" / "sir_firewall" / "policy" / "isc_packs" / f"{pack_id}.json"
        )
        runner_evaluable = enforcement_policy_pack_path.exists()
        results.append(
            {
                "pack_id": pack_id,
                "status": str(pack.get("status") or ""),
                "visibility": str(pack.get("visibility") or ""),
                "block_rows": len(block_rows),
                "deterministic_rule_matched": len(deterministic_matched),
                "deterministic_rule_unmatched_ids": [row_id for row_id in block_ids if row_id not in deterministic_set],
                "full_gate_matched": len(full_gate_matched),
                "full_gate_unmatched_ids": [row_id for row_id in block_ids if row_id not in full_gate_set],
                "runner_evaluable": runner_evaluable,
                "enforcement_policy_pack_path": str(enforcement_policy_pack_path.resolve())
                if runner_evaluable
                else None,
                "runner_evaluability_reason": (
                    None if runner_evaluable else "missing_enforcement_policy_pack"
                ),
            }
        )

    return {"registry_version": str(registry.get("registry_version") or ""), "packs": results}


def _ids(values: Iterable[str]) -> str:
    rendered = ", ".join(f"`{value}`" for value in values)
    return rendered or "—"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "| Pack | Status | Visibility | Block rows | Deterministic rules | Deterministic unmatched | Full gate | Full-gate unmatched | Runner evaluability |",
        "|---|---|---|---:|---:|---|---:|---|---|",
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
                    "Runner-evaluable" if pack["runner_evaluable"] else "Not runner-evaluable",
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def public_packs(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return packs eligible for public coverage surfaces.

    Public surfaces contain active packs whose registry visibility is either
    ``public`` or ``encoded``. Draft and internal packs are deliberately
    excluded; encoded suite content may still have public aggregate results.
    """
    return [
        pack
        for pack in report["packs"]
        if pack["status"] in PUBLIC_STATUSES
        and pack["visibility"] in PUBLIC_VISIBILITIES
    ]


def render_html_table_body(report: dict[str, Any]) -> str:
    lines = [f"    <!-- {BEGIN} -->"]
    for pack in public_packs(report):
        evaluability = (
            "Runner-evaluable"
            if pack["runner_evaluable"]
            else '<span class="marker">Not runner-evaluable</span>'
        )
        lines.append(
            "      <tr>"
            f"<td><code>{html.escape(pack['pack_id'])}</code></td>"
            f"<td>{html.escape(pack['visibility'])}</td>"
            f"<td><code>{pack['full_gate_matched']}/{pack['block_rows']}</code></td>"
            f"<td>{evaluability}</td>"
            "</tr>"
        )
    lines.append(f"    <!-- {END} -->")
    return "\n".join(lines)


def render_javascript_lookup(report: dict[str, Any], variable_name: str, indent: int) -> str:
    prefix = " " * indent
    entry_prefix = " " * (indent + 2)
    lines = [f"{prefix}// {BEGIN}", f"{prefix}const {variable_name} = {{"]
    packs = public_packs(report)
    for index, pack in enumerate(packs):
        comma = "," if index < len(packs) - 1 else ""
        coverage = f"{pack['full_gate_matched']}/{pack['block_rows']}"
        lines.append(
            f"{entry_prefix}{json.dumps(pack['pack_id'])}: {json.dumps(coverage)}{comma}"
        )
    lines.extend([f"{prefix}}};", f"{prefix}// {END}"])
    return "\n".join(lines)


def replace_generated(document: str, generated: str) -> str:
    begin_candidates = (f"<!-- {BEGIN} -->", f"// {BEGIN}")
    end_candidates = (f"<!-- {END} -->", f"// {END}")
    begins = [marker for marker in begin_candidates if marker in document]
    ends = [marker for marker in end_candidates if marker in document]
    if len(begins) != 1 or len(ends) != 1:
        raise ValueError("document must contain exactly one generated coverage region")
    begin, end = begins[0], ends[0]
    if document.count(begin) != 1 or document.count(end) != 1:
        raise ValueError("document must contain exactly one generated coverage region")
    start = document.rfind("\n", 0, document.index(begin)) + 1
    return document[:start] + generated + document[document.index(end) + len(end) :]


def inject_javascript_lookup(
    document: str, report: dict[str, Any], variable_name: str, indent: int
) -> str:
    """Insert a generated lookup into a source page, or refresh an existing one."""
    generated = render_javascript_lookup(report, variable_name, indent)
    if BEGIN in document or END in document:
        return replace_generated(document, generated)

    pattern = re.compile(
        rf"^(?P<indent>[ \t]*)const\s+{re.escape(variable_name)}\s*=\s*\{{.*?^\s*\}};",
        flags=re.DOTALL | re.MULTILINE,
    )
    matches = list(pattern.finditer(document))
    if len(matches) != 1:
        raise ValueError(f"document must contain exactly one {variable_name} lookup")
    match = matches[0]
    if len(match.group("indent").expandtabs()) != indent:
        raise ValueError(f"unexpected indentation for {variable_name} lookup")
    return document[: match.start()] + generated + document[match.end() :]


def update_published_surfaces(report: dict[str, Any]) -> None:
    domain_path = ROOT / "docs" / "domain-packs.html"
    domain_path.write_text(
        replace_generated(domain_path.read_text(encoding="utf-8"), render_html_table_body(report)),
        encoding="utf-8",
    )
    for path, (variable_name, indent) in PUBLISHED_LOOKUP_SURFACES.items():
        path.write_text(
            replace_generated(
                path.read_text(encoding="utf-8"),
                render_javascript_lookup(report, variable_name, indent),
            ),
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    parser.add_argument("--update-published-surfaces", action="store_true")
    args = parser.parse_args()

    report = build_report(registry_path=args.registry.resolve(), root=ROOT)
    args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    if args.update_published_surfaces:
        update_published_surfaces(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
