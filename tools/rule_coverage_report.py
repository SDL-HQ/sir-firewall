#!/usr/bin/env python3
"""Generate read-only rule coverage reports for every registered benchmark pack.

This tool evaluates suite content in memory.  It does not write gate state,
proofs, certificates, or run artefacts. In publication-update mode it also
writes the public machine-readable coverage report.
"""

from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import sys
from pathlib import Path as _Path

# Run directly from a clone without an editable install. The four verifiers in
# this directory already do this; a tool that only works once the package is
# installed makes a test's outcome depend on the ambient environment, which is
# how test_rule_coverage_report came to pass or fail according to whether
# PYTHONPATH happened to be set. tests/test_tools_run_from_a_clone.py holds the
# property for every tool here that imports sir_firewall.
_REPO_ROOT = _Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_Path(__file__).resolve().parent))

from sir_firewall import __version__
import sir_firewall.core as sir_firewall_core
from sir_firewall.core import GENESIS_HASH, _check_jailbreak, normalize_obfuscation
from sir_firewall.deterministic_rules import find_rule_hits


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "spec" / "packs" / "pack_registry.v1.json"
PUBLISHED_JSON = ROOT / "docs" / "coverage.json"
# Where load_domain_pack() looks, resolved from the installed package rather than
# from the repository layout, so this agrees with the runner under any install.
# red_team_suite._isc_pack_path does the same and
# tests/test_runnable_suites.py holds that helper against load_domain_pack.
ISC_PACK_DIR = Path(sir_firewall_core.__file__).resolve().parent / "policy" / "isc_packs"
PUBLIC_STATUSES = frozenset({"active"})
PUBLIC_VISIBILITIES = frozenset({"public", "encoded"})
BEGIN = "BEGIN GENERATED FULL-GATE COVERAGE"
END = "END GENERATED FULL-GATE COVERAGE"

PUBLISHED_LOOKUP_SURFACES = {
    ROOT / "docs" / "latest-run.html": ("coverageByPack", 8),
    ROOT / "docs" / "latest-audit.html": ("coverageByPack", 8),
    ROOT / "docs" / "latest-live-audit.html": ("coverageByPack", 8),
    ROOT / "proofs" / "template.html": ("coverageByPack", 8),
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
        # Evaluability is whether red_team_suite.py can run this suite, so it is
        # derived the way the runner derives it: the registry's enforcement_pack,
        # falling back to the suite's own id when absent, resolved against the
        # directory load_domain_pack() reads.
        #
        # Until 13 October 2026 this used pack_id alone. That matched the runner
        # until the enforcement_pack resolver landed, after which it reported
        # four suites as not runner-evaluable while the runner ran all four:
        # account_recovery_fraud, mental_health_clinical, scenario_injection_chain
        # and scenario_tool_injection, each of which enforces under
        # generic_safety. docs/rule-coverage.md and docs/domain-packs.html
        # published that, along with a sentence saying the runner evaluates no
        # prompt content for those suites, which was false.
        enforcement_pack_id = str(pack.get("enforcement_pack") or "").strip() or pack_id
        enforcement_policy_pack_path = ISC_PACK_DIR / f"{enforcement_pack_id}.json"
        runner_evaluable = enforcement_policy_pack_path.is_file()
        results.append(
            {
                "pack_id": pack_id,
                "pack_version": str(pack.get("version") or ""),
                "status": str(pack.get("status") or ""),
                "visibility": str(pack.get("visibility") or ""),
                # pack_class and maturity are carried so spec/packs/PACKS.md's
                # posture column can be generated rather than retyped.
                "pack_class": str(pack.get("pack_class") or ""),
                "maturity": str(pack.get("maturity") or ""),
                "enforcement_pack": enforcement_pack_id,
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


def build_published_json(
    report: dict[str, Any], *, generated_at: str | None = None
) -> dict[str, Any]:
    """Build the public, machine-readable coverage publication."""
    timestamp = generated_at or datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    records = []
    for pack in public_packs(report):
        records.append(
            {
                "pack_id": pack["pack_id"],
                "pack_version": pack["pack_version"],
                "status": pack["status"],
                "visibility": pack["visibility"],
                "is_public": True,
                "block_row_count": pack["block_rows"],
                "deterministic_rule_covered_count": pack["deterministic_rule_matched"],
                "deterministic_rule_uncovered_row_ids": pack[
                    "deterministic_rule_unmatched_ids"
                ],
                "full_gate_covered_count": pack["full_gate_matched"],
                "full_gate_uncovered_row_ids": pack["full_gate_unmatched_ids"],
            }
        )
    return {
        "generated_at": timestamp,
        "sir_firewall_version": __version__,
        "public_inclusion_policy": {
            "statuses": sorted(PUBLIC_STATUSES),
            "visibilities": sorted(PUBLIC_VISIBILITIES),
            "description": (
                "Includes active registry packs with public or encoded visibility; "
                "draft and internal packs are excluded."
            ),
        },
        "packs": records,
    }


def render_published_json(report: dict[str, Any], *, generated_at: str | None = None) -> str:
    return json.dumps(
        build_published_json(report, generated_at=generated_at),
        indent=2,
        ensure_ascii=False,
    ) + "\n"


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


def render_markdown_region(report: dict[str, Any]) -> str:
    """The markdown table, wrapped in the markers that make it owned.

    docs/rule-coverage.md carried this table by hand until 13 October 2026.
    Nothing generated it and nothing compared it with the generator, which is
    why its runner-evaluability column stayed wrong after the enforcement_pack
    resolver landed: correcting the derivation alone would have left the table
    to be retyped, and the next divergence would have been just as silent.
    """
    return f"<!-- {BEGIN} -->\n{render_markdown(report).rstrip()}\n<!-- {END} -->"


def render_spec_posture_region(report: dict[str, Any]) -> str:
    """The derivable columns of spec/packs/PACKS.md's suite table.

    That table carried six hand-typed columns until 13 October 2026, four of
    them mechanically derivable and two of those measurements. Its own preamble
    said the values were "sourced from the generated report", which was not true
    of any of them: it was typed, and it still marked `account_recovery_fraud`,
    `mental_health_clinical`, `scenario_injection_chain` and
    `scenario_tool_injection` as not runner-evaluable five days after the
    generated surfaces were corrected. A third instance of a published figure
    whose correctness depended on someone remembering to retype it, found by an
    independent review.

    The taxonomy column is deliberately not here. PACKS.md defines taxonomy as a
    readability label that is explicitly "not scores, rankings, or analytics",
    assigned per suite by a person, and no mapping from the suites' own category
    values to those labels is declared anywhere. Generating it would mean this
    tool inventing an editorial judgement and publishing it as derived, which is
    a worse defect than typing it. It stays hand-authored, beside the boundary
    rules that govern it, and a test holds its membership against the registry.
    """
    lines = [
        f"<!-- {BEGIN} -->",
        "| Pack/Scenario | Pack class | Registry posture | Full-gate coverage | Runner evaluability |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for pack in report["packs"]:
        posture = " / ".join(
            part for part in (pack["status"], pack["visibility"], pack["maturity"]) if part
        )
        lines.append(
            f"| `{pack['pack_id']}` | {pack['pack_class']} | {posture} | "
            f"`{pack['full_gate_matched']}/{pack['block_rows']}` | "
            f"{'Runner-evaluable' if pack['runner_evaluable'] else 'Not runner-evaluable'} |"
        )
    lines.append(f"<!-- {END} -->")
    return "\n".join(lines)


def replace_generated(document: str, generated: str) -> str:
    """Rewrite the one generated region in a document, or refuse to touch it.

    The order check exists because the slice arithmetic below is silent when it
    is wrong. With the end marker before the begin marker, a document with
    exactly one of each satisfied every other condition here, and the prefix and
    suffix overlapped: the output kept the text before the end marker, inserted
    the generated block, and then repeated everything between the two markers
    along with both markers themselves. The corruption is a duplication, not a
    deletion. Nothing is lost, which is if anything harder to notice, and a
    corrupted published surface and a correct one are the same kind of file.

    Found by an independent review on 13 October 2026. A later review disputed
    the first version of this paragraph, which said the intervening text was
    deleted. The old function was run against a reversed-marker document and the
    intervening text appeared twice in its output. The check was right and the
    account of what it prevents was not, because it was described rather than
    executed.
    """
    begin_candidates = (f"<!-- {BEGIN} -->", f"// {BEGIN}")
    end_candidates = (f"<!-- {END} -->", f"// {END}")
    begins = [marker for marker in begin_candidates if marker in document]
    ends = [marker for marker in end_candidates if marker in document]
    if len(begins) != 1 or len(ends) != 1:
        raise ValueError("document must contain exactly one generated coverage region")
    begin, end = begins[0], ends[0]
    if document.count(begin) != 1 or document.count(end) != 1:
        raise ValueError("document must contain exactly one generated coverage region")
    begin_at = document.index(begin)
    end_at = document.index(end)
    if end_at < begin_at:
        raise ValueError(
            "generated coverage region markers are in reverse order: the end "
            "marker precedes the begin marker, so the region has no extent and "
            "rewriting it would delete the text between them"
        )
    start = document.rfind("\n", 0, begin_at) + 1
    return document[:start] + generated + document[end_at + len(end) :]


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


def render_published_surfaces(report: dict[str, Any]) -> dict[Path, str]:
    """Every surface's full new content, with nothing written yet.

    Separate from writing because the previous version wrote each surface as it
    rendered the next, starting with coverage.json. A marker error in the fourth
    surface therefore left the first three updated and the rest stale, which is
    a publication set that disagrees with itself and gives no sign of it. Every
    way this can refuse is now reached before the first byte is written.

    This is not atomic and does not claim to be: a failure inside the write loop
    below, such as a full disk, still leaves a partial set. What it removes is
    the predictable case, where the input itself is what makes the run refuse.
    """
    rendered: dict[Path, str] = {PUBLISHED_JSON: render_published_json(report)}

    coverage_doc = ROOT / "docs" / "rule-coverage.md"
    rendered[coverage_doc] = replace_generated(
        coverage_doc.read_text(encoding="utf-8"), render_markdown_region(report)
    )

    domain_path = ROOT / "docs" / "domain-packs.html"
    rendered[domain_path] = replace_generated(
        domain_path.read_text(encoding="utf-8"), render_html_table_body(report)
    )

    spec_path = ROOT / "spec" / "packs" / "PACKS.md"
    rendered[spec_path] = replace_generated(
        spec_path.read_text(encoding="utf-8"), render_spec_posture_region(report)
    )

    for path, (variable_name, indent) in PUBLISHED_LOOKUP_SURFACES.items():
        rendered[path] = replace_generated(
            path.read_text(encoding="utf-8"),
            render_javascript_lookup(report, variable_name, indent),
        )

    return rendered


def update_published_surfaces(report: dict[str, Any]) -> None:
    for path, content in render_published_surfaces(report).items():
        path.write_text(content, encoding="utf-8")


def owned_surfaces() -> set[Path]:
    """Every file update_published_surfaces writes, by resolved path."""
    owned = {
        PUBLISHED_JSON,
        ROOT / "docs" / "rule-coverage.md",
        ROOT / "docs" / "domain-packs.html",
        ROOT / "spec" / "packs" / "PACKS.md",
    }
    owned.update(PUBLISHED_LOOKUP_SURFACES)
    return {path.resolve() for path in owned}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    parser.add_argument("--update-published-surfaces", action="store_true")
    args = parser.parse_args()

    # Refuse to write a bare report over a surface this tool publishes, before
    # doing any work.
    #
    # --json-out and --markdown-out write a whole file. The published surfaces
    # are not whole files: each carries a generated region inside hand-written
    # text, and --update-published-surfaces rewrites just that region. Pointing
    # an out flag at one of them replaces the document with the bare report,
    # destroying the markers, and then publication rendering raises because the
    # region it owns is gone. The destructive write happens first, so the error
    # arrives after the damage.
    #
    # docs/rule-coverage.md was destroyed exactly this way on 12 October 2026,
    # by someone passing it as --markdown-out in the belief that was how the
    # document got regenerated. The generated region landed in the same week and
    # closed the drift; it did not close this, and an independent review found
    # the foot-gun still loaded on 13 October.
    owned = owned_surfaces()
    for flag, target in (("--json-out", args.json_out), ("--markdown-out", args.markdown_out)):
        if target.resolve() in owned:
            parser.error(
                f"{flag} points at {target}, which this tool publishes as a "
                "generated region inside hand-written text. Writing a whole "
                "report there would destroy the document. Use "
                "--update-published-surfaces to refresh the published surfaces, "
                "and give the out flags paths outside them."
            )

    report = build_report(registry_path=args.registry.resolve(), root=ROOT)
    args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    if args.update_published_surfaces:
        update_published_surfaces(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
