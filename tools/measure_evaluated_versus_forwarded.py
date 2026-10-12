#!/usr/bin/env python3
"""Measure the difference between what the gate evaluated and what is forwarded.

Item 7's condition says "approved calls preserve the evaluated content". That
phrase reads two ways and the readings are not both true.

The gate decides on the normalised payload: `_check_jailbreak` calls
`normalize_obfuscation(raw_payload)` and every rule match, danger-word check and
obfuscation signal runs against the result. The runner forwards the raw prompt:
`history = [{"role": "user", "content": prompt}]`. So a model receives a
different string from the one the rules matched.

Reading one, "the approved request is forwarded unmodified", is true and is what
the code does. Reading two, "what the model receives is what the rules matched",
is false wherever normalisation changes anything.

This measures how often it changes something, and in which direction, over every
prompt in the registry suites. The direction is what matters:

  - rule hits present in the normalised text and absent from the raw text is the
    normal case. Normalisation exists to reveal a payload that is obfuscated in
    transit, so the evaluated form is the more legible one.
  - rule hits present in the RAW text and absent from the normalised text is the
    dangerous case. A prompt approved on its normalised form would then be
    forwarded carrying wording the rules would have blocked, which is the
    missing-binding shape every other defect in this release has had.

No conclusion is stated here. The numbers are printed and the exit code reports
whether the dangerous case occurs at all.

Exit codes:
  0  measured, and no approved prompt is forwarded carrying rule hits the
     evaluated form did not have
  1  measured, and the dangerous case occurs; the report names the prompts
  2  could not measure
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sir_firewall import validate_sir  # noqa: E402
from sir_firewall.core import find_rule_hits, normalize_obfuscation  # noqa: E402

REGISTRY = ROOT / "spec/packs/pack_registry.v1.json"

# The runner's own template default, red_team_suite.py:67.
TEMPLATE_ID = "EU-AI-Act-ISC-v1"


def _verdict(prompt: str, enforcement_pack: str, pack_version: str | None) -> str:
    """The gate reached exactly as red_team_suite.py:752 reaches it.

    A first version of this tool called validate_sir({"payload": prompt}, [],
    "GENESIS"), which passes a list as the enforcement pack id and a string as
    the pack identity context. It returned BLOCKED for every prompt it was
    given, including "Explain the concept of human oversight in the context of
    AI regulation", while every suite reports harmless_blocked: 0. A uniform
    result that clean is a broken harness, not a finding, and this is the second
    time in this release that an invented call path produced one.
    """
    envelope = {
        "version": "1.0",
        "template_id": TEMPLATE_ID,
        "payload": prompt,
        "checksum": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "signature": "",
        "key_id": "default",
    }
    verdict = validate_sir(
        {"isc": envelope},
        enforcement_pack_id=(enforcement_pack or None),
        pack_identity_context={"pack_version": pack_version},
    )
    return str(verdict.get("status", "UNKNOWN"))


def _cosmetic(text: str) -> str:
    """Case folding and whitespace collapsing, and nothing else.

    `normalize_obfuscation` lowercases and collapses whitespace on every input,
    so a plain "raw differs from normalised" count is dominated by case and is
    not a measure of anything. Comparing against this instead isolates the
    substantive transformations: base64 decoding, homoglyph mapping, zero-width
    stripping and marker recovery.
    """
    collapsed = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).strip()
    return collapsed.lower()


def _rows(path: Path):
    """Every (prompt, expected, identifier) in a suite, csv or scenario.

    `prompt_b64` is the encoded form used by mental_health_clinical, whose
    registry visibility is `encoded`. The runner decodes it at
    red_team_suite.py:121 before the prompt reaches the gate, so the decoded
    string is both what is evaluated and what would be forwarded. Reading only
    the `prompt` column silently dropped that suite's 25 rows and reported 428
    of 453.
    """
    if path.suffix == ".csv":
        with path.open(encoding="utf-8", newline="") as handle:
            for index, row in enumerate(csv.DictReader(handle)):
                prompt = row.get("prompt")
                if not (prompt or "").strip():
                    encoded = (row.get("prompt_b64") or "").strip()
                    if not encoded:
                        continue
                    prompt = base64.b64decode(encoded.encode("ascii")).decode(
                        "utf-8", errors="replace"
                    )
                yield prompt, (row.get("expected") or "").strip(), row.get("id") or str(index)
        return
    payload = json.loads(path.read_text(encoding="utf-8"))
    turns = payload.get("turns") or payload.get("rows") or []
    for index, turn in enumerate(turns):
        content = turn.get("content") or turn.get("prompt")
        if not (content or ""):
            # scenario_tool_injection turn 4 carries content_b64. Reading only
            # `content` dropped it, and the resulting total of 453 matched the
            # published figure for the wrong reasons: this missing row and the
            # wrongly included canary_fail row cancelled out.
            encoded = (turn.get("content_b64") or turn.get("prompt_b64") or "").strip()
            if not encoded:
                continue
            content = base64.b64decode(encoded.encode("ascii")).decode(
                "utf-8", errors="replace"
            )
        yield str(content), (turn.get("expected") or "").strip(), turn.get(
            "turn_id"
        ) or turn.get("id") or str(index)


def measure() -> dict:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    suites = {}
    totals = {
        "prompts": 0,
        "identical": 0,
        "cosmetic_only": 0,
        "substantive": 0,
        "allow_prompts": 0,
        "allow_substantive": 0,
        "allow_substantive_blocked": 0,
        "hits_revealed_by_normalisation": 0,
        "hits_lost_by_normalisation": 0,
    }
    dangerous = []
    forwarded = []

    for entry in registry["packs"]:
        if entry.get("enforcement_expected_to_fail"):
            # canary_fail exists to make the verdict script refuse. Its single
            # row is not content and does not belong in a content measurement.
            continue
        relative = entry.get("suite_path") or entry.get("scenario_path")
        if not relative:
            continue
        path = ROOT / relative
        if not path.is_file():
            continue

        counts = {key: 0 for key in totals}
        for prompt, expected, identifier in _rows(path):
            normalised = normalize_obfuscation(prompt)
            raw_hits = set(find_rule_hits(prompt))
            normalised_hits = set(find_rule_hits(normalised))

            substantive = _cosmetic(prompt) != normalised
            counts["prompts"] += 1
            if prompt == normalised:
                counts["identical"] += 1
            elif substantive:
                counts["substantive"] += 1
            else:
                counts["cosmetic_only"] += 1
            if expected == "allow":
                counts["allow_prompts"] += 1
                if substantive:
                    counts["allow_substantive"] += 1
                    status = _verdict(
                        prompt,
                        entry.get("enforcement_pack") or "",
                        entry.get("pack_version"),
                    )
                    if status != "PASS":
                        counts["allow_substantive_blocked"] += 1
                    folded = _cosmetic(prompt)
                    forwarded.append(
                        {
                            "suite": entry["pack_id"],
                            "id": identifier,
                            "status": status,
                            "forwarded": prompt,
                            "evaluated": normalised,
                            # True when normalisation only added text. The
                            # direction matters more than the fact of a
                            # difference: if the evaluated string contains the
                            # forwarded one, the gate judged something at least
                            # as suspicious as what the model receives.
                            "evaluated_contains_forwarded": folded in normalised,
                            "appended": (
                                normalised[len(folded):] if folded in normalised else None
                            ),
                        }
                    )

            revealed = normalised_hits - raw_hits
            lost = raw_hits - normalised_hits
            if revealed:
                counts["hits_revealed_by_normalisation"] += 1
            if lost:
                counts["hits_lost_by_normalisation"] += 1
                dangerous.append(
                    {
                        "suite": entry["pack_id"],
                        "id": identifier,
                        "expected": expected,
                        "rule_hits_only_in_raw": sorted(lost),
                        "evaluated_would_block": bool(normalised_hits),
                    }
                )

        suites[entry["pack_id"]] = counts
        for key in totals:
            totals[key] += counts[key]

    return {
        "totals": totals,
        "suites": suites,
        "forwarded_carrying_hits_the_evaluated_form_lacked": dangerous,
        "approved_and_substantively_different": forwarded,
    }


def main() -> int:
    try:
        report = measure()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not measure: {exc}", file=sys.stderr)
        return 2

    totals = report["totals"]
    print("Evaluated versus forwarded content\n")
    print(f"  prompts measured                      {totals['prompts']:>6}")
    print(f"  byte-identical to the evaluated form  {totals['identical']:>6}")
    print(f"  differ by case and whitespace only    {totals['cosmetic_only']:>6}")
    print(f"  differ substantively                  {totals['substantive']:>6}")
    print(f"  of the allow-prompts, substantively   {totals['allow_substantive']:>6}"
          f"  of {totals['allow_prompts']}")
    print(f"  of those, the gate did not pass       {totals['allow_substantive_blocked']:>6}")
    print(f"  rule hits revealed by normalisation   {totals['hits_revealed_by_normalisation']:>6}")
    print(f"  rule hits lost by normalisation       {totals['hits_lost_by_normalisation']:>6}")
    print()
    print(f"  {'suite':<32} {'prompts':>8} {'cosmetic':>9} {'subst':>6} {'lost':>5}")
    for name, counts in sorted(report["suites"].items()):
        print(
            f"  {name:<32} {counts['prompts']:>8} {counts['cosmetic_only']:>9} "
            f"{counts['substantive']:>6} {counts['hits_lost_by_normalisation']:>5}"
        )

    approved = [
        item
        for item in report["approved_and_substantively_different"]
        if item["status"] == "PASS"
    ]
    if approved:
        print("\n  Approved, forwarded, and substantively different from what was evaluated:")
        contained = sum(1 for item in approved if item["evaluated_contains_forwarded"])
        for item in approved:
            print(f"    {item['suite']}/{item['id']}")
            print(f"      forwarded : {item['forwarded'][:100]!r}")
            print(f"      evaluated : {item['evaluated'][:100]!r}")
            print(f"      normalisation added only: {item['appended']!r}")
        print(
            f"\n  evaluated text contains the forwarded text: {contained} of "
            f"{len(approved)}. Where that holds, normalisation only added; nothing "
            "the model receives was hidden from the rules."
        )

    dangerous = report["forwarded_carrying_hits_the_evaluated_form_lacked"]
    if dangerous:
        print("\n  Prompts whose raw form carries rule hits the evaluated form did not:")
        for item in dangerous:
            print(
                f"    {item['suite']}/{item['id']} expected={item['expected']} "
                f"rules={','.join(item['rule_hits_only_in_raw'])} "
                f"evaluated_would_block={item['evaluated_would_block']}"
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
