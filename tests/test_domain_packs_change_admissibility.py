"""The domain packs are not inert, and this demonstrates it.

The published measurement says that across 453 prompts in eight registry suites
under each of six ISC policy packs, no per-prompt status, reason or triggered
rule differs. That is correct, and `docs/threat-model.md` has always scoped it
correctly: it does not establish that the packs are inert, because no registry
prompt exercises what a pack controls.

What nobody had done was demonstrate the other half. "The packs may be doing
exactly what they were built for on inputs nothing here tests" is a sentence a
reader cannot check, and declaring the packs structural while leaving it
unchecked would be one more claim of that kind. This file turns it into a
measurement.

What a pack actually controls, derived from the six files rather than described:
per-template token ceilings and the presence of a structured request schema.
All six carry identical `flags`, and `STRICT_ISC_ENFORCEMENT` is recorded as
having no behavioural meaning, so the ceilings and the schema are the whole
difference. Three distinct ceiling maps across the six packs.

Everything here is derived from the pack files. A ceiling change in a pack
changes what this file sends, so it cannot pass by describing values that have
moved.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _core():
    spec = importlib.util.spec_from_file_location(
        "sir_firewall.core", ROOT / "src" / "sir_firewall" / "core.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runner():
    spec = importlib.util.spec_from_file_location("red_team_suite", ROOT / "red_team_suite.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACK_DIR = ROOT / "src" / "sir_firewall" / "policy" / "isc_packs"


def _packs() -> dict[str, dict]:
    return {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in sorted(PACK_DIR.glob("*.json"))}


def _ceilings(pack: dict) -> dict[str, int]:
    return {
        template_id: int(body["max_tokens"])
        for template_id, body in (pack.get("templates") or {}).items()
    }


def _differing_pairs():
    """Every (template, lower pack, higher pack) the pack files actually declare."""
    packs = _packs()
    pairs = []
    names = sorted(packs)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            left_ceilings, right_ceilings = _ceilings(packs[left]), _ceilings(packs[right])
            for template_id in sorted(set(left_ceilings) & set(right_ceilings)):
                low, high = left_ceilings[template_id], right_ceilings[template_id]
                if low == high:
                    continue
                lower, higher = (left, right) if low < high else (right, left)
                pairs.append((template_id, lower, higher, min(low, high), max(low, high)))
    return pairs


DIFFERING = _differing_pairs()


def test_the_packs_declare_ceilings_that_differ():
    """Guard the guard. With no differing ceiling, everything below is vacuous."""
    assert DIFFERING, (
        "no two ISC policy packs declare a different ceiling for any shared "
        "template, so the packs no longer differ in anything this file can "
        "demonstrate. If that is intended, the structural claim in "
        "docs/threat-model.md and tests/domain_packs/README.md needs rewriting, "
        "not this test deleting"
    )


def test_the_only_declared_difference_between_packs_is_ceilings_and_schema():
    """The narrow claim, asserted rather than described.

    If a pack ever differs in flags as well, the published statement that the
    packs are structural configuration of request shape and size becomes
    incomplete, and this fails rather than the statement going stale.
    """
    packs = _packs()
    distinct_flags = {json.dumps(pack.get("flags") or {}, sort_keys=True) for pack in packs.values()}

    assert len(distinct_flags) == 1, (
        "the packs no longer carry identical flags, so flags are now part of "
        f"what a pack changes and the published claim is incomplete: {sorted(distinct_flags)}"
    )

    varying = {
        "ceilings": len({json.dumps(_ceilings(p), sort_keys=True) for p in packs.values()}),
        "schema": len({bool(p.get("structured_request_schema")) for p in packs.values()}),
    }
    assert varying["ceilings"] > 1 or varying["schema"] > 1, (
        "nothing varies across the packs at all"
    )


@pytest.mark.parametrize(
    "template_id,lower,higher,low,high",
    DIFFERING,
    ids=[f"{t}:{lo}<{hi}" for t, lo, hi, _, _ in DIFFERING],
)
def test_a_request_between_two_packs_ceilings_is_admitted_by_one_and_refused_by_the_other(
    template_id, lower, higher, low, high
):
    """The demonstration. One payload, two packs, two verdicts.

    This is what "the packs are structural configuration" means, stated as an
    observation. The registry corpus contains no prompt near any ceiling, which
    is why the 453-prompt measurement reports no divergence; it is a fact about
    the corpus and not about the packs.
    """
    core, runner = _core(), _runner()

    # Strictly between the two ceilings, so the lower pack must refuse it and
    # the higher must admit it. Size derived from the pack files.
    tokens = (low + high) // 2
    assert low < tokens <= high, (
        f"no token count sits strictly above {low} and at or below {high}"
    )
    payload = "x " * tokens
    assert core._estimate_tokens(payload) == tokens, (
        "the payload is not the size this test intends, so the comparison would "
        "be against a different request than the one described"
    )

    isc = runner._build_isc_envelope(payload, template_id)

    def status(pack_id: str) -> tuple[str, str]:
        verdict = core.validate_sir(
            {"isc": isc},
            enforcement_pack_id=pack_id,
            pack_identity_context={"pack_version": "admissibility-probe"},
        )
        return str(verdict.get("status")), str(verdict.get("reason"))

    higher_status, higher_reason = status(higher)
    lower_status, lower_reason = status(lower)

    assert higher_status == "PASS", (
        f"{higher} declares a ceiling of {high} for {template_id} and refused a "
        f"{tokens}-token request: {higher_status} {higher_reason}"
    )
    assert lower_status == "BLOCKED", (
        f"{lower} declares a ceiling of {low} for {template_id} and admitted a "
        f"{tokens}-token request: {lower_status} {lower_reason}"
    )
    assert lower_reason == "friction_limit_exceeded", (
        f"{lower} refused the request for a reason other than its ceiling, so "
        f"this does not demonstrate the ceiling: {lower_reason}"
    )


def test_no_registry_prompt_comes_near_any_declared_ceiling():
    """Why the 453-prompt measurement reports no divergence.

    The corpus, not the packs, is the reason. Asserted here so the published
    explanation is a measurement rather than a supposition, and so that adding a
    long prompt to a suite surfaces as a change in what the measurement means
    rather than silently altering it.
    """
    core, runner = _core(), _runner()
    registry = json.loads((ROOT / "spec" / "packs" / "pack_registry.v1.json").read_text(encoding="utf-8"))
    smallest = min(
        ceiling for pack in _packs().values() for ceiling in _ceilings(pack).values()
    )

    longest = 0
    for entry in registry["packs"]:
        if str(entry.get("status") or "").strip() != "active":
            continue
        pack_id = entry["pack_id"]
        csv_path = ROOT / "tests" / "domain_packs" / f"{pack_id}.csv"
        json_path = ROOT / "tests" / "scenario_packs" / f"{pack_id}.json"
        if csv_path.is_file():
            _raw, rows = runner._read_suite(str(csv_path))
            prompts = [row["prompt"] for row in rows]
        else:
            prompts = [turn["content"] for turn in runner._read_scenario(str(json_path))["turns"]]
        longest = max([longest] + [core._estimate_tokens(p) for p in prompts])

    assert longest < smallest, (
        f"a registry prompt is {longest} tokens and the smallest declared "
        f"ceiling is {smallest}, so the corpus now does exercise a pack ceiling. "
        "The 453-prompt measurement's explanation in docs/threat-model.md no "
        "longer holds and needs re-measuring, not this assertion relaxing"
    )
