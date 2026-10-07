"""The chain rule has one implementation, and the writer uses the verifier's.

Until 7 October 2026 red_team_suite.py held a private _compute_ledger_hash and
tools/itgl.py held the same rule inside verify_ledger. They agreed because
both were three lines. tools/itgl.py is what ships to a third party in a
minimal verification bundle, so a drift between them would mean our published
archives verify for us and not for a reader, which is the one failure this
project cannot afford.

This matters more from chain_version 2 onward, where the rule stops being
"concatenate two hex strings" and becomes a canonical serialisation over a
field set. Two implementations of that will drift.
"""

import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_runner_uses_the_verifiers_chain_rule_object():
    """Not an equivalent function. The same one.

    The runner is loaded first because importing it is what puts tools/ on
    sys.path and populates sys.modules["itgl"]; comparing against a separately
    loaded copy of the file would compare two different module objects and
    pass even if the runner had its own rule.
    """
    runner = _load("red_team_suite_single_impl", "red_team_suite.py")
    import itgl

    assert runner.compute_ledger_hash is itgl.compute_ledger_hash, (
        "the runner no longer uses tools/itgl.py's chain rule. A second "
        "implementation of the chain is how a published archive comes to "
        "verify for us and not for a reader."
    )


def test_the_runner_does_not_reimplement_the_chain():
    source = (ROOT / "red_team_suite.py").read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in source.splitlines()
        if "sha256" in line and ("prev_hash" in line or "prev_ledger_hash" in line)
    ]
    assert not offenders, (
        "red_team_suite.py appears to compute a chain hash itself: "
        f"{offenders}. Import compute_ledger_hash from tools/itgl.py instead."
    )


def test_what_the_writer_writes_is_what_the_verifier_accepts(tmp_path):
    """The round trip, over the one rule both sides now share."""
    itgl = _load("itgl_round_trip", "tools/itgl.py")

    prev = "GENESIS"
    rows = []
    for index in range(1, 4):
        final_hash = hashlib.sha256(f"row-{index}".encode()).hexdigest()
        ledger_hash = itgl.compute_ledger_hash(prev, final_hash)
        rows.append({
            "ts": f"2026-10-07T00:00:0{index}Z",
            "prompt_index": index,
            "status": "PASS",
            "final_hash": final_hash,
            "prev_hash": prev,
            "ledger_hash": ledger_hash,
        })
        prev = ledger_hash

    path = tmp_path / "itgl_ledger.jsonl"
    path.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows),
        encoding="utf-8",
    )
    head, count = itgl.load_and_verify_ledger(path)
    assert count == 3
    assert head == f"sha256:{rows[-1]['ledger_hash']}"


def test_the_shipped_verifier_stays_standalone():
    """tools/itgl.py goes into minimal bundles that contain no package. It
    must not acquire an import of sir_firewall while being made the single
    source of the rule."""
    source = (ROOT / "tools" / "itgl.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+sir_firewall", source, re.M), (
        "tools/itgl.py imports the package; it would stop working in the "
        "minimal bundle a third party verifies with"
    )
