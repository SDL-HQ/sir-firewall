"""The key registry is valid against the schema published beside it.

Both files are in the minimal verification bundle the README lists, and until
19 November 2026 nothing held one to the other. The registry as published
failed its own schema three ways: `last_trusted_run_id`, added on 6 October,
was a property the schema forbade, and the schema pinned two sentences of
`x_verifier_expectations` to the timestamp rule that was replaced that day
because it could be defeated. The schema was a second copy of the rule's text,
and it was the copy nobody updated.

The schema now says a rule is stated; the registry states it.
"""

import json
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[1]
REGISTRY = REPO / "spec" / "pubkeys" / "key_registry.v1.json"
SCHEMA = REPO / "spec" / "pubkeys" / "key_registry.v1.schema.json"


def _errors(registry):
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return [f"{list(e.path)}: {e.message[:120]}" for e in Draft202012Validator(schema).iter_errors(registry)]


def test_the_committed_registry_is_valid():
    assert _errors(json.loads(REGISTRY.read_text(encoding="utf-8"))) == []


def test_the_schema_still_refuses_what_it_should():
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    registry["keys"][0]["a_field_nobody_declared"] = True
    assert any("a_field_nobody_declared" in e for e in _errors(registry))
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    registry["keys"][0]["anchored_payload_hashes"] = ["not a hash"]
    assert _errors(registry)
