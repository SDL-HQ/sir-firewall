"""The published benchmark indexes satisfy the schemas they are published with.

SIR publishes `spec/benchmark_index.v2.schema.json` as the contract for
`proofs/runs/benchmark_index.v2.json`, and until 15 October 2026 nothing
checked one against the other. The published index had been failing it with 108
errors, two per pair: `tools/publish_run.py` emits the pair's provider-call
counts, its completeness booleans and two further deltas, and the schema
declared none of them while forbidding anything undeclared.

Nothing was wrong with the data. The contract was wrong about it, which is the
same class of defect as a document describing behaviour the code does not have,
and it was found by an independent review rather than by this repository.

Both copies of each index are checked. docs/runs is the published surface a
reader fetches and proofs/runs is the evidence tree, and they are written
separately.

The publisher's own output is checked too, from the pair artefacts on disk. A
test that only validated the committed file would pass for a release in which
the publisher had started emitting something new, right up until the next
benchmark run published it.

Checked on 15 October 2026 against four mutations of a scratch copy, never the
repository. Each count is what pytest reported:

    1. revert the schema additions                         3 failed
    2. publisher emits a new undeclared field              1 failed
    3. the docs copy of the index diverges                 1 failed
    4. the schema itself made invalid                      4 failed

and the restored copy passed 8 of 8. Mutation 4 is the one worth noting: an
invalid schema cannot fail a document, so without the check-schema cases a
broken contract would read as four satisfied ones.

jsonschema became a declared dependency for this file. The published schemas
had no validator in the repository at all, which is how the contract came to
disagree with the artifact it governs.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

INDEXES = (
    ("spec/benchmark_index.v1.schema.json", "proofs/runs/benchmark_index.v1.json"),
    ("spec/benchmark_index.v1.schema.json", "docs/runs/benchmark_index.v1.json"),
    ("spec/benchmark_index.v2.schema.json", "proofs/runs/benchmark_index.v2.json"),
    ("spec/benchmark_index.v2.schema.json", "docs/runs/benchmark_index.v2.json"),
)


def _load(relative_path):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def _errors(schema, document):
    return [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in Draft202012Validator(schema).iter_errors(document)
    ]


@pytest.mark.parametrize("schema_path", sorted({schema for schema, _ in INDEXES}))
def test_each_index_schema_is_itself_a_valid_schema(schema_path):
    """A schema that is not valid cannot fail a document, so it must be checked."""
    Draft202012Validator.check_schema(_load(schema_path))


@pytest.mark.parametrize(("schema_path", "index_path"), INDEXES)
def test_the_published_index_satisfies_its_schema(schema_path, index_path):
    errors = _errors(_load(schema_path), _load(index_path))
    assert not errors, f"{index_path} against {schema_path}:\n" + "\n".join(errors)


def test_both_copies_of_the_v2_index_are_identical():
    """The evidence tree and the published surface must not diverge.

    They are written by two separate calls. If they can differ, a reader
    fetching docs/runs and an operator reading proofs/runs are looking at
    different claims about the same runs.
    """
    assert _load("proofs/runs/benchmark_index.v2.json") == _load(
        "docs/runs/benchmark_index.v2.json"
    )


def test_what_the_publisher_builds_now_satisfies_the_schema():
    """The contract is checked against the code, not only against the file.

    Loaded and called directly rather than through a published artifact, so a
    field the publisher starts emitting fails here before a benchmark run
    publishes it.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "publish_run_for_schema_test", ROOT / "tools" / "publish_run.py"
    )
    assert spec and spec.loader
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)

    runs_dir = ROOT / "proofs" / "runs"
    entries = _load("proofs/runs/benchmark_index.v1.json")["entries"]
    assert entries, "no v1 entries to build from"

    built = publisher._build_benchmark_index_v2(
        runs_dir=runs_dir, runs=entries, pairs_dir=(runs_dir / "pairs")
    )

    errors = _errors(_load("spec/benchmark_index.v2.schema.json"), built)
    assert not errors, "tools/publish_run.py output against its schema:\n" + "\n".join(
        errors
    )
    assert built["pairs"], "the builder produced no pairs, so nothing was checked"
