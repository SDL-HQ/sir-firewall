"""The gate's decision path contains no model, no embedding and no scoring.

"Deterministic and explainable (rules-only; no embeddings, no hidden scoring)"
is on the README and was, until this file, an argument rather than a check. The
claims register's condition is that a claim survives a reader who goes looking
for the failures, and the way a reader would check this one is to ask what the
deciding code imports.

So the import set is derived from the source rather than listed. If a model
client, a numeric library or anything that could compute a similarity score is
ever imported into ``src/sir_firewall/``, the claim stops being true and this
file fails, instead of the claim quietly going stale on a public surface.

``litellm`` is a real dependency of this repository and is deliberately not a
dependency of the gate: it is declared in the ``live`` extra and imported at
three call sites in ``red_team_suite.py``, all of them after the gate has
decided. That separation is the claim, and it is asserted below in both
directions.
"""

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "src/sir_firewall"

# The gate may import these and nothing else from outside the standard library.
# cryptography verifies the signing key's own signature inside core.py.
PERMITTED_THIRD_PARTY = {"cryptography"}

# Anything that could make a decision the rules did not make. Not exhaustive by
# intent: the equality assertion below is what actually holds the boundary, and
# this list exists so the failure message names the problem.
MODEL_OR_SCORING = {
    "openai",
    "anthropic",
    "litellm",
    "transformers",
    "sentence_transformers",
    "torch",
    "tensorflow",
    "jax",
    "flax",
    "keras",
    "sklearn",
    "scipy",
    "numpy",
    "pandas",
    "gensim",
    "spacy",
    "nltk",
    "faiss",
    "chromadb",
    "pinecone",
    "tiktoken",
    "onnxruntime",
    "joblib",
    "xgboost",
    "lightgbm",
}


def _modules():
    return sorted(path for path in GATE.rglob("*.py") if path.is_file())


def _imports(path: Path) -> set:
    """Every top-level module name imported anywhere in a file.

    Walked statically, so an import inside a function or guarded by a try block
    is found too. That is the point: a lazily imported model client is still a
    model client in the decision path.
    """
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative, inside the gate
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        found |= {name for name in names if name}
    return found


def _third_party() -> dict:
    found = {}
    for path in _modules():
        for name in _imports(path):
            if name in sys.stdlib_module_names or name == "sir_firewall":
                continue
            found.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    return found


def test_the_scan_finds_the_deciding_code():
    """Guard the guard. A move or a rename must not make this file vacuous."""
    paths = {str(path.relative_to(ROOT)) for path in _modules()}

    assert "src/sir_firewall/deterministic_rules.py" in paths, sorted(paths)
    assert "src/sir_firewall/core.py" in paths, sorted(paths)
    assert len(paths) >= 6, sorted(paths)


def test_the_gate_imports_nothing_beyond_the_standard_library_and_cryptography():
    third_party = _third_party()
    unexpected = {
        name: sorted(files)
        for name, files in third_party.items()
        if name not in PERMITTED_THIRD_PARTY
    }

    assert not unexpected, (
        "the gate's decision path now imports something outside the standard "
        "library and cryptography. The README claims rules-only with no "
        "embeddings and no hidden scoring; either this import does not decide "
        f"anything and belongs outside the package, or the claim is now wrong: {unexpected}"
    )


@pytest.mark.parametrize("package", sorted(MODEL_OR_SCORING))
def test_no_model_client_or_scoring_library_reaches_the_gate(package):
    """Named individually so a failure says which one and where."""
    sites = _third_party().get(package)

    assert not sites, (
        f"{package!r} is imported by the decision path at {sorted(sites or [])}; "
        "a rules-only gate cannot import something that scores"
    )


def test_the_model_client_is_declared_as_an_extra_and_not_as_a_dependency():
    """The separation is structural, not only conventional."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    required = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    extras = text.split("[project.optional-dependencies]", 1)[1].split("\n[", 1)[0]

    for client in ("litellm", "openai"):
        assert client not in required, (
            f"{client} is a required dependency; installing the gate must not "
            "install a model client"
        )
        assert client in extras, f"{client} should be declared in the live extra"


def test_the_model_client_is_imported_only_after_the_gate_has_decided():
    """Guard the guard, from the other side.

    If this stops finding litellm in the suite, either LIVE mode has gone or the
    import has moved, and the claim about where the model sits needs re-reading
    rather than trusting.
    """
    suite = _imports(ROOT / "red_team_suite.py")

    assert "litellm" in suite, (
        "the suite no longer imports a model client; the claim that the model "
        "sits downstream of the gate rather than inside it needs re-checking"
    )
    assert "litellm" not in _third_party(), "and it must still be absent from the gate"
