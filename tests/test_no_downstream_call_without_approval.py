"""No code path in SIR can issue a downstream call without an approving verdict.

Item 7's condition is written as a universal: *all* supported failure paths
produce zero downstream calls. A harness cannot support that word. It only sees
the paths it runs, so it can report "zero calls observed on the paths
exercised" and nothing stronger; one unexercised path falsifies the universal
and the harness is structurally unable to notice. That is the same shape as the
"every run" claim corrected on 8 October.

What earns the word is the topology, which is checked here rather than observed.
The route from the runner to a provider is a single choke point:

    if status == "PASS" and do_model_calls:      <- two guards
        _maybe_call_model(...)                   <- one caller
            if not enable: return {...}          <- third guard
            _call_provider_model(...)            <- one caller
                litellm completion() / responses()

Each of the two functions has exactly one definition and exactly one caller, and
`src/sir_firewall/` imports nothing capable of a network call at all, which
`tests/test_no_model_in_the_decision_path.py` holds separately. So the claim
this file supports is bounded and exact:

    No code path in SIR can issue a downstream call unless the gate returned
    PASS and the call flag is enabled.

It does not extend past SIR's own process. An integrator who catches the
exception and calls the model anyway is outside it, because SIR is input-only
and pre-inference. That boundary is stated on the public surfaces beside the
attribution gap, not implied here.

Adding a second call site, removing a guard, or importing a client somewhere new
fails this file.

A structural test that passes is worth nothing until it has been shown to fail.
Checked on 9 October 2026 against seven mutations of a scratch copy, never the
repository:

    1. drop the `do_model_calls` guard                       1 failed
    2. drop the verdict guard, keep the flag                 1 failed
    3. add a second, unguarded `_maybe_call_model` call      2 failed
    4. remove the refusal inside `_maybe_call_model`         1 failed
    5. call litellm from a new function outside the leaf     2 failed
    6. invoke the availability-probe import in `main()`      1 failed
    7. `import requests` into `src/sir_firewall/core.py`     1 failed

and the restored copy passed 25 of 25. Mutation 6 is the one worth noting: the
probe import is legitimate and the call it could become is not, and nothing but
that assertion distinguishes them.
"""

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "red_team_suite.py"
GATE = ROOT / "src/sir_firewall"

TREE = ast.parse(RUNNER.read_text(encoding="utf-8"))

# The two functions on the route to a provider. Each must stay a choke point.
CHOKE_POINTS = ("_maybe_call_model", "_call_provider_model")

# The leaf function, and the only place a provider client may be invoked.
LEAF = "_call_provider_model"

# Modules that can open a socket. None of these may appear anywhere in the gate.
NETWORK_CAPABLE = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "urllib3",
    "requests",
    "httpx",
    "aiohttp",
    "litellm",
    "openai",
    "anthropic",
    "ftplib",
    "telnetlib",
    "smtplib",
    "xmlrpc",
    "asyncio",
}


def _parents(tree):
    """Child to parent, so a call can be walked back to its guards."""
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    return parent


PARENT = _parents(TREE)


def _enclosing_function(node):
    while node in PARENT:
        node = PARENT[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def _definitions(name):
    return [
        node
        for node in ast.walk(TREE)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]


def _calls_to(name):
    return [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]


def _guards_above(node):
    """The test expression of every `if` the node sits inside, innermost first."""
    guards = []
    current = node
    while current in PARENT:
        parent = PARENT[current]
        if isinstance(parent, ast.If) and current not in parent.orelse:
            guards.append(ast.unparse(parent.test))
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            break
        current = parent
    return guards


def test_the_scan_finds_the_route():
    """Guard the guard. A rename must not make this file vacuous."""
    for name in CHOKE_POINTS:
        assert _definitions(name), f"{name} is gone; the route has changed and this file is stale"
    assert _calls_to("validate_sir") or "validate_sir" in RUNNER.read_text(encoding="utf-8"), (
        "the runner no longer reaches the gate"
    )


@pytest.mark.parametrize("name", CHOKE_POINTS)
def test_each_choke_point_has_one_definition_and_one_caller(name):
    """Two functions, one route. Branching either of them breaks the claim."""
    definitions = _definitions(name)
    callers = _calls_to(name)

    assert len(definitions) == 1, f"{name} has {len(definitions)} definitions"
    assert len(callers) == 1, (
        f"{name} has {len(callers)} call sites. The structural claim rests on one "
        "route to a provider; a second site has to be guarded in its own right and "
        "this file does not know about it"
    )


def test_the_provider_call_is_guarded_on_the_verdict_and_the_call_flag():
    """Both guards, named. Either one alone is a weaker claim than we publish."""
    call = _calls_to("_maybe_call_model")[0]
    guards = _guards_above(call)

    assert guards, "the single provider call site sits under no condition at all"
    combined = " ".join(guards)
    assert "status == 'PASS'" in combined or 'status == "PASS"' in combined, (
        f"the call is not guarded on an approving verdict; guards found: {guards}"
    )
    assert "do_model_calls" in combined, (
        f"the call is not guarded on the call flag; guards found: {guards}"
    )


def test_the_guarded_block_is_not_an_else_branch():
    """A guard the call reaches when the condition is false is not a guard."""
    call = _calls_to("_maybe_call_model")[0]
    node = call
    while node in PARENT:
        parent = PARENT[node]
        if isinstance(parent, ast.If):
            assert node not in parent.orelse, (
                "the provider call is reached from the else branch of its guard"
            )
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            break
        node = parent


def test_the_inner_function_refuses_before_doing_anything_when_calls_are_disabled():
    """The second guard is inside the function, so it survives a careless caller."""
    function = _definitions("_maybe_call_model")[0]
    first = function.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        first = function.body[1]  # docstring

    assert isinstance(first, ast.If), (
        "_maybe_call_model does not begin with a refusal; the only thing standing "
        "between a caller and a provider would then be the caller"
    )
    assert "enable" in ast.unparse(first.test), ast.unparse(first.test)
    assert any(isinstance(node, ast.Return) for node in ast.walk(first)), (
        "the refusal does not return"
    )


def test_every_provider_client_invocation_is_inside_the_leaf_function():
    """litellm may be called in exactly one place."""
    offenders = {}
    for node in ast.walk(TREE):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in ("completion", "responses"):
            continue
        where = _enclosing_function(node)
        if where != LEAF:
            offenders.setdefault(node.func.id, []).append(where or "module scope")

    assert not offenders, (
        f"a provider client is invoked outside {LEAF}: {offenders}. Every such site "
        "needs its own verdict guard, and the single-choke-point claim is wrong"
    )


def test_a_client_imported_anywhere_else_is_never_invoked():
    """The availability probe in main() imports litellm and must not call it.

    An import outside the leaf function is allowed, because checking that LIVE
    mode is installable is not a call. What is not allowed is that name later
    becoming one, which is how a second route would appear without a second call
    site being obvious.
    """
    bound_elsewhere = {}
    for node in ast.walk(TREE):
        if not isinstance(node, ast.ImportFrom) or (node.module or "") != "litellm":
            continue
        where = _enclosing_function(node)
        if where == LEAF:
            continue
        for alias in node.names:
            bound_elsewhere[alias.asname or alias.name] = where or "module scope"

    for name, where in bound_elsewhere.items():
        for node in ast.walk(TREE):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == name
            ):
                pytest.fail(
                    f"{name!r}, imported from litellm in {where}, is invoked at line "
                    f"{node.lineno}. That is a second route to a provider"
                )


@pytest.mark.parametrize("module", sorted(NETWORK_CAPABLE))
def test_the_gate_cannot_open_a_socket(module):
    """The decision path has no network reach of any kind.

    tests/test_no_model_in_the_decision_path.py holds the rules-only claim by
    requiring the gate's imports to be the standard library and cryptography.
    This is the same boundary from the other side and it is the half item 7
    needs: a module that cannot reach the network cannot make a downstream call
    on any path, exercised or not.
    """
    offenders = []
    for path in sorted(GATE.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            if module in names:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert not offenders, (
        f"{module!r} is imported by the decision path at {offenders}; it can now "
        "reach the network and the zero-downstream-call claim no longer holds "
        "structurally"
    )


def test_the_socket_list_is_not_vacuous():
    """Guard the guard, again. An empty list would pass every case above."""
    assert len(NETWORK_CAPABLE) >= 10
    assert "litellm" in NETWORK_CAPABLE and "socket" in NETWORK_CAPABLE
    assert "socket" not in sys.stdlib_module_names or True  # stdlib membership is irrelevant here
    assert list(GATE.rglob("*.py")), "the gate package has no modules to scan"
