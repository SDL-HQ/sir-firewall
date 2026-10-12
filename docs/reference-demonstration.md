# Reference demonstration: downstream calls and evaluated content

Item 7 of the 2.4 release. Two claims, two kinds of evidence, two scopes stated
rather than implied. Everything below runs from a clone with no credentials and
no network.

## The claims

**Structural, bounded to SIR's own code.** No code path in SIR can issue a
downstream call unless the gate returned `PASS` and the call flag is enabled.

**Observed, bounded to the paths exercised.** On each failure path listed below
as reachable through the runner, the harness observed zero downstream calls.

**Forwarded content.** The approved request is forwarded byte-for-byte when the
call flag is enabled. The gate's decision was made on its normalised form, which
is a different string in every case measured.

The two scopes are different on purpose. A harness cannot support the word
"all": it only sees the paths it runs, and one unexercised path falsifies a
universal without the harness noticing. The universal comes from the topology
instead. The observation is what shows the topology behaves as read.

## What is not claimed

**An integrator who ignores the verdict.** SIR is input-only and pre-inference.
A caller that catches the exception, or reads `BLOCKED` and calls the model
anyway, is outside both claims, and nothing in SIR can prevent it. This is the
same boundary as the attribution gap: SIR has no actor, user, session or
principal field and observes neither the model's output nor any downstream
action.

**Any path not in the list below.** The paths the runner cannot construct are
named, not omitted.

## Run it

Three commands. Each is self-contained and each prints its own verdict.

```
python3 tools/demonstrate_failure_paths.py
python3 tools/measure_evaluated_versus_forwarded.py
python3 -m pytest tests/test_no_downstream_call_without_approval.py -q
```

The first runs the real runner in live mode with a counterfeit provider client
on the path. Exit 0 means every listed failure path observed zero calls **and**
the positive control fired. Exit 1 means either a failure path attempted a call
or the harness could not see one, and those are reported differently.

The second measures the difference between what the gate evaluated and what is
forwarded. Exit 1 is expected: it reports that two prompts have rule hits in
their raw form that their normalised form does not, both of which are blocked.

The third is the structural test, 25 assertions over the call topology.

No credentials are needed. Live mode refuses to start without `XAI_API_KEY`, so
the harness sets a local dummy value in the subprocess environment only. The
counterfeit client never opens a socket.

## The route to a provider

One choke point, three guards:

```
red_team_suite.py:816   if status == "PASS" and do_model_calls:
red_team_suite.py:826       _maybe_call_model(...)            one caller
red_team_suite.py:539           if not enable: return {...}
red_team_suite.py:543           _call_provider_model(...)     one caller
red_team_suite.py:516/522/530       litellm responses() / completion()
```

`_maybe_call_model` and `_call_provider_model` each have exactly one definition
and exactly one caller. Every litellm invocation is inside the leaf function.
The availability probe in `main()` imports litellm and is asserted never to call
it. And `src/sir_firewall/` imports nothing capable of a network call: not
litellm, not requests, not urllib, not socket. A module that cannot reach the
network cannot make a downstream call on any path, exercised or not.

## Failure paths

The gate returns only `PASS` or `BLOCKED`, so every failure path is a `BLOCKED`
with a reason.

| Path | Reachable through the runner | Calls observed |
|---|---|---:|
| rule match, ordinary `BLOCKED` | yes | 0 |
| `systemic_reset_policy_load_failed` | yes | 0 |
| approved call (positive control) | yes | 1, as required |

Not reachable through the runner, and therefore not observed:

| Path | Why not |
|---|---|
| `malformed_payload` | `_build_isc_envelope` always produces a well-formed envelope, so the runner cannot submit a malformed one. Reachable only by calling the gate directly. |
| `systemic_reset_domain_pack_invalid`, `systemic_reset_domain_pack_load_failed` | every registry entry declares an enforcement pack and a missing one fails at resolution before the first row, so the runner refuses rather than reaching this reason per row. |
| `systemic_reset_internal_error` | the fail-closed wrapper around an otherwise-unhandled exception. Producing it on demand means injecting a fault into the gate, which would be testing the injection. |

All three are covered by the structural claim, because each returns `BLOCKED`
and the guard is false for anything that is not `PASS`.

## Evaluated versus forwarded

Measured over 453 prompts in the eight registry suites.

| | |
|---|---:|
| byte-identical to the text evaluated | **0** |
| differ by case and whitespace folding only | 359 |
| differ substantively | 94 |
| approved prompts differing substantively | 7 of 168 |
| of those, forwarded | 7 |

In those 7 the evaluated string contains the forwarded string: normalisation
added text and removed none. What it added was ` override` five times, ` bypass`
once and ` human oversight` once, which is the non-idempotent marker recovery
recorded in `docs/claims-register.md`. So the gate decided on text it had partly
added. For these 7 that addition did not cause a block, and **whether that is
rule design or luck is not measured.**

Two prompts have the reverse shape, where the evaluated form does not contain
the forwarded one. Both are a base64 wrapper replaced by its decoded payload, so
the wrapper's rule hit disappears because the wrapper did. Both are blocked.

## Reading the harness honestly

Two things in it exist because the first versions were wrong, and they are the
parts worth copying into any similar harness.

**A positive control.** One case is an approved prompt where a call must be
attempted and the counterfeit client must fire. Without it, zero calls on the
failure paths would be indistinguishable from a harness that was not watching.

**A reached-its-path check.** Each failure case declares the reason it expects
to produce, and the harness refuses to report anything if a case did not reach
it. Four successive versions of the policy-load case silently failed to fire:
the corrupted policy was not the file the gate reads, then the gate was loading
from the repository rather than the working tree because
`red_team_suite.py:46` inserts its own directory's `src` at `sys.path[0]`. One
of those versions reported a fail-open defect that did not exist. Zero calls
from a case that never reached its path is not evidence of anything.
