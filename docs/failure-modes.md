# Failure modes: when SIR itself fails

This note describes SIR 2.3.4 as implemented, not an availability guarantee.
SIR is a synchronous, deterministic pre-inference library gate: only a returned
verdict is a SIR decision. The distinctions below matter operationally.

## Four different outcomes

1. **Returned `BLOCKED` verdict.** `validate_sir()` completed and returned a
   dictionary whose `status` is `BLOCKED`. The caller must not send that request
   to inference. This is the only outcome that is SIR's own fail-closed
   behaviour.
2. **Exception propagated to the caller.** No verdict was returned. An
   integrator must treat this as unavailable governance and stop the downstream
   call (fail closed), alert, and retain suitable diagnostics. SIR cannot control
   what caller code does after an exception escapes.
3. **Bundled runner process failure.** Request evaluation did not produce a
   request-level verdict; the command exits non-zero (and may print a traceback).
   Automation must treat this as an unsuccessful/inconclusive run, never as a
   passing request or audit.
4. **Integrator-elected continuation.** Caller code may catch an escaped
   exception or ignore a failed process and call a model anyway. That is an
   integrator bypass, not a SIR `PASS`, and SIR cannot prevent or describe that
   downstream disposition from inside the failed call.

## Current 2.3.4 behaviour

| Failure | Actual outcome | Classification |
|---|---|---|
| An otherwise-unhandled `Exception` anywhere in `_validate_sir_impl()` (including `_check_jailbreak()`) | `validate_sir()` returns `BLOCKED`, reason `systemic_reset_internal_error`. Its new ITGL contains component `internal_error` and the exception type; if converting the exception message with `str()` also fails, the message is `<exception message unavailable>`. | Fail closed |
| Domain policy-pack file contains malformed JSON | `_read_domain_pack()` converts `JSONDecodeError` to `DomainPackValidationError`; the gate returns `BLOCKED`, reason `systemic_reset_domain_pack_invalid`. | Fail closed |
| Domain policy pack parses but violates the minimum schema | The schema validator raises `DomainPackValidationError`; the gate returns `BLOCKED`, reason `systemic_reset_domain_pack_invalid`. Required content is a matching non-empty `pack_id`, all built-in templates with positive integer `max_tokens`, and native booleans for all required flags. | Fail closed |
| `spec/packs/pack_registry.v1.json` is absent or malformed | This file is runner/CLI selection metadata, not input to `validate_sir()`. `red_team_suite.py` lets `FileNotFoundError` or `JSONDecodeError` escape and the process fails; the `sir` CLI's registry loader instead reports an error and exits `2`. No request-level reason code applies. | Process failure, not a block |
| `deterministic_rules.py` raises while regexes are compiled | Patterns are compiled at module import, before `validate_sir()` exists or its boundary can run. Import/startup fails and no verdict or reason code exists. | Propagated import exception / process failure |
| A deterministic rule raises while matching | Matching is invoked inside `_check_jailbreak()`, inside the public boundary. The gate returns `BLOCKED`, reason `systemic_reset_internal_error`, with the exception type in the ITGL. | Fail closed |
| A string payload exceeds its selected template's size limit | `_check_payload_size()` runs before checksum and matching. It returns a `BLOCKED` verdict with reason `friction_limit_exceeded`. The limit is `max_tokens * 4` characters and reported token use is ceiling(characters / 4). | Fail closed |
| A non-string payload has a `str()` method that raises | The early size check deliberately skips non-strings; `_check_crypto()` then coerces the payload. The public boundary catches that exception and returns `BLOCKED`, reason `systemic_reset_internal_error`, recording its type. | Fail closed |
| Deeply nested string `structured_request` exhausts Python's recursion limit in `json.loads()` | The structured parser catches `RecursionError`, maps it to type `structured_invalid_json`, and the gate returns `BLOCKED`, reason `structured_validation_failed`. | Fail closed |
| Parsing a string `structured_request` raises in-process `MemoryError` | The same structured parser catches `MemoryError`, maps it to type `structured_invalid_json`, and returns `BLOCKED`, reason `structured_validation_failed`. | Fail closed if Python raises the exception in-process |
| Parsing a string `tool_result` raises in-process `MemoryError` | The tool-result parser catches `MemoryError`, maps it to type `tool_result_invalid_json`, and returns `BLOCKED`, reason `tool_result_validation_failed`. | Fail closed if Python raises the exception in-process |

The determining code paths are small enough to quote:

```python
# public validation boundary
try:
    return _validate_sir_impl(...)
except Exception as exc:
    ...
    return _sr_block("systemic_reset_internal_error", ...)
```

```python
# structured JSON parse boundary
try:
    pairs = json.loads(raw, object_pairs_hook=list)
except (json.JSONDecodeError, RecursionError, MemoryError):
    return None, "structured_invalid_json"
```

The separate tool-result loader has the same exception tuple and returns
`tool_result_invalid_json`; each ingress then uses its own validation reason.

```python
# registry loading in the bundled runner: deliberately outside validate_sir()
with open(path, "r", encoding="utf-8") as f:
    registry = json.load(f)
```

The payload path is likewise ordered: `_check_payload_size()` returns
`friction_limit_exceeded` before `_check_crypto()`, `_check_friction()`, and
`_check_jailbreak()`; `_check_jailbreak()` calls `find_rule_hits(normalized)`.
The regex objects used by that function are created by top-level `re.compile(...)`
expressions in `deterministic_rules.py`, while `core.py` imports its functions at
module load.

## What changed from 2.3.0

The 2.3.0 source and the 2.3.1 hardening diff show three behavioural changes:

| Case | 2.3.0 | 2.3.1 |
|---|---|---|
| Parsed domain pack missing expected top-level content (including `{}`) | No minimum schema was enforced. `pack_id` was inserted with `setdefault`; absent `flags` and `templates` became empty dictionaries, then built-in enforcement flags and friction limits were used. A safe, valid ISC could therefore return `PASS` even though the operator's pack policy was absent. | Minimum schema failure returns `BLOCKED` / `systemic_reset_domain_pack_invalid`. Values are validated rather than silently defaulted or coerced. |
| Malformed domain-pack JSON | `JSONDecodeError` was caught by the broad domain-pack load handler and returned `BLOCKED` / `systemic_reset_domain_pack_load_failed`. | It is classified as an invalid present pack and returns `BLOCKED` / `systemic_reset_domain_pack_invalid`. |
| Unexpected exception during validation or rule matching | There was no outer exception boundary; the exception propagated to the library caller (and ordinarily failed a runner process). | The new public boundary returns `BLOCKED` / `systemic_reset_internal_error` and records exception type and message in a fresh ITGL. |
| `RecursionError` parsing a structured request | Caught and returned `BLOCKED` / `structured_validation_failed`, type `structured_invalid_json`. | Unchanged. |
| `MemoryError` parsing a structured request | Not caught at the parse site and propagated to the caller. | Caught at the parse site and returned `BLOCKED` / `structured_validation_failed`, type `structured_invalid_json`. (The outer boundary would also catch an in-process `MemoryError` arising elsewhere.) |
| Oversized string payload | Returned `BLOCKED` / `friction_limit_exceeded`. | Unchanged. |

The empty-pack path is therefore a dated audit finding, not a timeless claim:
the internal failure-mode audit identified it on **21 September 2026**, and the
2.3.1 hardening commit fixed it that day.

## Boundaries and remaining non-guarantees

- An operating-system or container OOM kill terminates the process without
  giving Python an exception to catch. No in-process block or ITGL is possible.
- `except Exception` intentionally does not catch `BaseException` subclasses
  such as `KeyboardInterrupt` and `SystemExit`; those propagate.
- Import-time failures—including deterministic regex compilation—occur before
  the public boundary is available.
- A malformed or absent benchmark pack registry is a selection/process error,
  not a request-level block. It has no systemic-reset reason code.
- Raw structured JSON is parsed before its extracted request-text length is
  checked. Although recursion and in-process memory exceptions are handled,
  parser CPU and allocation work are not bounded by the 4,000-character
  request-text constraint.
- The structured-request and tool-result JSON parsers catch `JSONDecodeError`,
  `RecursionError`, and `MemoryError` symmetrically. They map parser exhaustion
  to their ingress-specific invalid-JSON type and validation reason; genuinely
  unexpected exceptions still reach the `systemic_reset_internal_error`
  boundary.
- The internal-error ITGL is newly constructed, so partial step history from
  before the unexpected exception is not retained in that returned verdict.
- Library integrators own the final disposition of any exception that escapes
  and of every returned verdict. They must stop inference on failure; SIR cannot
  control an integrator that elects to continue.
