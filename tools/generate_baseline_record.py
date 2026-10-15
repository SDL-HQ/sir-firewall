#!/usr/bin/env python3
"""Issue the signed record of an ungated baseline run.

A baseline runs a prompt set with the SIR gate out of the path. Nothing decides
the prompts, so there is no verdict to report and no audit outcome to compute.
Until SIR 2.5 such a run was described by an audit certificate, which has both:
54 were published recording AUDIT FAILED under proof classes naming firewall
activity. docs/archive-errata.md E7 records them, and
tools/generate_certificate.py now refuses the ledger of such a run outright.

This tool issues the document that replaces it. The record says one thing: a
named prompt set was forwarded to a named provider with nothing deciding on it,
and this is what came back at the transport level. Its contract is
spec/baseline_record.v1.schema.json.

What it refuses, and why each refusal is here rather than left to a reader:

- a summary that is not a baseline's. A gated run has a certificate.
- a summary still carrying gate counters. The runner removes them; a summary
  that has them did not come from a baseline run, whatever it says about its
  role.
- a ledger that is not a baseline ledger by tools/itgl.py's classification.
  The rows decide what this run was, not the summary's own account of itself.
- counters that disagree with the rows. The record's counters are recomputed
  here and recomputed again by the verifier, so the number in the document is
  never the only place the number exists.

Output:
  proofs/baseline.json            the signed record
  OUTPUT_BASELINE_JSON=<path>     on stdout, for the caller to archive

Exit codes: 0 on success; any refusal raises, which exits non-zero with the
reason on stderr.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from document_signing import sign_document  # noqa: E402
from itgl import (  # noqa: E402
    BASELINE_ROW_VERSION,
    CHAIN_VERSION_V2,
    baseline_ledger_defects,
    derive_counters,
    load_and_verify_ledger,
    load_ledger,
)

RECORD_KIND = "sir_ungated_baseline"
RECORD_VERSION = 1

SUMMARY_PATH = Path("proofs/run_summary.json")
RECORD_PATH = Path("proofs/baseline.json")

# Gate counters. The runner removes every one of these from a baseline summary,
# so their presence means this summary did not come from a baseline run.
GATE_COUNTERS_IN_SUMMARY = (
    "jailbreaks_leaked",
    "harmless_blocked",
    "content_evaluated",
    "content_allow_prompts",
    "content_block_prompts",
    "content_false_positive_rate",
    "systemic_reset_count",
    "legitimate_requests_denied_by_system_failure",
    "configuration_hash",
    "configurations_observed",
    "proof_class",
)

COUNTER_FIELDS = (
    "prompts_forwarded",
    "expected_block_prompts_forwarded",
    "expected_allow_prompts_forwarded",
    "provider_call_attempts",
    "provider_call_successes",
    "provider_call_failures",
)


def _sir_firewall_version() -> str:
    try:
        import sir_firewall  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "sir_firewall must be installed from the current checkout before generating evidence"
        ) from exc
    version = str(getattr(sir_firewall, "__version__", "")).strip()
    if not version:
        raise RuntimeError("installed sir_firewall package does not expose __version__")
    return version


def _git_commit_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, cwd=_REPO_ROOT
        ).strip()
    except Exception:
        return ""


def _load_summary(path: Path) -> Dict[str, Any]:
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"{path} not found; run the baseline before issuing its record") from exc
    if not isinstance(summary, dict):
        raise RuntimeError(f"{path} is not a JSON object")
    return summary


def _require_baseline_summary(summary: Dict[str, Any]) -> None:
    execution = summary.get("benchmark_execution")
    execution = execution if isinstance(execution, dict) else {}
    if execution.get("gate_mode") != "ungated" or execution.get("benchmark_role") != "baseline":
        raise RuntimeError(
            "refusing to issue a baseline record: this run summary does not describe an "
            f"ungated baseline (benchmark_execution={execution!r}). A gated run is "
            "described by an audit certificate."
        )

    present = [field for field in GATE_COUNTERS_IN_SUMMARY if field in summary]
    if present:
        raise RuntimeError(
            "refusing to issue a baseline record: this run summary carries gate counters "
            f"{present}, which a baseline run does not produce. The summary and the run "
            "disagree about what happened."
        )


def build_record(summary: Dict[str, Any], *, ledger_rows, ledger_path: str) -> Dict[str, Any]:
    """The record's signed fields, in the order they are signed in."""
    counters = derive_counters(ledger_rows)
    if counters is None or sorted(counters) != sorted(COUNTER_FIELDS):
        raise RuntimeError(
            "refusing to issue a baseline record: the ledger's counters could not be "
            f"recomputed as a baseline's (got {sorted(counters) if counters else None})"
        )

    claimed = summary.get("baseline_forwarding")
    if not isinstance(claimed, dict):
        raise RuntimeError(
            "refusing to issue a baseline record: the run summary carries no "
            "baseline_forwarding counters"
        )
    disagreements = {
        field: {"summary": claimed.get(field), "ledger": counters[field]}
        for field in COUNTER_FIELDS
        if claimed.get(field) != counters[field]
    }
    if disagreements:
        raise RuntimeError(
            "refusing to issue a baseline record: the summary's counters are not "
            f"supported by the ledger it binds: {json.dumps(disagreements, sort_keys=True)}"
        )
    if counters["provider_call_successes"] + counters["provider_call_failures"] != counters[
        "provider_call_attempts"
    ]:
        raise RuntimeError(
            "refusing to issue a baseline record: the provider call outcomes do not "
            f"partition the attempts: {json.dumps(counters, sort_keys=True)}"
        )

    terminal_hash, row_count = load_and_verify_ledger(Path(ledger_path), CHAIN_VERSION_V2)

    scenario_hash = str(summary.get("scenario_hash") or "").strip()
    suite_hash = str(summary.get("suite_hash") or "").strip()
    if scenario_hash:
        prompt_set_hash, prompt_set_hash_kind = scenario_hash, "scenario_hash"
    elif suite_hash:
        prompt_set_hash, prompt_set_hash_kind = suite_hash, "suite_hash"
    else:
        raise RuntimeError(
            "refusing to issue a baseline record: the run summary carries no prompt-set hash, "
            "so the record could not be paired with a gated run"
        )

    repository = os.getenv("GITHUB_REPOSITORY", "SDL-HQ/sir-firewall")
    ci_run_id = os.getenv("GITHUB_RUN_ID", "").strip()
    ci_run_url = (
        f"https://github.com/{repository}/actions/runs/{ci_run_id}"
        if repository and ci_run_id
        else ""
    )

    record: Dict[str, Any] = {
        "record_kind": RECORD_KIND,
        "record_version": RECORD_VERSION,
        "run_id": str(summary.get("run_id") or "").strip(),
        "timestamp_utc": str(summary.get("timestamp_utc") or summary.get("date") or "").strip(),
        "sir_firewall_version": _sir_firewall_version(),
        "commit_sha": (os.getenv("GITHUB_SHA", "").strip() or _git_commit_sha()),
        "repository": repository,
        "ci_run_url": ci_run_url,
        "mode": "live",
        "provider": str(summary.get("provider") or "").strip(),
        "model": str(summary.get("model") or "").strip(),
        "pack_id": str(summary.get("pack_id") or "").strip(),
        "pack_version": str(summary.get("pack_version") or "").strip(),
        "suite_path": str(summary.get("suite_path") or "").strip(),
        "prompt_set_hash": prompt_set_hash,
        "prompt_set_hash_kind": prompt_set_hash_kind,
        "ledger": {
            "path": str(ledger_path),
            "chain_version": CHAIN_VERSION_V2,
            "row_version": BASELINE_ROW_VERSION,
            "row_count": row_count,
            "itgl_final_hash": terminal_hash,
        },
        "counters": {field: counters[field] for field in COUNTER_FIELDS},
        "signing_key_id": (os.getenv("SDL_SIGNING_KEY_ID") or "default").strip() or "default",
    }
    if summary.get("scenario_id"):
        record["scenario_id"] = str(summary["scenario_id"])

    # Fields that have to carry something. commit_sha, repository and
    # ci_run_url are provenance and may be empty on a local run, exactly as on
    # a certificate, where they gate publication as the canonical latest rather
    # than issuance. pack_version is empty for a prompt set that declares none.
    required_non_empty = (
        "run_id",
        "timestamp_utc",
        "sir_firewall_version",
        "mode",
        "provider",
        "model",
        "pack_id",
        "suite_path",
        "prompt_set_hash",
        "prompt_set_hash_kind",
        "signing_key_id",
    )
    empty = [field for field in required_non_empty if not str(record.get(field) or "").strip()]
    if empty:
        raise RuntimeError(
            f"refusing to issue a baseline record: these fields are empty: {empty}"
        )
    return record


def main(summary_path: str | None = None) -> int:
    private_key_pem = os.environ.get("SDL_PRIVATE_KEY_PEM")
    if not private_key_pem:
        raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

    summary = _load_summary(Path(summary_path or SUMMARY_PATH))
    _require_baseline_summary(summary)

    ledger_path = str(summary.get("ledger_path") or "").strip()
    if not ledger_path:
        raise RuntimeError("refusing to issue a baseline record: the summary names no ledger")

    rows = load_ledger(Path(ledger_path))
    defects = baseline_ledger_defects(rows)
    if defects:
        raise RuntimeError(
            "refusing to issue a baseline record: "
            f"{ledger_path} is not a baseline ledger: " + "; ".join(defects[:5])
        )

    record = sign_document(
        build_record(summary, ledger_rows=rows, ledger_path=ledger_path), private_key_pem
    )

    RECORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    RECORD_PATH.write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"OK: Wrote baseline record -> {RECORD_PATH}")
    print(f"OUTPUT_BASELINE_JSON={RECORD_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
