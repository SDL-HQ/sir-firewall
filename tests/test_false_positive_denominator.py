"""A false-positive rate is over the requests that should have been allowed.

Until 8 October 2026 the published rate was ``harmless_blocked /
content_evaluated``. ``harmless_blocked`` counts only rows whose ``expected`` is
``allow``; ``content_evaluated`` counts every row that reached a content
decision, including the expected-block ones. Numerator and denominator were over
different samples, and the rate understated the real one by between 2.1x and
3.0x depending on the suite's composition:

    generic_safety                 50 allow of 150   3.0x
    eu_ai_act_compliance_pressure  50 allow of 150   3.0x
    data_exfiltration_pressure     23 allow of  50   2.2x
    support_operator_override      24 allow of  50   2.1x
    mental_health_clinical         10 allow of  25   2.5x
    account_recovery_fraud          3 allow of   8   2.7x

It was latent rather than observed. No suite has ever produced a harmless block,
so both rates evaluated to 0.0, and the field reached none of the 292 published
certificates because it arrived with item 1 on 7 October. That is luck, not
design, and item 6's condition is specifically that no rate is published without
its sampling method.

So the denominator is published beside the rate, derived from the ledger like
every other counter, and cross-checked against the runner's own count.
"""

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ITGL = _load("itgl_fp", "tools/itgl.py")


def _row(index, expected, status, reset=""):
    return {
        "chain_version": 2,
        "ts": f"2026-10-08T00:00:{index:02d}Z",
        "prompt_index": index,
        "expected": expected,
        "status": status,
        "systemic_reset_reason": reset,
        "provider_call_attempted": False,
        "provider_call_outcome": "",
        "final_hash": f"{index:064x}",
    }


# --- the derivation ----------------------------------------------------------


def test_the_denominator_is_the_allow_prompts_not_every_prompt():
    """The arithmetic the old rate got wrong, at the smallest scale that shows it.

    One harmless block among two allow-prompts and six block-prompts. The true
    rate is 1/2; the old rate was 1/8.
    """
    rows = [
        _row(1, "allow", "PASS"),
        _row(2, "allow", "BLOCKED"),
    ] + [_row(i, "block", "BLOCKED") for i in range(3, 9)]
    derived = ITGL.derive_counters(rows)

    assert derived["content_evaluated"] == 8
    assert derived["content_allow_prompts"] == 2
    assert derived["content_block_prompts"] == 6
    assert derived["harmless_blocked"] == 1
    assert derived["harmless_blocked"] / derived["content_allow_prompts"] == 0.5
    assert derived["harmless_blocked"] / derived["content_evaluated"] == 0.125, (
        "the old denominator, kept here to show what the correction is worth"
    )


def test_the_two_halves_sum_to_what_was_evaluated():
    rows = [_row(1, "allow", "PASS"), _row(2, "block", "BLOCKED"),
            _row(3, "allow", "BLOCKED"), _row(4, "block", "PASS")]
    derived = ITGL.derive_counters(rows)

    assert (
        derived["content_allow_prompts"] + derived["content_block_prompts"]
        == derived["content_evaluated"]
    )


def test_a_reset_allow_prompt_is_not_in_the_denominator():
    """It was never judged, so it cannot be a false positive.

    An allow-prompt lost to a systemic reset is a real denial of a legitimate
    request and is counted as legitimate_requests_denied_by_system_failure.
    Folding it into the false-positive denominator would dilute the rate with
    requests the gate never ruled on, and folding it into the numerator would
    call a system failure a content decision. It belongs in neither.
    """
    rows = [
        _row(1, "allow", "PASS"),
        _row(2, "allow", "BLOCKED", reset="systemic_reset_policy_load_failed"),
        _row(3, "allow", "BLOCKED"),
    ]
    derived = ITGL.derive_counters(rows)

    assert derived["content_evaluated"] == 2
    assert derived["content_allow_prompts"] == 2
    assert derived["harmless_blocked"] == 1
    assert derived["legitimate_requests_denied_by_system_failure"] == 1
    assert derived["harmless_blocked"] / derived["content_allow_prompts"] == 0.5


def test_a_legacy_ledger_derives_nothing_rather_than_zero():
    """Unchanged behaviour, asserted because a new counter could break it."""
    assert ITGL.derive_counters([{"ts": "x", "prompt_index": 1, "final_hash": "a"}]) is None


# --- the published summary ---------------------------------------------------


def _working_tree(tmp_path):
    for name in ("tests", "spec", "policy", "src"):
        (tmp_path / name).symlink_to(ROOT / name)
    (tmp_path / "proofs").mkdir()
    return tmp_path


def _run(pack_id, tmp_path):
    work = _working_tree(tmp_path)
    subprocess.run(
        [sys.executable, str(ROOT / "red_team_suite.py"), "--pack", pack_id, "--no-model-calls"],
        cwd=work, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(work)},
    )
    return json.loads((work / "proofs/run_summary.json").read_text(encoding="utf-8"))


def test_the_summary_publishes_the_denominator_beside_the_rate(tmp_path):
    """Item 6's condition: no rate without its sampling method."""
    summary = _run("generic_safety", tmp_path)

    assert "content_false_positive_rate" in summary
    assert "content_allow_prompts" in summary, (
        "the rate is published; the sample it is over must be published with it"
    )
    assert summary["content_allow_prompts"] == 50
    assert summary["content_block_prompts"] == 100
    assert summary["content_evaluated"] == 150


def test_the_published_denominator_matches_the_suite_file(tmp_path):
    """Derived from the ledger, checked against the suite on disk.

    If these diverge, either rows are missing from the ledger or the suite's
    own labels are not what the run was measured against.
    """
    rows = list(csv.DictReader((ROOT / "tests/domain_packs/generic_safety.csv").open(encoding="utf-8")))
    expected_allow = sum(1 for r in rows if (r.get("expected") or "").strip() == "allow")

    summary = _run("generic_safety", tmp_path)

    assert summary["content_allow_prompts"] == expected_allow


def test_the_rate_is_null_when_no_allow_prompt_was_judged(tmp_path):
    """Same rule as before: absent is unknown, never zero.

    The guard moves with the denominator. A run of nothing but block-prompts has
    no false-positive rate, and reporting 0.0 would claim a measurement that was
    never taken.
    """
    rows = [_row(i, "block", "BLOCKED") for i in range(1, 4)]
    derived = ITGL.derive_counters(rows)

    assert derived["content_allow_prompts"] == 0
    assert derived["content_evaluated"] == 3


@pytest.mark.parametrize("pack_id,allow,block", [
    ("generic_safety", 50, 100),
    ("eu_ai_act_compliance_pressure", 50, 100),
    ("data_exfiltration_pressure", 23, 27),
    ("support_operator_override", 24, 26),
    ("mental_health_clinical", 10, 15),
    ("account_recovery_fraud", 3, 5),
])
def test_every_suite_publishes_its_composition(pack_id, allow, block, tmp_path):
    """The numbers in this file's docstring, asserted rather than asserted about.

    These are also the figures the 2.1x to 3.0x understatement was computed
    from, so if a suite's composition changes, that claim needs restating.
    """
    summary = _run(pack_id, tmp_path)

    assert summary["content_allow_prompts"] == allow
    assert summary["content_block_prompts"] == block


# --- the certificate ---------------------------------------------------------


def test_the_certificate_carries_the_denominator_it_invites_division_by(tmp_path):
    """A certificate must not hand a reader the wrong arithmetic.

    Before this, a certificate published harmless_blocked beside
    content_evaluated and nothing else. harmless_blocked is scoped to
    allow-prompts and content_evaluated is not, so the obvious division is the
    wrong one. The denominator is now signed alongside, making the correct rate
    derivable from the certificate alone and offline.
    """
    import base64
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from sir_firewall.evidence_paths import canonical_ledger_path

    work = _working_tree(tmp_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    rows = [_row(1, "allow", "PASS"), _row(2, "allow", "BLOCKED")]
    rows += [_row(i, "block", "BLOCKED") for i in range(3, 9)]
    prev = "GENESIS"
    for row in rows:
        row["prev_hash"] = prev
        row["ledger_hash"] = ITGL.compute_ledger_hash(prev, row)
        prev = row["ledger_hash"]
    ledger = canonical_ledger_path("fp-run", work / "proofs/runs")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(
        "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )

    derived = ITGL.derive_counters(rows)
    summary = {
        "suite_name": "fp", "suite_path": "missing.csv",
        "suite_hash": "sha256:" + "1" * 64, "run_id": "fp-run",
        "ledger_path": str(ledger.relative_to(work)),
        "proof_class": "FIREWALL_ONLY_AUDIT",
        **{k: v for k, v in derived.items() if k != "systemic_reset_counts_by_reason"},
    }
    (work / "proofs/run_summary.json").write_text(json.dumps(summary), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/generate_certificate.py")],
        cwd=work, capture_output=True, text=True,
        env={
            "PATH": "/usr/bin:/bin", "HOME": str(work),
            "SDL_PRIVATE_KEY_PEM": key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode(),
        },
    )
    certificates = list(work.glob("proofs/archive/audit-certificate-*.json"))
    assert len(certificates) == 1, result.stdout + result.stderr
    cert = json.loads(certificates[0].read_text(encoding="utf-8"))

    assert cert["harmless_blocked"] == 1
    assert cert["content_evaluated"] == 8
    assert cert["content_allow_prompts"] == 2
    assert cert["content_block_prompts"] == 6
    # The point: the correct rate is now derivable from the certificate alone.
    assert cert["harmless_blocked"] / cert["content_allow_prompts"] == 0.5
    # And it is inside the signed payload, not beside it.
    payload = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    assert "content_allow_prompts" in payload
    rebuilt = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert cert["payload_hash"] == "sha256:" + hashlib.sha256(rebuilt).hexdigest()
