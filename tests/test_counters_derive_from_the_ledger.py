"""The published counters are recomputed from the evidence, not asserted beside it.

Until 8 October 2026 the runner counted while it wrote rows, the summary
carried those counts, the certificate signed them, and nothing anywhere
checked one against the other. A number on a signed certificate was a claim
about a run, and the ledger that run produced could say something different
without anything noticing.

Three checks now exist, at the three places a number can stop being true:
the runner derives from the rows it wrote, the generator refuses to sign a
summary the ledger does not support, and the verifier recomputes from the
ledger a certificate binds. The derivation lives in tools/itgl.py so a reader
with the minimal bundle can do the same.
"""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sir_firewall.evidence_paths import canonical_ledger_path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ITGL = _load("itgl_counters", "tools/itgl.py")


def _row(index, status="PASS", expected="allow", reset="", attempted=False, outcome=""):
    return {
        "chain_version": 2,
        "ts": f"2026-10-08T00:00:0{index}Z",
        "prompt_index": index,
        "status": status,
        "expected": expected,
        "systemic_reset_reason": reset,
        "provider_call_attempted": attempted,
        "provider_call_outcome": outcome,
        "final_hash": hashlib.sha256(str(index).encode()).hexdigest(),
    }


MIXED = [
    _row(1),                                                        # clean allow
    _row(2, status="BLOCKED", expected="block"),                    # correct block
    _row(3, status="PASS", expected="block"),                       # a leak
    _row(4, status="BLOCKED", expected="allow"),                    # a harmless block
    _row(5, status="BLOCKED", expected="allow", reset="systemic_reset_policy_load_failed"),
    _row(6, status="BLOCKED", expected="block", reset="systemic_reset_internal_error"),
    _row(7, attempted=True, outcome="success"),
    _row(8, attempted=True, outcome="failure"),
]


def test_the_derivation_matches_what_the_rows_say():
    derived = ITGL.derive_counters(MIXED)
    assert derived == {
        "prompts_tested": 8,
        "content_evaluated": 6,
        "systemic_reset_count": 2,
        "systemic_reset_counts_by_reason": {
            "systemic_reset_policy_load_failed": 1,
            "systemic_reset_internal_error": 1,
        },
        "jailbreaks_leaked": 1,
        "harmless_blocked": 1,
        # The two halves of content_evaluated, added 8 October 2026 with the
        # false-positive denominator. Rows 1, 4, 7 and 8 are allow and judged;
        # rows 2 and 3 are block and judged; rows 5 and 6 are resets and so in
        # neither. tests/test_false_positive_denominator.py covers the rate.
        "content_allow_prompts": 4,
        "content_block_prompts": 2,
        "legitimate_requests_denied_by_system_failure": 1,
        "provider_call_attempts": 2,
        "provider_call_successes": 1,
        "provider_call_failures": 1,
    }


def test_a_legacy_ledger_cannot_be_used_to_check_counters_and_says_so():
    """Absent is unknown, not zero. Returning zeros here would invent a
    disagreement with every archive published before 8 October 2026."""
    legacy = [{"ts": "x", "prompt_index": 1, "status": "PASS", "final_hash": "a"}]
    assert ITGL.derive_counters(legacy) is None
    assert ITGL.counter_disagreements({"prompts_tested": 999}, legacy) is None


def test_disagreement_is_reported_per_field_with_both_values():
    claimed = {"prompts_tested": 8, "harmless_blocked": 0, "jailbreaks_leaked": 1}
    disagreements = ITGL.counter_disagreements(claimed, MIXED)
    assert disagreements == {"harmless_blocked": {"claimed": 0, "ledger": 1}}


def test_fields_the_claim_does_not_mention_are_not_invented():
    """A certificate predating a counter must not be reported as disagreeing
    about it."""
    assert ITGL.counter_disagreements({"prompts_tested": 8}, MIXED) == {}


# ---------------------------------------------------------------------------
# The reader-facing check, end to end against the real verifier.
# ---------------------------------------------------------------------------

def _sign(cert: dict, key) -> dict:
    """The documented scheme: everything except signature and payload_hash."""
    cert = {k: v for k, v in cert.items() if k not in ("signature", "payload_hash")}
    payload = json.dumps(cert, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cert["payload_hash"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    cert["signature"] = base64.b64encode(
        key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    return cert


@pytest.fixture(scope="module")
def signed_world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("counters")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    (tmp / "pub.pem").write_text(pub, encoding="utf-8")
    (tmp / "registry.json").write_text(json.dumps({
        "version": "v1",
        "keys": [{
            "key_id": "ephemeral", "pubkey_pem": pub, "status": "active",
            "created_utc": "2026-01-01T00:00:00Z", "valid_from_utc": "2026-01-01T00:00:00Z",
        }],
    }), encoding="utf-8")

    prev = "GENESIS"
    rows = []
    for row in MIXED:
        row = dict(row)
        row["prev_hash"] = prev
        row["ledger_hash"] = ITGL.compute_ledger_hash(prev, row)
        prev = row["ledger_hash"]
        rows.append(row)
    ledger = tmp / "itgl_ledger.jsonl"
    ledger.write_text(
        "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )

    derived = ITGL.derive_counters(rows)
    base = {
        "sir_firewall_version": "2.3.8",
        "run_id": "20261008-000000-000000-gh1-abc",
        "detached_ledger": True,
        "itgl_final_hash": f"sha256:{rows[-1]['ledger_hash']}",
        "itgl_row_count": len(rows),
        "signing_key_id": "ephemeral",
        # The ledger below is chain version 2, so the verifier requires the
        # contract v4 fields of any certificate bound to it. See
        # tests/test_contract_floor_is_not_self_asserted.py for why the
        # version claimed above does not decide that.
        "configuration_hash": "sha256:" + "0" * 64,
        "counters_checked_against_ledger": True,
        **{k: v for k, v in derived.items() if k != "systemic_reset_counts_by_reason"},
    }
    return tmp, key, ledger, base


def _verify(tmp, cert, ledger, name):
    import subprocess, sys
    path = tmp / name
    path.write_text(json.dumps(cert), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(ROOT / "tools/verify_certificate.py"), str(path),
         "--ledger", str(ledger), "--pubkey", str(tmp / "pub.pem"),
         "--key-registry", str(tmp / "registry.json")],
        capture_output=True, text=True,
    )


def test_an_honest_certificate_verifies(signed_world):
    tmp, key, ledger, base = signed_world
    result = _verify(tmp, _sign(dict(base), key), ledger, "honest.json")
    assert result.returncode == 0, result.stderr


def test_a_signed_counter_the_ledger_does_not_support_is_refused(signed_world):
    """The whole point. The chain is intact, the terminal hash matches, the
    signature is valid, and the certificate still says something the rows do
    not. Before this it verified at exit 0."""
    tmp, key, ledger, base = signed_world
    forged = dict(base)
    forged["harmless_blocked"] = 0          # the run had one
    result = _verify(tmp, _sign(forged, key), ledger, "forged.json")

    assert result.returncode == 11, result.stdout + result.stderr
    assert "counter binding verification failed" in result.stderr
    assert "certificate=0, ledger=1" in result.stderr


def test_hiding_a_leak_is_refused(signed_world):
    tmp, key, ledger, base = signed_world
    forged = dict(base)
    forged["jailbreaks_leaked"] = 0         # the run had one
    result = _verify(tmp, _sign(forged, key), ledger, "noleak.json")
    assert result.returncode == 11
    assert "jailbreaks_leaked" in result.stderr


def test_claiming_content_was_evaluated_when_it_was_not_is_refused(signed_world):
    tmp, key, ledger, base = signed_world
    forged = dict(base)
    forged["content_evaluated"] = forged["prompts_tested"]
    result = _verify(tmp, _sign(forged, key), ledger, "evaluated.json")
    assert result.returncode == 11
    assert "content_evaluated" in result.stderr


# --- the refusal at the point of issue, not only at the point of reading -----
#
# The verifier refusals above catch a disagreeing certificate when someone
# checks it. That is the last line, not the first. A certificate that should
# never have existed should not be signed, because once signed it is in an
# archive and a reader has to be relied upon to run the check.


def _generator_world(tmp_path, monkeypatch, *, summary_overrides):
    """A run whose ledger is chain version 2, so the counters are derivable."""
    monkeypatch.chdir(tmp_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setenv("SDL_PRIVATE_KEY_PEM", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode())

    prev = "GENESIS"
    rows = []
    for row in MIXED:
        row = dict(row)
        row["prev_hash"] = prev
        row["ledger_hash"] = ITGL.compute_ledger_hash(prev, row)
        prev = row["ledger_hash"]
        rows.append(row)
    ledger = canonical_ledger_path("generator-run", tmp_path / "proofs/runs")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(
        "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )

    derived = ITGL.derive_counters(rows)
    summary = {
        "suite_name": "counters-test",
        "suite_path": "missing.csv",
        "suite_hash": "sha256:" + "1" * 64,
        "run_id": "generator-run",
        "ledger_path": str(ledger.relative_to(tmp_path)),
        "proof_class": "FIREWALL_ONLY_AUDIT",
        **{k: v for k, v in derived.items() if k != "systemic_reset_counts_by_reason"},
    }
    summary.update(summary_overrides)
    (tmp_path / "proofs").mkdir(exist_ok=True)
    (tmp_path / "proofs/run_summary.json").write_text(json.dumps(summary), encoding="utf-8")

    spec = importlib.util.spec_from_file_location(
        f"generator_{abs(hash(str(tmp_path)))}", ROOT / "tools/generate_certificate.py"
    )
    assert spec and spec.loader
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    return generator


def test_the_generator_refuses_to_sign_a_summary_the_ledger_does_not_support(
    tmp_path, monkeypatch
):
    generator = _generator_world(
        tmp_path, monkeypatch, summary_overrides={"jailbreaks_leaked": 0}
    )

    with pytest.raises(RuntimeError, match="refusing to sign certificate"):
        generator.main()

    assert not list(tmp_path.glob("proofs/archive/*.json")), (
        "a certificate was written despite the refusal"
    )
    assert not (tmp_path / "proofs/local-audit.json").exists()


def test_the_generator_signs_a_summary_the_ledger_does_support(tmp_path, monkeypatch):
    """The refusal above has to be the disagreement, not the fixture failing."""
    generator = _generator_world(tmp_path, monkeypatch, summary_overrides={})

    generator.main()

    certificates = list(tmp_path.glob("proofs/archive/audit-certificate-*.json"))
    assert len(certificates) == 1, certificates
    cert = json.loads(certificates[0].read_text(encoding="utf-8"))
    assert cert["counters_checked_against_ledger"] is True
    # The ledger is chain version 2, so this certificate is in the era that
    # requires the contract v4 fields however it is read.
    assert cert["content_evaluated"] == ITGL.derive_counters(
        ITGL.load_ledger(canonical_ledger_path("generator-run", tmp_path / "proofs/runs"))
    )["content_evaluated"]
