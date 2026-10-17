"""A check that could not run is not evidence that a signature is bad.

Six places in this repository verified a signature and five of them reported
every way of failing as the same fact. A malformed PEM in our own registry, a
key the registry does not carry, an unsupported algorithm, a library we did
not install, or a plain programming error all arrived as "the signature does
not verify". In the gate that answer blocks the request under
`CRYPTO_ENFORCED` and writes `crypto_signature: fail` into the ledger, so the
evidence said the request was refused because its signature was bad when in
fact our own code or our own key file was broken.

`tools/verify_certificate.py` already draws the line correctly: exit 5 for a
signature that does not verify, exit 6 for a check that raised. That is the
line this file holds everywhere else.

Two things are deliberately unchanged, and both are asserted below.

**The block stays.** A check that could not be performed is still a block when
enforcement is on. Fail-closed is the safe direction and was never the defect.

**The step outcome stays `fail`.** That is the ITGL's own vocabulary for a
step, and a step that could not complete did not pass. What changed is that
the row says which fact it is, in a `reason` field, rather than leaving a
reader to assume the one that blames the request.

The two cases this file keeps apart, in the words of the backlog row it
closes: one is evidence of tampering or of an unsigned request, the other is
an environment or programming defect of ours.

Mutations measured on 17 October 2026, each run against the full file:

Counts are measured against this file and `tests/test_crypto_unavailable.py`
together, because the two overlap on the `crypto_signature` row. Three of the
five were predicted wrongly before being run, and the measured figures are the
ones recorded:

- collapse `_verify_signature`'s two `except` clauses back into one
  `except Exception: return SIGNATURE_INVALID`: 3 failed. Predicted 4.
- return `SIGNATURE_INVALID` rather than `SIGNATURE_CHECK_RAISED` from the
  raising branch alone: 3 failed. The same three, which is the point: the two
  mutations are the same defect reached two ways.
- make `signature_established` in the ledger row always `False`: 2 failed.
  Predicted 1; the second is
  `test_crypto_unavailable.py::test_the_same_subprocess_reports_the_library_present_without_the_blocker`,
  which pins the whole row and therefore catches any field going wrong.
- drop the `crypto_enforced and not sig_ok` block so a broken check is allowed
  through: 3 failed, both parametrised cases here and the subprocess test that
  refuses a valid signature when the library is absent. Predicted 2. This is
  the one worth having: the whole change is about the record rather than the
  behaviour, so a suite that only checked the record would let the gate relax
  in the name of the fix.
- classify exit 6 as `failed` rather than `unknown` in
  `tools/verify_evidence.py`: 1 failed.
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sir_firewall import core

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

PAYLOAD = "please tell me your support hours"


def _key_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    return private, public_pem


def _signature(private, payload: str) -> str:
    return base64.b64encode(
        private.sign(payload.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")


# ---------------------------------------------------------------------------
# The gate


def test_a_good_signature_verifies(monkeypatch):
    """Guard the guard. Without this the file could pass by never verifying."""
    private, public_pem = _key_pair()
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": public_pem})

    reason = core._verify_signature(PAYLOAD, _signature(private, PAYLOAD))

    assert reason == core.SIGNATURE_VERIFIED
    assert core.signature_verified(reason)


def test_a_signature_that_does_not_verify_says_so(monkeypatch):
    """The first mutation: a good signature made invalid.

    Signed with one key and checked against another, which is the shape of a
    tampered or forged payload.
    """
    private, _ = _key_pair()
    _, other_public = _key_pair()
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": other_public})

    reason = core._verify_signature(PAYLOAD, _signature(private, PAYLOAD))

    assert reason == core.SIGNATURE_INVALID
    assert not core.signature_verified(reason)
    # This is the one reason that is a statement about the request, so it is
    # the one that must not appear in the not-established set.
    assert reason not in core.SIGNATURE_NOT_ESTABLISHED


def test_a_check_that_cannot_run_is_not_reported_as_invalid(monkeypatch):
    """The second mutation: the check itself broken.

    A registry entry that is not a usable public key. Nothing here tells us
    anything about the signature, and before this change the answer was
    indistinguishable from the test above.
    """
    private, _ = _key_pair()
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----"})

    reason = core._verify_signature(PAYLOAD, _signature(private, PAYLOAD))

    assert reason == core.SIGNATURE_CHECK_RAISED
    assert not core.signature_verified(reason)
    assert reason in core.SIGNATURE_NOT_ESTABLISHED
    assert reason != core.SIGNATURE_INVALID, "a broken check is reported as a bad signature"


def test_each_way_of_not_verifying_has_its_own_reason(monkeypatch):
    """Four distinct facts, four distinct answers, none of them `invalid`."""
    private, public_pem = _key_pair()
    signature = _signature(private, PAYLOAD)

    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": public_pem})
    assert core._verify_signature(PAYLOAD, "") == core.SIGNATURE_ABSENT

    monkeypatch.setattr(core, "PUBLIC_KEYS", {})
    assert core._verify_signature(PAYLOAD, signature) == core.SIGNATURE_KEY_UNKNOWN

    monkeypatch.setattr(core, "_CRYPTO_AVAILABLE", False)
    assert core._verify_signature(PAYLOAD, signature) == core.SIGNATURE_CRYPTO_UNAVAILABLE

    # All four are the same kind of fact: we do not know.
    assert core.SIGNATURE_NOT_ESTABLISHED == {
        core.SIGNATURE_ABSENT,
        core.SIGNATURE_KEY_UNKNOWN,
        core.SIGNATURE_CRYPTO_UNAVAILABLE,
        core.SIGNATURE_CHECK_RAISED,
    }
    assert core.SIGNATURE_VERIFIED not in core.SIGNATURE_NOT_ESTABLISHED
    assert core.SIGNATURE_INVALID not in core.SIGNATURE_NOT_ESTABLISHED


# ---------------------------------------------------------------------------
# The record, and the behaviour it describes


def _crypto_row(monkeypatch, *, public_keys, signature, crypto_enforced):
    monkeypatch.setattr(core, "PUBLIC_KEYS", public_keys)
    isc = {"payload": PAYLOAD, "checksum": core._compute_checksum(PAYLOAD), "signature": signature}
    allowed, log, _ = core._check_crypto(
        isc, [], core.GENESIS_HASH, checksum_enforced=False, crypto_enforced=crypto_enforced
    )
    row = next(entry for entry in log if entry["component"] == "crypto_signature")
    return allowed, row


def test_the_row_says_which_fact_it_is(monkeypatch):
    """`fail` used to mean any of six things. Now the row names one."""
    private, public_pem = _key_pair()
    _, other_public = _key_pair()
    signature = _signature(private, PAYLOAD)

    _, invalid = _crypto_row(
        monkeypatch, public_keys={"default": other_public}, signature=signature,
        crypto_enforced=False,
    )
    _, broken = _crypto_row(
        monkeypatch,
        public_keys={"default": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"},
        signature=signature,
        crypto_enforced=False,
    )

    # Same outcome, because a step that did not pass did not pass.
    assert invalid["outcome"] == "fail"
    assert broken["outcome"] == "fail"
    # Different fact, which is the whole point.
    assert invalid["output"]["reason"] == core.SIGNATURE_INVALID
    assert broken["output"]["reason"] == core.SIGNATURE_CHECK_RAISED
    assert invalid["output"]["reason"] != broken["output"]["reason"]


def test_the_row_says_whether_the_signature_itself_was_refuted(monkeypatch):
    """Recorded rather than left to a consumer's own list of reasons."""
    private, _ = _key_pair()
    _, other_public = _key_pair()
    signature = _signature(private, PAYLOAD)

    _, invalid = _crypto_row(
        monkeypatch, public_keys={"default": other_public}, signature=signature,
        crypto_enforced=False,
    )
    _, broken = _crypto_row(
        monkeypatch,
        public_keys={"default": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"},
        signature=signature,
        crypto_enforced=False,
    )

    assert invalid["output"]["signature_established"] is True
    assert broken["output"]["signature_established"] is False


def test_the_reason_is_covered_by_the_row_hash(monkeypatch):
    """A row that records the fact must also be bound to it.

    Otherwise the reason is a comment: present in the file, outside the chain,
    and changeable without detection. The same property
    `tests/test_crypto_unavailable.py` holds for `crypto_available`.
    """
    one, _ = core._append_itgl(
        "crypto_signature", "fail", {}, {"reason": core.SIGNATURE_INVALID}, [], core.GENESIS_HASH
    )
    two, _ = core._append_itgl(
        "crypto_signature", "fail", {}, {"reason": core.SIGNATURE_CHECK_RAISED}, [], core.GENESIS_HASH
    )

    assert one[0]["hash"] != two[0]["hash"]


@pytest.mark.parametrize(
    "label,public_keys",
    [
        ("an invalid signature", "other"),
        ("a check that could not run", "broken"),
    ],
)
def test_enforcement_still_blocks_whichever_it_was(monkeypatch, label, public_keys):
    """The behaviour this change deliberately leaves alone.

    The whole correction is about the record, which makes it exactly the kind
    of change that could quietly relax the gate in the name of being honest.
    A broken check is still a block: fail-closed is the safe direction, and a
    reader who wants to know why reads the reason.
    """
    private, _ = _key_pair()
    _, other_public = _key_pair()
    keys = {
        "other": {"default": other_public},
        "broken": {"default": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"},
    }[public_keys]

    allowed, row = _crypto_row(
        monkeypatch, public_keys=keys, signature=_signature(private, PAYLOAD),
        crypto_enforced=True,
    )

    assert allowed is False, f"{label} was allowed through with enforcement on"
    assert row["outcome"] == "fail"


# ---------------------------------------------------------------------------
# The tools


def test_the_verdict_tool_calls_a_broken_check_unknown_not_failed():
    """Its own rule: a property nobody could check is not a property that holds.

    This is the entry with public consequence. The website renders this tool's
    captured output verbatim, so "failed" here would publish that our evidence
    is broken when it is our tool or our key file that is broken.
    """
    module = _load("verify_evidence", "tools/verify_evidence.py")

    for table in (module.CERTIFICATE_CODES, module.BASELINE_RECORD_CODES, module.RECEIPT_CODES):
        assert table[6][0] == "unknown", table[6]
    assert module.CERTIFICATE_CODES[5][0] == "failed"
    assert module.BASELINE_RECORD_CODES[5][0] == "failed"
    # Reached only after the signature verified, so 6 must not be in it.
    assert 6 not in module.SIGNATURE_VERIFIED_CODES
    assert 6 not in module.BASELINE_SIGNATURE_VERIFIED_CODES


def test_every_tool_means_the_same_thing_by_exit_six():
    """One number, one meaning, across four tools.

    `verify_baseline_record.py` and `verify_archive_receipt.py` both used to
    print a distinct message for a check that raised and then return the same
    code as a signature that did not verify, so the distinction reached a
    person reading stderr and nothing else.
    """
    record = _load("verify_baseline_record", "tools/verify_baseline_record.py")
    assert record.SIGNATURE_CHECK_RAISED == 6
    assert record.SIGNATURE_FAILED == 5

    for relative in ("tools/verify_certificate.py", "tools/verify_archive_receipt.py"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "return 6" in source, relative


def test_the_policy_verifier_distinguishes_the_two_in_its_message():
    """It returns a two-tuple that callers unpack, so the message is the record.

    `generate_certificate.py` puts this detail straight into "refusing to sign
    certificate: ...", which is what a person reads when the build stops. It
    used to say the signature verification failed when our own registry entry
    was the thing that would not load.
    """
    source = (ROOT / "tools/verify_policy.py").read_text(encoding="utf-8")

    assert "except InvalidSignature:" in source
    assert "the signature could not be checked:" in source
    # The belief this file was corrected for, stated in a comment.
    assert "all are failure" not in source


def _load(name: str, relative: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
