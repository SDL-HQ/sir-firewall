"""What the gate does when the cryptography library is not installed.

``src/sir_firewall/core.py`` imports ``cryptography`` inside a try block and
sets ``_CRYPTO_AVAILABLE = False`` when that fails. ``_verify_signature`` then
returns false without consulting a key, ``_check_crypto`` records the
``crypto_signature`` step as ``fail`` while writing ``crypto_available: false``
into the ITGL row, and the request is blocked when ``CRYPTO_ENFORCED`` is on.

That design is the reason this file exists. A signature step that merely failed
would leave a reader unable to tell a missing library from a bad signature, and
those are different facts about a run: one is an environment defect, the other
is evidence of tampering or of an unsigned request. The row separates them.

Nothing tested any of it. Measured at 86b1a6c on 16 October 2026:
``_CRYPTO_AVAILABLE``, ``crypto_available`` and ``_check_crypto`` appeared in
zero test files, so every property above was established by reading the source,
which in this repository is the same as not established. The ``except``
branch carries ``# pragma: no cover``, and it stays: the branch is exercised
in a subprocess below, which a coverage run of this process does not observe.
The pragma now means "covered elsewhere" rather than "untested", and this note
is the elsewhere.

The real import failure is exercised in a subprocess with a meta-path finder
that refuses ``cryptography``, rather than by setting the module flag, because
setting the flag assumes the thing in question: that a failed import reaches it.
The signed envelope is built in this process, where the library is present, and
handed to the subprocess as data. So the subprocess refuses a **valid**
signature it cannot check, which is the property worth having.

Mutations measured on 16 October 2026, each run against the full file:

- ``_verify_signature`` returns ``True`` instead of ``False`` when
  ``_CRYPTO_AVAILABLE`` is false: 4 failed.
- drop ``crypto_available`` from the ``crypto_signature`` step output:
  4 failed.
- hardcode ``{"crypto_available": True}`` in that step output: 3 failed.
- make the enforced path return ``True`` when the signature is unverified
  (``if crypto_enforced and not sig_ok`` to ``if False and not sig_ok``):
  1 failed.
- remove ``not _CRYPTO_AVAILABLE`` from the ``_verify_signature`` guard:
  ``test_the_flag_short_circuits_before_the_key_is_loaded`` fails (1 failed).
  This one is worth reading. The mutation changes no outcome anywhere, because
  the function wraps its body in ``except Exception`` and the NameError from
  the absent ``load_pem_public_key`` is caught and returned as a failed
  verification. A first draft asserted only the return value and the mutation
  survived. The test now asserts the key is never loaded. The broad except is
  recorded in ``docs/backlog.md``: it is fail-closed and therefore safe, and it
  also means a programming error inside this function reads as an invalid
  signature.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sir_firewall import core

ROOT = Path(__file__).resolve().parents[1]

PACK = {
    "pack_id": "generic_safety",
    "templates": {"EU-AI-Act-ISC-v1": {"max_tokens": 2000}},
    "flags": {
        "STRICT_ISC_ENFORCEMENT": True,
        "CHECKSUM_ENFORCED": True,
        "CRYPTO_ENFORCED": True,
    },
}

PAYLOAD = "Safe request for a summary report."


def _signed_envelope():
    """A genuinely valid signature, built where the library exists."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    signature = base64.b64encode(
        private_key.sign(PAYLOAD.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    isc = {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": PAYLOAD,
        "checksum": hashlib.sha256(PAYLOAD.encode("utf-8")).hexdigest(),
        "signature": signature,
        "key_id": "default",
    }
    return isc, public_pem


PROGRAM = textwrap.dedent(
    """
    import json, sys

    class RefuseCryptography:
        def find_spec(self, name, path=None, target=None):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("cryptography is not installed in this environment")
            return None

    if "--allow-cryptography" not in sys.argv:
        sys.meta_path.insert(0, RefuseCryptography())

    from sir_firewall import core

    request = json.loads(sys.argv[1])
    pack = request["pack"]
    core.load_domain_pack = lambda pack_id=None: pack
    core.PUBLIC_KEYS = {"default": request["public_pem"]}

    out = core.validate_sir({"isc": request["isc"]})
    signature_rows = [
        row for row in out["itgl_log"] if row["component"] == "crypto_signature"
    ]
    print(json.dumps({
        "crypto_available_flag": core._CRYPTO_AVAILABLE,
        "status": out["status"],
        "reason": out.get("reason"),
        "signature_rows": [
            {"outcome": row["outcome"], "output": row["output"]}
            for row in signature_rows
        ],
    }))
    """
)


def _run_subprocess(isc, public_pem, *, crypto_enforced, block=True):
    pack = json.loads(json.dumps(PACK))
    pack["flags"]["CRYPTO_ENFORCED"] = crypto_enforced
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    request = json.dumps({"isc": isc, "public_pem": public_pem, "pack": pack})
    argv = [sys.executable, "-c", PROGRAM, request]
    if not block:
        argv.append("--allow-cryptography")
    completed = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _run_without_cryptography(isc, public_pem, *, crypto_enforced):
    return _run_subprocess(isc, public_pem, crypto_enforced=crypto_enforced, block=True)


# --- the import guard itself -------------------------------------------------


def test_a_failed_import_leaves_the_module_usable_with_the_flag_false():
    isc, public_pem = _signed_envelope()

    result = _run_without_cryptography(isc, public_pem, crypto_enforced=False)

    assert result["crypto_available_flag"] is False


def test_the_same_subprocess_reports_the_library_present_without_the_blocker():
    """Guard the harness. A subprocess broken some other way would also say False."""
    isc, public_pem = _signed_envelope()

    allowed = _run_subprocess(isc, public_pem, crypto_enforced=True, block=False)

    assert allowed["crypto_available_flag"] is True
    assert allowed["status"] == "PASS"
    assert allowed["signature_rows"] == [
        {
            "outcome": "pass",
            "output": {
                "crypto_available": True,
                "reason": core.SIGNATURE_VERIFIED,
                "signature_established": True,
            },
        }
    ]


# --- enforced: fail closed ---------------------------------------------------


def test_a_valid_signature_is_refused_when_the_library_is_absent():
    """Fail closed. The signature is good; nothing here can establish that."""
    isc, public_pem = _signed_envelope()

    result = _run_without_cryptography(isc, public_pem, crypto_enforced=True)

    assert result["status"] == "BLOCKED"
    assert result["reason"] == "invalid_signature_or_checksum"
    assert result["signature_rows"] == [
        {
            "outcome": "fail",
            "output": {
                "crypto_available": False,
                # The row names the environment defect rather than leaving a
                # reader to infer it from a bare `fail`.
                "reason": core.SIGNATURE_CRYPTO_UNAVAILABLE,
                "signature_established": False,
            },
        }
    ]


def test_the_same_envelope_passes_where_the_library_is_present(monkeypatch):
    """The refusal above is the missing library and nothing else."""
    isc, public_pem = _signed_envelope()
    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: PACK)
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": public_pem})

    out = core.validate_sir({"isc": isc})

    assert out["status"] == "PASS"


# --- unenforced: disclosed rather than blocked -------------------------------


def test_an_absent_library_is_recorded_rather_than_enforced_when_off():
    isc, public_pem = _signed_envelope()

    result = _run_without_cryptography(isc, public_pem, crypto_enforced=False)

    assert result["status"] == "PASS"
    assert result["signature_rows"] == [
        {
            "outcome": "fail",
            "output": {
                "crypto_available": False,
                # The row names the environment defect rather than leaving a
                # reader to infer it from a bare `fail`.
                "reason": core.SIGNATURE_CRYPTO_UNAVAILABLE,
                "signature_established": False,
            },
        }
    ]


# --- the field earns its place ------------------------------------------------


def test_the_row_separates_an_absent_library_from_an_unverified_signature(monkeypatch):
    """Both are `fail`. The field is the only thing that tells them apart."""
    isc, public_pem = _signed_envelope()

    absent = _run_without_cryptography(isc, public_pem, crypto_enforced=False)

    unsigned = dict(isc, signature="")
    monkeypatch.setattr(core, "load_domain_pack", lambda pack_id=None: PACK)
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": public_pem})
    out = core.validate_sir({"isc": unsigned})
    present = [
        {"outcome": row["outcome"], "output": row["output"]}
        for row in out["itgl_log"]
        if row["component"] == "crypto_signature"
    ]

    assert absent["signature_rows"][0]["outcome"] == "fail"
    assert present[0]["outcome"] == "fail"
    assert absent["signature_rows"][0]["output"] == {
        "crypto_available": False,
        "reason": core.SIGNATURE_CRYPTO_UNAVAILABLE,
        "signature_established": False,
    }
    # The envelope here carries no signature at all, so the library being
    # present is not the point: what separates the two rows now is the reason
    # itself. Before this change both said `fail` and a reader had to infer
    # the difference from `crypto_available`, which is the inference this test
    # existed to make possible and no longer has to.
    assert present[0]["output"] == {
        "crypto_available": True,
        "reason": core.SIGNATURE_ABSENT,
        "signature_established": False,
    }
    assert (
        absent["signature_rows"][0]["output"]["reason"] != present[0]["output"]["reason"]
    ), "the two facts share a reason, which is what this test refuses"


def test_the_flag_short_circuits_before_the_key_is_loaded(monkeypatch):
    """The guard must be reached, not merely produce the same answer.

    This was the sharpest test in the file when the function returned a
    boolean. `_verify_signature` wraps its body in `except Exception`, so
    dropping `not _CRYPTO_AVAILABLE` from the guard still returned false: the
    NameError from the absent `load_pem_public_key` was caught and read as a
    failed verification. The outcome was identical and the mutation invisible
    to any assertion about the return value, so this asserts the key is never
    loaded, which the guard has to exist to achieve.

    Since the function returns a reason rather than a boolean, that mutation
    is also visible in the return value: without the guard the answer becomes
    `check_raised` rather than `crypto_unavailable`, which is the honest
    description of a NameError and a different fact. Measured on 17 October
    2026. The loaded-key assertion stays anyway, because it holds the stronger
    property and does not depend on the reason vocabulary staying as it is.
    """
    _, public_pem = _signed_envelope()
    loaded = []
    monkeypatch.setattr(core, "_CRYPTO_AVAILABLE", False)
    monkeypatch.setattr(core, "PUBLIC_KEYS", {"default": public_pem})
    monkeypatch.setattr(
        core, "load_pem_public_key", lambda *a, **k: loaded.append(1), raising=False
    )

    assert (
        core._verify_signature(PAYLOAD, "c2lnbmF0dXJl", key_id="default")
        == core.SIGNATURE_CRYPTO_UNAVAILABLE
    )
    assert loaded == [], "the key was loaded after the library was reported absent"


def test_the_crypto_available_field_is_covered_by_the_row_hash(monkeypatch):
    """A row that records the fact must also be bound to it."""
    monkeypatch.setattr(core, "_CRYPTO_AVAILABLE", False)
    log, prev = core._append_itgl("crypto_signature", "fail", {}, {"crypto_available": False}, [], core.GENESIS_HASH)
    other, _ = core._append_itgl("crypto_signature", "fail", {}, {"crypto_available": True}, [], core.GENESIS_HASH)

    assert log[0]["hash"] != other[0]["hash"]
    assert prev == log[0]["hash"]
