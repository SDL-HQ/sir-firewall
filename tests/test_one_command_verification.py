"""One command over one run directory, and what its verdict is allowed to mean.

The documented evaluator procedure was two commands, with a third, the contract
validator, existing and not named in it. Measured against a complete published
archive, that procedure did reject every change, deletion and mismatch tried
against it: whatever ``verify_certificate.py`` missed, the archive receipt
caught. The gap was the rest of the condition, that the evaluator should not
need to know which command closes which gap.

The sharpest instance: passing ``--require-registry`` and omitting it produced
byte-identical stdout and the same exit code, while the assurance kit asked the
evaluator to record "authoritative SDL trust established" in the first case and
not the second. Pointed at an arbitrary public key file with no registry at all,
the verifier printed OK and exited 0, with the key's status never consulted. A
weaker result reported identically to a stronger one is the defect this project
keeps finding in other people's evidence.

So the rules this file holds:

- the registry is the default and opting out changes the verdict, not only the
  prose, so the weaker check cannot be reached by forgetting something
- unknown is neither pass nor fail, and has its own exit code
- absence of evidence is reported rather than skipped, so a missing receipt
  does not reduce the number of properties that had to hold
- the tool never verifies a file the evaluator did not point at
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/verify_evidence.py"

# A complete 2.3.8 archive: certificate, ledger, manifest and receipt all
# present, signed by a key in the approved registry.
COMPLETE_RUN = "20261002-002222-291398-gh36945614280-d321de6346c6"
# A January 2026 archive, before any evidence contract existed.
PRE_CONTRACT_RUN = "20260111-023031-211ac186f758"

ESTABLISHED, NOT_ESTABLISHED, FAILED, UNREADABLE = 0, 1, 2, 3


def _verify(path, *extra):
    result = subprocess.run(
        [sys.executable, str(TOOL), str(path), "--json", *extra],
        cwd=ROOT, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )
    report = json.loads(result.stdout) if result.stdout.strip().startswith("{") else None
    return result.returncode, report, result.stderr


def _state(report, name):
    for entry in report["properties"]:
        if entry["property"] == name:
            return entry["state"]
    raise AssertionError(f"{name} not in {[e['property'] for e in report['properties']]}")


def _detail(report, name):
    for entry in report["properties"]:
        if entry["property"] == name:
            return entry["detail"]
    raise AssertionError(name)


@pytest.fixture
def archive(tmp_path):
    def _copy(run_id=COMPLETE_RUN):
        destination = tmp_path / run_id
        shutil.copytree(ROOT / "docs/runs" / run_id, destination)
        return destination
    return _copy


# --- what it establishes on a real archive -----------------------------------


def test_a_published_archive_establishes_signature_binding_custody_and_contract():
    code, report, _ = _verify(ROOT / "docs/runs" / COMPLETE_RUN)

    assert _state(report, "signing trust") == "established"
    assert _state(report, "certificate") == "established"
    assert _state(report, "archive custody") == "established"
    assert _state(report, "evidence contract") == "established"
    # And one it cannot: this ledger predates the fields the derivation needs.
    assert _state(report, "signed counters") == "unknown"
    assert code == NOT_ESTABLISHED


def test_a_pre_contract_archive_says_so_rather_than_passing_or_failing():
    """219 of the 292 archives published before SIR 2.4.0 are in this position.

    They are not invalid: signature, binding and custody all hold. No evidence
    contract governs their version, which is neither a pass nor a violation.
    """
    code, report, _ = _verify(ROOT / "docs/runs" / PRE_CONTRACT_RUN)

    assert _state(report, "evidence contract") == "unknown"
    assert "no evidence contract governs" in _detail(report, "evidence contract")
    assert code != FAILED


# --- the registry is the default ---------------------------------------------


def test_opting_out_of_the_registry_changes_the_verdict_not_only_the_prose():
    """The defect this tool exists for.

    ``verify_certificate.py`` with and without ``--require-registry`` produced
    identical output and the same exit code. Here the weaker check is reachable
    only by saying so, and saying so is visible in the verdict.
    """
    strict_code, strict, _ = _verify(ROOT / "docs/runs" / COMPLETE_RUN)
    loose_code, loose, _ = _verify(ROOT / "docs/runs" / COMPLETE_RUN, "--allow-unregistered-key")

    assert _state(strict, "signing trust") == "established"
    assert _state(loose, "signing trust") == "unknown"
    assert strict != loose


def test_there_is_no_flag_that_asks_for_the_registry():
    """It cannot be forgotten, because there is nothing to remember."""
    help_text = subprocess.run(
        [sys.executable, str(TOOL), "--help"], cwd=ROOT, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin"},
    ).stdout

    assert "--require-registry" not in help_text
    assert "--allow-unregistered-key" in help_text


# --- unknown is neither pass nor fail ----------------------------------------


def test_a_missing_receipt_is_unknown_and_not_a_failure(archive):
    run = archive()
    (run / "archive_receipt.json").unlink()
    code, report, _ = _verify(run)

    assert _state(report, "archive custody") == "unknown"
    assert code == NOT_ESTABLISHED


def test_a_changed_file_inside_the_archive_is_a_failure(archive):
    """The case ``verify_certificate.py`` passes at exit 0 on its own: a row's
    decision altered, chain fields untouched, under chain version 1."""
    run = archive()
    path = run / "proofs/itgl_ledger.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows[0]["status"] = "PASS" if rows[0].get("status") != "PASS" else "BLOCKED"
    path.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows), encoding="utf-8")

    code, report, _ = _verify(run)

    assert _state(report, "archive custody") == "failed"
    assert code == FAILED


def test_the_verdict_is_the_worst_state_present(archive):
    run = archive()
    (run / "archive_receipt.json").unlink()
    (run / "audit.json").write_text(
        json.dumps({**json.loads((ROOT / "docs/runs" / COMPLETE_RUN / "audit.json").read_text()),
                    "prompts_tested": 1}),
        encoding="utf-8",
    )
    code, report, _ = _verify(run)

    states = {entry["state"] for entry in report["properties"]}
    assert "failed" in states and "unknown" in states
    assert code == FAILED, "a failure beside an unknown is a failure"


# --- it verifies what it was pointed at --------------------------------------


def test_a_run_directory_with_no_ledger_is_not_rescued_by_a_copy_elsewhere(archive):
    """``verify_certificate.py`` can discover a ledger from the signed run id,
    and that discovery resolves against the working directory. A bundle verified
    from inside a repository checkout could therefore have its binding checked
    against the repository's copy of the ledger rather than its own. This tool
    passes an explicit path or none.
    """
    sys.path.insert(0, str(ROOT / "src"))
    from sir_firewall.evidence_paths import canonical_ledger_path

    assert (ROOT / canonical_ledger_path(COMPLETE_RUN)).is_file(), (
        "this test is only meaningful while a copy exists at the canonical path"
    )

    run = archive()
    (run / "proofs/itgl_ledger.jsonl").unlink()
    code, report, _ = _verify(run)

    assert _state(report, "certificate") == "unknown"
    assert "no ledger in this run directory" in _detail(report, "certificate")
    assert code != ESTABLISHED


def test_discovery_prefers_the_ledger_beside_the_certificate(archive):
    """The underlying verifier's order, fixed alongside this tool.

    Pointed at a run directory holding a ledger that does not match, discovery
    must find that one and fail, rather than finding the canonical copy and
    passing.
    """
    run = archive()
    other = ROOT / "docs/runs" / "20261002-030936-161538-gh36958888228-3c39599f5009"
    shutil.copy(other / "proofs/itgl_ledger.jsonl", run / "proofs/itgl_ledger.jsonl")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/verify_certificate.py"), str(run / "audit.json"),
         "--key-registry", str(ROOT / "spec/pubkeys/key_registry.v1.json"), "--require-registry"],
        cwd=ROOT, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert result.returncode == 7, result.stdout + result.stderr


# --- the shape of the thing --------------------------------------------------


def test_a_directory_that_is_not_a_run_is_unreadable(tmp_path):
    code, _, stderr = _verify(tmp_path)

    assert code == UNREADABLE
    assert "no certificate" in stderr


def test_the_four_exit_codes_are_distinct_and_documented():
    docstring = (ROOT / "tools/verify_evidence.py").read_text(encoding="utf-8")

    assert len({ESTABLISHED, NOT_ESTABLISHED, FAILED, UNREADABLE}) == 4
    for code, label in ((0, "ESTABLISHED"), (1, "NOT ESTABLISHED"), (2, "FAILED")):
        assert f"  {code}  {label}" in docstring, label


# --- the SIR 2.3.4 evidence-binding correction -------------------------------
#
# Before 2.3.4, certificate generation took itgl_final_hash from an environment
# variable or a mutable file, so a certificate could sign a hash left by an
# earlier run. docs/evidence-binding-correction.md records it and states that the
# archives were deliberately not re-signed. A verifier that calls those archives
# broken is reporting a documented format boundary as tampering.


def test_the_whole_published_archive_agrees_with_the_boundary_the_correction_states():
    """Every certificate from 2.3.4 onward binds its ledger. Below it, many do not.

    This is the measurement the classification rests on, so it is taken from the
    archive rather than asserted. If a 2.3.4-or-later certificate ever stops
    matching its ledger, that is a real failure and this test is where it
    surfaces.
    """
    corrected_total = corrected_bound = 0
    uncorrected_unbound = 0

    for certificate in sorted((ROOT / "docs/runs").glob("*/audit.json")):
        ledger = certificate.parent / "proofs/itgl_ledger.jsonl"
        if not ledger.is_file():
            continue
        cert = json.loads(certificate.read_text(encoding="utf-8"))
        version = cert.get("sir_firewall_version")
        parsed = (
            tuple(int(part) for part in version.split("."))
            if isinstance(version, str) and version.count(".") == 2 and version[0].isdigit()
            else None
        )
        rows = [
            json.loads(line)
            for line in ledger.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        bound = cert.get("itgl_final_hash") == "sha256:" + rows[-1]["ledger_hash"]
        if parsed is not None and parsed >= (2, 3, 4):
            corrected_total += 1
            corrected_bound += int(bound)
        elif not bound:
            uncorrected_unbound += 1

    assert corrected_total >= 24, corrected_total
    assert corrected_bound == corrected_total, (
        f"{corrected_total - corrected_bound} certificates at or above SIR 2.3.4 do not "
        "match the ledger shipped with them; the correction is supposed to make that "
        "impossible, so this is a real binding failure and not a format boundary"
    )
    assert uncorrected_unbound > 0, (
        "no pre-2.3.4 certificate is unbound, so the classification below is "
        "untested against the archive it exists for"
    )


def test_a_pre_correction_mismatch_is_unknown_rather_than_failed():
    """105 published archives are in this position. None of them is broken."""
    unbound = None
    for certificate in sorted((ROOT / "docs/runs").glob("*/audit.json")):
        ledger = certificate.parent / "proofs/itgl_ledger.jsonl"
        if not ledger.is_file():
            continue
        cert = json.loads(certificate.read_text(encoding="utf-8"))
        version = cert.get("sir_firewall_version")
        if version != "1.0.2":
            continue
        rows = [
            json.loads(line)
            for line in ledger.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if cert.get("itgl_final_hash") != "sha256:" + rows[-1]["ledger_hash"]:
            unbound = certificate.parent
            break

    assert unbound is not None, "no unbound pre-correction archive to check"
    code, report, _ = _verify(unbound)

    assert _state(report, "certificate") == "unknown"
    assert "predates the SIR 2.3.4 evidence-binding correction" in _detail(report, "certificate") or (
        "not fully checked" in _detail(report, "certificate")
    )
    assert code == NOT_ESTABLISHED, "a documented format boundary is not a failure"


def test_a_post_correction_mismatch_is_still_a_failure(archive):
    """The softening above must not reach the certificates the correction covers.

    COMPLETE_RUN is a 2.3.8 archive. Its ledger is replaced with another run's,
    which is a genuine binding failure and must stay one.
    """
    run = archive()
    other = ROOT / "docs/runs" / "20261002-030936-161538-gh36958888228-3c39599f5009"
    shutil.copy(other / "proofs/itgl_ledger.jsonl", run / "proofs/itgl_ledger.jsonl")

    code, report, _ = _verify(run)

    assert _state(report, "certificate") == "failed"
    assert code == FAILED
