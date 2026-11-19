"""`verify_evidence.py` reports a check as performed only when this run performed it.

Until 19 November 2026 the `signed counters` line read "the signed counters
were recomputed from the rows the certificate binds" whenever the certificate
carried `counters_checked_against_ledger: true` and `verify_certificate.py` had
not returned 11. Every outcome in which the verifier never reached the
counters is also "not 11". Measured on copies of a published archive: with the
ledger taken out, with its last three rows cut, and with the certificate
altered so its payload hash failed, the line said the counters had been
recomputed, over rows nobody read. In the third case `evidence contract` was
also OK, about the fields of a document nobody had authenticated. The verdict
was FAILED each time, correctly. One line was not.

The receipt check had the same kind of gap in the other direction: it
establishes that every file the signed manifest names is unchanged and said
nothing of a file the manifest does not name. That is now a note, and not a
failure.

No published archive showed any of this, so no published line changed.

Breaking this: report `signed counters` established for any certificate code
other than 0.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUN = "20261026-114228-317580-gh40317017323-d8bd37b6606d"
RECOMPUTED = "the signed counters were recomputed from the rows the certificate binds"


@pytest.fixture
def archive(tmp_path):
    source = REPO / "docs" / "runs" / RUN
    if not source.is_dir():
        pytest.skip(f"published archive not present: {source}")
    copy = tmp_path / "archive"
    shutil.copytree(source, copy)
    return copy


def _verify(archive):
    result = subprocess.run([sys.executable, str(REPO / "tools" / "verify_evidence.py"), str(archive), "--json"],
                            capture_output=True, text=True, cwd=REPO)
    report = json.loads(result.stdout)
    return result.returncode, {p["property"]: p for p in report["properties"]}


def test_the_archive_as_published_recomputes_and_says_so(archive):
    code, properties = _verify(archive)
    assert code == 0
    assert properties["signed counters"]["state"] == "established"
    assert properties["signed counters"]["detail"] == RECOMPUTED
    assert properties["archive custody"]["detail"] == "every file named by the signed manifest is present and unchanged"


def test_with_no_ledger_nothing_was_recomputed(archive):
    (archive / "proofs" / "itgl_ledger.jsonl").unlink()
    _, properties = _verify(archive)
    counters = properties["signed counters"]
    assert counters["state"] == "unknown" and RECOMPUTED not in counters["detail"]
    assert "no ledger" in counters["detail"] and "not agreement" in counters["detail"]


def test_with_a_ledger_that_does_not_bind_nothing_was_recomputed(archive):
    ledger = archive / "proofs" / "itgl_ledger.jsonl"
    rows = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join(rows[:-3]) + "\n", encoding="utf-8")
    code, properties = _verify(archive)
    assert code == 2 and properties["certificate"]["state"] == "failed"
    counters = properties["signed counters"]
    assert counters["state"] == "unknown" and RECOMPUTED not in counters["detail"]


def test_a_certificate_that_does_not_verify_is_not_judged_on_its_contents(archive):
    path = archive / "audit.json"
    certificate = json.loads(path.read_text(encoding="utf-8"))
    certificate["model"] = str(certificate.get("model")) + " altered"
    path.write_text(json.dumps(certificate, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    code, properties = _verify(archive)
    assert code == 2 and properties["certificate"]["state"] == "failed"
    assert properties["signed counters"]["state"] == "unknown"
    assert properties["evidence contract"]["state"] == "unknown"
    assert "was not judged" in properties["evidence contract"]["detail"]


def test_a_file_the_manifest_does_not_name_is_named_and_is_not_a_failure(archive):
    (archive / "NOTICE.md").write_text("not named by the manifest\n", encoding="utf-8")
    (archive / "proofs" / "added.txt").write_text("not named by the manifest\n", encoding="utf-8")
    code, properties = _verify(archive)
    custody = properties["archive custody"]
    assert code == 0 and custody["state"] == "established"
    assert "2 file(s) in this directory are not named by the signed manifest" in custody["detail"]
    assert "NOTICE.md" in custody["detail"] and "proofs/added.txt" in custody["detail"]

    receipt = subprocess.run([sys.executable, str(REPO / "tools" / "verify_archive_receipt.py"), str(archive), "--require-registry"],
                             capture_output=True, text=True, cwd=REPO)
    assert receipt.returncode == 0
    lines = receipt.stdout.strip().splitlines()
    assert lines[0].startswith("NOTE: 2 file(s)") and lines[-1].startswith("OK: archive receipt verified")
