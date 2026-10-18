"""No tracked text file carries a CRLF, in a repository whose premise is signed bytes.

`.gitattributes` sets `* -text`, so git performs no line-ending conversion in
either direction and a clone lands byte for byte on every platform. That rule
protects a checkout. It does not protect a commit: with conversion disabled,
an editor that writes CRLF commits CRLF, and from then on the bytes that get
hashed are different bytes.

Why that matters here rather than being a style preference. `publish_run.py`
hashes whatever it finds in a run directory into `manifest.json` and signs the
manifest. `verify_archive_receipt.py` reads those files back and compares.
`core.py` computes `rules_hash` from `deterministic_rules.py` with
`read_bytes()`, so the configuration identity carried by every published
certificate is a hash of that file's bytes. A CRLF added to any of them
changes a digest that something already signed.

Binary files are skipped, and finding out why took running the first version
rather than reading it. A bare carriage return is not the property: it fails
immediately on `docs/assets/StructuralDesignLabs_Logo.png`, which carries a
`0x0D` byte at random like any compressed file will. The check is therefore
`\\r\\n` in files with no NUL byte, which is git's own binary heuristic. A
version of this test asserting "no CR anywhere" would have been wrong on the
day it was written, and would have been fixed by exempting a file rather than
by correcting the property.

Measured when this landed: 6,209 tracked files, one containing a CR and it is
the logo, zero containing a CRLF in a text file. So the property held before
the guard existed, and the guard is holding a line rather than describing a
cleanup.

The two tests are deliberately separate. The first is the property. The second
guards the guard: if the file list ever comes back empty, "no file contains a
CRLF" is vacuously true and passes while checking nothing, which is the same
failure this project refuses everywhere else.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def test_no_tracked_text_file_carries_a_crlf() -> None:
    """A CRLF changes the bytes that manifests and the rule hash cover."""
    offenders = []
    for name in _tracked_files():
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in content:
            # Binary by git's own heuristic; a 0x0D byte in it means nothing.
            continue
        if b"\r\n" in content:
            offenders.append(name)

    assert offenders == [], (
        "tracked text files carry a CRLF, which changes the bytes that "
        "manifests, archive receipts and the configuration hash are computed "
        f"over: {offenders[:10]}"
    )


def test_the_file_list_is_not_empty() -> None:
    """Guard the guard: an empty list makes the check above vacuously true."""
    tracked = _tracked_files()
    assert len(tracked) > 1000, (
        "git ls-files returned too few files for the CRLF check to mean "
        f"anything: {len(tracked)}"
    )
