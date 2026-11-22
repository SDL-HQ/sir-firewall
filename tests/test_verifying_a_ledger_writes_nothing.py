"""Verifying a ledger writes nothing, and the hash file a publisher archives is its ledger's.

Until 21 November 2026 `tools/verify_itgl.py` wrote `proofs/itgl_final_hash.txt`
beneath the directory it was run from, every time. That file is tracked here
and published beside the root ledger. So a reader who verified an archived
ledger from a checkout left that ledger's terminal hash in a tracked file that
describes a different run, as a side effect of checking something.

The write is now asked for, with `--write-hash PATH`, by every publishing step
that archives the file.

How many such steps there are is derived from the tree and not listed here. A
hand-typed list of the publishing steps is a second copy of which steps
publish, and nothing compared it to the tree: the first version of this test
named three, the repository had four, and the fourth was
`.github/workflows/r1-cli-acceptance.yml`, which archived the checkout's hash
file on every run. Its first run after `publish_run.py` learned to compare
refused it, which is the comparison working and the enumeration not.

Requiring the flag does not by itself make a forgotten one fail closed, and
that was measured and not assumed. The file is tracked, so a publishing step
that forgets the flag does not find it missing: it finds last run's. An
existence check passes and the stale hash is copied into an archive and signed
over. Over the published archive on 21 November 2026, 107 of the 338 archives
carrying both files hold a hash file that is not the terminal hash of the
ledger beside it, every one published before October 2026.

So `tools/publish_run.py` compares the two before it copies or signs
anything, and that comparison is what a forgotten flag runs into.

Breaking this: write the file unconditionally again, drop `--write-hash` from
a publishing step, or have `_stale_hash_file` return None.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from itgl import CHAIN_VERSION_V1, load_and_verify_ledger  # noqa: E402
from publish_run import HASH_FILE, ROOT_LEDGER, _stale_hash_file  # noqa: E402

RUNS = REPO / "docs" / "runs"
AN_OLDER_RUN = RUNS / "20260921-135018-029319-gh35607761858-f3dd66376a01"
A_NEWER_RUN = RUNS / "20261026-114228-317580-gh40317017323-d8bd37b6606d"


def _ledger(run):
    path = run / "proofs" / "itgl_ledger.jsonl"
    if not path.is_file():
        pytest.skip(f"published ledger not present: {path}")
    return path


def _verify(*argv, cwd):
    return subprocess.run(
        [sys.executable, str(REPO / "tools" / "verify_itgl.py"), *map(str, argv)], capture_output=True, text=True, cwd=cwd
    )


# --- the reader ----------------------------------------------------------------------


def test_verifying_a_ledger_leaves_no_file_behind(tmp_path):
    ledger = _ledger(AN_OLDER_RUN)
    result = _verify("--ledger", ledger, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    computed, _ = load_and_verify_ledger(ledger, CHAIN_VERSION_V1)
    assert f"ITGL_FINAL_HASH={computed}" in result.stdout
    assert list(tmp_path.iterdir()) == []


def test_verifying_an_archived_ledger_from_the_checkout_does_not_touch_the_tracked_file():
    tracked = REPO / HASH_FILE
    if not tracked.is_file():
        pytest.skip(f"{HASH_FILE} is not in this checkout")
    before = tracked.read_bytes()
    result = _verify("--ledger", _ledger(AN_OLDER_RUN), cwd=REPO)
    assert result.returncode == 0, result.stderr
    assert tracked.read_bytes() == before


def test_the_hash_is_written_where_a_publisher_says_and_nowhere_else(tmp_path):
    ledger = _ledger(A_NEWER_RUN)
    destination = tmp_path / "out" / "itgl_final_hash.txt"
    result = _verify("--ledger", ledger, "--write-hash", destination, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    computed, _ = load_and_verify_ledger(ledger, CHAIN_VERSION_V1)
    assert destination.read_text(encoding="utf-8") == computed + "\n"
    assert [path.name for path in tmp_path.iterdir()] == ["out"]


def test_a_ledger_that_does_not_verify_writes_no_hash(tmp_path):
    rows = _ledger(A_NEWER_RUN).read_text(encoding="utf-8").splitlines()
    altered = tmp_path / "ledger.jsonl"
    altered.write_text("\n".join(rows[1:]) + "\n", encoding="utf-8")
    destination = tmp_path / "hash.txt"
    result = _verify("--ledger", altered, "--write-hash", destination, cwd=tmp_path)
    assert result.returncode == 1 and not destination.exists()


# --- the publishing steps name the destination ------------------------------------------------


def _publishing_steps():
    """Every tracked file that archives the hash file, found rather than listed.

    A file is a publishing step if it hands `publish_run.py` the hash file to
    copy. That is the property the rule is about, so it is the property looked
    for; a step added later is found by the same walk.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", ".github/workflows", "tools"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.split("\0")
    found = []
    for name in tracked:
        if not name or not name.endswith((".yml", ".yaml", ".py")):
            continue
        path = REPO / name
        if path.name in ("verify_itgl.py", "publish_run.py"):
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        uncommented = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        if "publish_run" in uncommented and str(HASH_FILE) in uncommented:
            found.append((name, uncommented))
    return found


def test_every_step_that_archives_the_hash_file_asks_for_it_to_be_written():
    steps = _publishing_steps()
    assert len(steps) >= 4, [name for name, _ in steps]
    for name, source in steps:
        assert "verify_itgl.py" in source, f"{name} archives {HASH_FILE} and never writes it"
        assert f"--write-hash" in source, f"{name} runs verify_itgl.py without --write-hash"
        assert str(HASH_FILE) in source, name
        if not name.endswith((".yml", ".yaml")):
            # A Python caller builds the invocation as a list over several
            # lines, so the flag is not on the line that names the tool and
            # the check above is the whole check. Only in a workflow is one
            # invocation one line.
            continue
        for line in source.splitlines():
            if "verify_itgl.py" in line and "--write-hash" not in line:
                raise AssertionError(f"{name}: a verify_itgl.py call with no --write-hash: {line.strip()}")


# --- a forgotten flag meets a comparison, not an existence check ----------------------------------


def _root(tmp_path, ledger_from, hash_from=None):
    """A repository root holding a root ledger, and optionally a hash file."""
    (tmp_path / "proofs").mkdir(exist_ok=True)
    (tmp_path / ROOT_LEDGER).write_bytes(_ledger(ledger_from).read_bytes())
    if hash_from is not None:
        computed, _ = load_and_verify_ledger(_ledger(hash_from), CHAIN_VERSION_V1)
        (tmp_path / HASH_FILE).write_text(computed + "\n", encoding="utf-8")
    return tmp_path


BOTH = [ROOT_LEDGER, HASH_FILE]


def test_a_hash_file_written_from_this_runs_ledger_is_published(tmp_path):
    assert _stale_hash_file(_root(tmp_path, A_NEWER_RUN, hash_from=A_NEWER_RUN), BOTH) is None


def test_a_publisher_that_forgot_to_write_the_file_is_refused(tmp_path):
    # The previous run left its hash on disk. This run wrote a ledger and did
    # not ask for the hash to be written.
    root = _root(tmp_path, A_NEWER_RUN, hash_from=AN_OLDER_RUN)
    assert (root / HASH_FILE).is_file(), "an existence check would have passed"
    refusal = _stale_hash_file(root, BOTH)
    assert refusal is not None and "left over from another run" in refusal and "--write-hash" in refusal


def test_a_hash_file_with_no_ledger_beside_it_is_refused(tmp_path):
    root = _root(tmp_path, A_NEWER_RUN, hash_from=A_NEWER_RUN)
    assert "without" in _stale_hash_file(root, [HASH_FILE])
    (root / ROOT_LEDGER).unlink()
    assert "without" in _stale_hash_file(root, BOTH)


def test_a_ledger_that_does_not_verify_cannot_vouch_for_the_file(tmp_path):
    root = _root(tmp_path, A_NEWER_RUN, hash_from=A_NEWER_RUN)
    rows = (root / ROOT_LEDGER).read_text(encoding="utf-8").splitlines()
    (root / ROOT_LEDGER).write_text("\n".join(rows[1:]) + "\n", encoding="utf-8")
    assert "does not verify" in _stale_hash_file(root, BOTH)


def test_nothing_is_said_about_an_archive_that_carries_no_hash_file(tmp_path):
    root = _root(tmp_path, A_NEWER_RUN)
    assert _stale_hash_file(root, BOTH) is None
    assert _stale_hash_file(root, [ROOT_LEDGER]) is None


def test_the_publisher_refuses_before_it_copies_or_signs(tmp_path):
    root = _root(tmp_path, A_NEWER_RUN, hash_from=AN_OLDER_RUN)
    certificate = A_NEWER_RUN / "audit.json"
    result = subprocess.run(
        [
            sys.executable, str(REPO / "tools" / "publish_run.py"), "--cert", str(certificate),
            "--repo-root", str(root), "--copy", ROOT_LEDGER, "--copy", HASH_FILE,
        ],
        capture_output=True, text=True, cwd=root,
    )
    assert result.returncode == 1 and "refusing to publish" in result.stderr
    assert not (root / "proofs" / "runs").exists(), "an archive directory was created before the refusal"


def test_the_committed_root_pair_and_every_archive_since_october_agree():
    # The property the comparison holds a publisher to, over what has been
    # published since the steps were made to move together.
    pairs = [(REPO / ROOT_LEDGER, REPO / HASH_FILE)]
    pairs += [
        (run / ROOT_LEDGER, run / HASH_FILE)
        for run in sorted(RUNS.iterdir())
        if run.is_dir() and run.name >= "20261001"
    ]
    checked = 0
    for ledger, hash_file in pairs:
        if not (ledger.is_file() and hash_file.is_file()):
            continue
        computed, _ = load_and_verify_ledger(ledger, CHAIN_VERSION_V1)
        assert hash_file.read_text(encoding="utf-8").strip() == computed, hash_file
        checked += 1
    if not checked:
        pytest.skip("no ledger and hash file pair in this checkout")
