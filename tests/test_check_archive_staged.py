"""Guards for the publication gate added in 2.3.7.

Ninety-nine published run archives named `leaks_count.txt` and
`harmless_blocked.txt` in their signed manifests while a repo-wide .gitignore
rule kept git from ever committing them. The archives were published
incomplete, `tools/verify_archive_receipt.py` failed on every one of them for
any third party, and CI stayed green throughout.

These tests guard both halves of the fix: the ignore rule that caused it, and
the gate that would have caught it.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = REPO_ROOT / "tools" / "check_archive_staged.py"


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def _run_checker(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args], cwd=cwd, capture_output=True, text=True
    )


def _write_archive(root: Path, run_id: str, names: list[str]) -> None:
    for tree in ("proofs/runs", "docs/runs"):
        run_dir = root / tree / run_id
        (run_dir / "proofs").mkdir(parents=True, exist_ok=True)
        for name in names:
            target = run_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"content of {name}\n", encoding="utf-8")
        manifest = {
            "run_id": run_id,
            "files": [{"path": name, "sha256": "sha256:" + "0" * 64} for name in names],
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _init_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    return tmp_path


def test_passes_when_every_manifest_file_is_staged(tmp_path):
    repo = _init_repo(tmp_path)
    _write_archive(repo, "run-ok", ["audit.json", "proofs/itgl_ledger.jsonl"])
    _git(repo, "add", "-A")

    result = _run_checker(repo)

    assert result.returncode == 0, result.stderr
    assert "run-ok" in result.stdout


def test_fails_when_an_ignore_rule_drops_a_manifest_file(tmp_path):
    """The exact shape of the defect: the file exists, the manifest names it,
    and .gitignore keeps it out of the commit."""
    repo = _init_repo(tmp_path)
    (repo / ".gitignore").write_text("leaks_count.txt\n", encoding="utf-8")
    _write_archive(repo, "run-dropped", ["audit.json", "leaks_count.txt"])
    _git(repo, "add", "-A")

    result = _run_checker(repo)

    assert result.returncode == 1
    assert "not staged in git" in result.stderr
    assert "leaks_count.txt" in result.stderr


def test_fails_when_a_manifest_file_is_absent_from_disk(tmp_path):
    repo = _init_repo(tmp_path)
    _write_archive(repo, "run-absent", ["audit.json"])
    for tree in ("proofs/runs", "docs/runs"):
        manifest_path = repo / tree / "run-absent" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"].append({"path": "harmless_blocked.txt", "sha256": "sha256:" + "0" * 64})
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _git(repo, "add", "-A")

    result = _run_checker(repo)

    assert result.returncode == 1
    assert "absent from disk" in result.stderr


def test_ignores_archives_not_staged_in_this_commit(tmp_path):
    """Archives published by earlier runs must not block a later run."""
    repo = _init_repo(tmp_path)
    (repo / ".gitignore").write_text("leaks_count.txt\n", encoding="utf-8")
    _write_archive(repo, "run-historical", ["audit.json", "leaks_count.txt"])
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "historical archive")

    result = _run_checker(repo)

    assert result.returncode == 0, result.stderr
    assert "nothing to check" in result.stdout


def test_repo_gitignore_does_not_hide_run_archive_counter_files():
    """The regression itself. A repo-wide pattern would silently drop these
    from every published archive whose manifest names them."""
    for name in ("leaks_count.txt", "harmless_blocked.txt"):
        archived = _git(REPO_ROOT, "check-ignore", f"proofs/runs/EXAMPLE_RUN/{name}")
        assert archived.returncode != 0, (
            f"{name} inside a run archive is ignored by .gitignore; "
            "published archives would fail tools/verify_archive_receipt.py"
        )
        root_copy = _git(REPO_ROOT, "check-ignore", name)
        assert root_copy.returncode == 0, (
            f"the mutable root-level {name} should stay ignored"
        )
