import subprocess
import sys
from pathlib import Path


def test_export_review_bundle_rejects_non_directory_out_path(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    out_path = tmp_path / "not_a_dir"
    out_path.write_text("x", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "tools/export_review_bundle.py", "--out", str(out_path)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )

    assert proc.returncode != 0
    assert "ERROR: --out must be a directory path" in (proc.stderr + proc.stdout)
