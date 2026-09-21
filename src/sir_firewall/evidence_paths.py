"""Canonical identity-derived paths for per-run evidence."""

from pathlib import Path


def canonical_ledger_path(run_id: str, runs_dir: Path = Path("proofs/runs")) -> Path:
    """Return the sole canonical ITGL ledger location for ``run_id``."""
    if not run_id or run_id in {".", ".."} or ".." in run_id or "/" in run_id or "\\" in run_id:
        raise ValueError(f"invalid run_id for canonical ledger path: {run_id!r}")
    return runs_dir / run_id / "proofs" / "itgl_ledger.jsonl"
