import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sir_firewall.cli", "verify", "cert", *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_verify_cert_forwards_explicit_ledger_and_binds():
    result = _run(
        "--ledger", "proofs/itgl_ledger.jsonl", "proofs/latest-audit.json"
    )
    assert result.returncode == 0, result.stderr
    assert "ledger binding verifies" in result.stdout


def test_cli_verify_cert_forwards_explicit_skip():
    result = _run("--no-ledger", "proofs/latest-audit.json")
    assert result.returncode == 0, result.stderr
    assert (
        "NOT VERIFIED: certificate-to-ledger binding was skipped with --no-ledger."
        in result.stderr
    )


def test_cli_verify_cert_reports_not_checked_when_discovery_finds_nothing(tmp_path):
    certificate = tmp_path / "audit.json"
    certificate.write_bytes((ROOT / "proofs/latest-audit.json").read_bytes())
    result = _run(str(certificate))
    assert result.returncode == 9
    assert "NOT CHECKED: certificate-to-ledger binding was not checked" in result.stderr


def test_cli_verify_cert_binding_modes_are_mutually_exclusive():
    result = _run(
        "--ledger", "proofs/itgl_ledger.jsonl", "--no-ledger",
        "proofs/latest-audit.json",
    )
    assert result.returncode == 2
    assert "not allowed with argument --ledger" in result.stderr
