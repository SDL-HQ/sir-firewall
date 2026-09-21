import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(cert: Path):
    return subprocess.run(
        [sys.executable, str(ROOT / "tools/validate_certificate_contract.py"), str(cert)],
        cwd=ROOT, capture_output=True, text=True,
    )


def test_pre_floor_certificate_is_reported_not_applicable():
    cert = next((ROOT / "proofs/archive").glob("audit-certificate-*.json"))
    payload = json.loads(cert.read_text(encoding="utf-8"))
    assert payload.get("sir_firewall_version") is None or payload.get("sir_firewall_version") < "2.2.0"
    result = _run(cert)
    assert result.returncode == 8
    assert "NOT APPLICABLE" in result.stderr
    assert ">= 2.2.0" in result.stderr


def test_at_floor_validation_success_message_is_unchanged():
    cert = next(
        path for path in (ROOT / "proofs/runs").glob("*/audit.json")
        if json.loads(path.read_text(encoding="utf-8")).get("sir_firewall_version") == "2.2.0"
    )
    result = _run(cert)
    assert result.returncode == 0
    assert result.stdout == "OK: certificate satisfies evidence contract v1.\n"
    assert result.stderr == ""


def test_contract_validator_reports_explicit_detachment(tmp_path):
    source = next(
        path for path in (ROOT / "proofs/runs").glob("*/audit.json")
        if json.loads(path.read_text(encoding="utf-8")).get("sir_firewall_version") == "2.3.3"
    )
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["detached_ledger"] = True
    certificate = tmp_path / "detached.json"
    certificate.write_text(json.dumps(payload), encoding="utf-8")
    result = _run(certificate)
    assert result.returncode == 0
    assert "detached_ledger=true" in result.stderr
