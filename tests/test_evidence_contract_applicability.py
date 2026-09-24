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
    version = payload.get("sir_firewall_version")
    assert not isinstance(version, str) or not version[:1].isdigit() or tuple(map(int, version.split("."))) < (2, 2, 0)
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


def test_v2_is_selected_for_234_and_requires_binding_fields(tmp_path):
    source = next(
        path for path in (ROOT / "proofs/runs").glob("*/audit.json")
        if json.loads(path.read_text(encoding="utf-8")).get("sir_firewall_version") == "2.3.4"
    )
    payload = json.loads(source.read_text(encoding="utf-8"))
    complete = tmp_path / "complete-v2.json"
    complete.write_text(json.dumps(payload), encoding="utf-8")
    result = _run(complete)
    assert result.returncode == 0
    assert result.stdout == "OK: certificate satisfies evidence contract v2.\n"

    payload.pop("itgl_row_count")
    certificate = tmp_path / "missing-row-count.json"
    certificate.write_text(json.dumps(payload), encoding="utf-8")
    result = _run(certificate)
    assert result.returncode == 2
    assert "missing required field: itgl_row_count" in result.stderr


def test_published_234_certificates_satisfy_v2():
    certificates = [
        path for path in (ROOT / "proofs/runs").glob("*/audit.json")
        if json.loads(path.read_text(encoding="utf-8")).get("sir_firewall_version") == "2.3.4"
    ]
    assert certificates
    assert all(_run(path).returncode == 0 for path in certificates)


def test_v3_is_selected_for_235_and_requires_policy_correspondence(tmp_path):
    source = next(
        path for path in (ROOT / "proofs/runs").glob("*/audit.json")
        if json.loads(path.read_text(encoding="utf-8")).get("sir_firewall_version") == "2.3.4"
    )
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["sir_firewall_version"] = "2.3.5"
    payload.pop("enforced_policy_matches_signed_policy", None)
    certificate = tmp_path / "missing-policy-correspondence.json"
    certificate.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(certificate)
    assert result.returncode == 2
    assert "missing required field: enforced_policy_matches_signed_policy" in result.stderr

    payload["enforced_policy_matches_signed_policy"] = True
    certificate.write_text(json.dumps(payload), encoding="utf-8")
    result = _run(certificate)
    assert result.returncode == 0
    assert result.stdout == "OK: certificate satisfies evidence contract v3.\n"


def test_every_published_run_uses_its_applicable_contract():
    certificates = sorted((ROOT / "docs/runs").glob("*/audit.json"))
    assert certificates
    for certificate in certificates:
        version = json.loads(certificate.read_text(encoding="utf-8")).get(
            "sir_firewall_version"
        )
        result = _run(certificate)
        parsed = (
            tuple(int(part) for part in version.split("."))
            if isinstance(version, str) and version.count(".") == 2 and version[0].isdigit()
            else None
        )
        expected = 0 if parsed is not None and parsed >= (2, 2, 0) else 8
        assert result.returncode == expected, (
            certificate,
            result.stdout,
            result.stderr,
        )
