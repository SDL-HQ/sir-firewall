import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "verifier-negatives"
README = FIXTURES / "README.md"

CASES = {
    "tampered-leak-count.json": {
        "verify_code": 3,
        "verify_stderr": "ERROR: payload_hash mismatch\n"
        "  cert: sha256:f6496562750bd5b12c20c56abdb1f762b9b34ac685d8169ded9671129be51b62\n"
        "  calc: sha256:315631c293a45f6a9316d2438d549da7e2b35da46ff1fdad45e31ba9b06b888e\n",
        "contract_code": 0,
        "contract_stdout": "OK: certificate satisfies evidence contract v1.\n",
        "contract_stderr": "",
    },
    "tampered-leak-count-rehashed.json": {
        "verify_code": 5,
        "verify_stderr": "ERROR: signature verification failed (InvalidSignature)\n",
        "contract_code": 0,
        "contract_stdout": "OK: certificate satisfies evidence contract v1.\n",
        "contract_stderr": "",
    },
    "tampered-signature-swap.json": {
        "verify_code": 5,
        "verify_stderr": "ERROR: signature verification failed (InvalidSignature)\n",
        "contract_code": 0,
        "contract_stdout": "OK: certificate satisfies evidence contract v1.\n",
        "contract_stderr": "",
    },
    "tampered-unregistered-key.json": {
        "verify_code": 1,
        "verify_stderr": "ERROR: signing_key_id not found in key registry: phase1-unregistered-temp-key\n",
        "contract_code": 0,
        "contract_stdout": "OK: certificate satisfies evidence contract v1.\n",
        "contract_stderr": "",
    },
    "tampered-required-field-removed.json": {
        "verify_code": 3,
        "verify_stderr": "ERROR: payload_hash mismatch\n"
        "  cert: sha256:f6496562750bd5b12c20c56abdb1f762b9b34ac685d8169ded9671129be51b62\n"
        "  calc: sha256:56ee344dd20d482a2bff0440ea05bad51b01181e5f8fcbcfd1ef3d8aa416e62f\n",
        "contract_code": 2,
        "contract_stdout": "",
        "contract_stderr": "ERROR: certificate contract validation failed:\n"
        " - missing required field: prompts_tested\n",
    },
}


def _run(tool: str, fixture: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / tool), str(FIXTURES / fixture)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(("fixture", "expected"), CASES.items())
def test_invalid_fixture_fails_verification_for_documented_reason(fixture, expected):
    result = _run("verify_certificate.py", fixture)

    assert result.returncode == expected["verify_code"]
    assert result.stdout == ""
    assert result.stderr == expected["verify_stderr"]


@pytest.mark.parametrize(("fixture", "expected"), CASES.items())
def test_contract_validation_exposes_documented_tool_boundary(fixture, expected):
    result = _run("validate_certificate_contract.py", fixture)

    assert result.returncode == expected["contract_code"]
    assert result.stdout == expected["contract_stdout"]
    assert result.stderr == expected["contract_stderr"]


def test_readme_diagnostics_match_verifier_and_contract_output():
    """Keep every documented exit code and verbatim diagnostic tied to actual tool output."""
    readme = README.read_text(encoding="utf-8")

    for fixture, expected in CASES.items():
        verify = _run("verify_certificate.py", fixture)
        contract = _run("validate_certificate_contract.py", fixture)
        fixture_section = readme.split(f"`{fixture}`", 1)[1].split("\n## ", 1)[0]
        assert f"Verifier exit code: `{verify.returncode}`" in fixture_section
        assert f"Contract-validator exit code: `{contract.returncode}`" in fixture_section
        assert f"```text\n{verify.stderr.rstrip()}\n```" in fixture_section
        contract_message = (contract.stdout or contract.stderr).rstrip()
        assert f"```text\n{contract_message}\n```" in fixture_section
