import hashlib
from pathlib import Path

import pytest

from sir_firewall import core


ROOT = Path(__file__).resolve().parents[1]


def _isc(payload: str, checksum: str | None = None) -> dict:
    return {
        "version": "1.0",
        "template_id": "EU-AI-Act-ISC-v1",
        "payload": payload,
        "checksum": checksum if checksum is not None else hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "signature": "",
    }


def _small_limit_pack(pack_id=None):
    return {
        "pack_id": "generic_safety",
        "templates": {"EU-AI-Act-ISC-v1": {"max_tokens": 3}},
        "flags": {"STRICT_ISC_ENFORCEMENT": True, "CHECKSUM_ENFORCED": True, "CRYPTO_ENFORCED": False},
    }


def test_oversized_payload_blocks_before_expensive_operations(monkeypatch):
    payload = "z" * 13
    isc = _isc(payload)
    monkeypatch.setattr(core, "load_domain_pack", _small_limit_pack)

    def unexpected(*args, **kwargs):
        pytest.fail("an expensive payload operation was reached")

    monkeypatch.setattr(core, "_compute_checksum", unexpected)
    monkeypatch.setattr(core, "_verify_signature", unexpected)
    monkeypatch.setattr(core, "_estimate_tokens", unexpected)

    out = core.validate_sir({"isc": isc})

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "friction_limit_exceeded"
    assert out["triggered_rule"]["rule_id"] == "SIR-RULE-FRICTION-LIMIT"
    assert out["itgl_log"][-1]["component"] == "friction"


def test_payload_at_exact_character_limit_still_passes(monkeypatch):
    payload = "z" * 12
    monkeypatch.setattr(core, "load_domain_pack", _small_limit_pack)

    out = core.validate_sir({"isc": _isc(payload)})

    assert out["status"] == "PASS"
    assert out["reason"] == "clean"


@pytest.mark.parametrize(
    ("field", "reason", "subtype"),
    [
        ("structured_request", "structured_validation_failed", "structured_invalid_json"),
        ("tool_result", "tool_result_validation_failed", "tool_result_invalid_json"),
    ],
)
def test_deeply_nested_json_blocks_instead_of_raising(field, reason, subtype):
    depth = 100_000
    raw = '{"a":' * depth + "0" + "}" * depth
    try:
        out = core.validate_sir({field: raw})
    except RecursionError:
        pytest.fail("RecursionError escaped validate_sir()")

    assert out["status"] == "BLOCKED"
    assert out["reason"] == reason
    assert out["type"] == subtype


@pytest.mark.parametrize(
    ("input_dict", "reason", "subtype"),
    [
        (
            {
                "isc": {
                    "version": "1.0",
                    "template_id": "EU-AI-Act-ISC-v1",
                    "payload": "\ud800",
                    "checksum": "unused",
                    "signature": "",
                }
            },
            "invalid_isc_schema",
            "invalid_unicode_payload",
        ),
        (
            {
                "structured_request": {
                    "schema_version": "v1",
                    "request_class": "account_recovery_challenge",
                    "action": "password_reset",
                    "channel": "chat",
                    "request_text": "\ud800",
                }
            },
            "structured_validation_failed",
            "structured_invalid_unicode",
        ),
        (
            {"tool_result": {"tool_name": "browser", "content": "\ud800"}},
            "tool_result_validation_failed",
            "tool_result_invalid_unicode",
        ),
    ],
)
def test_surrogate_payloads_block_instead_of_raising(input_dict, reason, subtype):
    try:
        out = core.validate_sir(input_dict)
    except UnicodeEncodeError:
        pytest.fail("UnicodeEncodeError escaped validate_sir()")

    assert out["status"] == "BLOCKED"
    assert out["reason"] == reason
    assert out["type"] == subtype


def test_validate_text_surrogate_routes_through_ingress_rejection():
    try:
        out = core.validate_text("\ud800")
    except UnicodeEncodeError:
        pytest.fail("UnicodeEncodeError escaped validate_text()")

    assert out["status"] == "BLOCKED"
    assert out["reason"] == "invalid_isc_schema"
    assert out["type"] == "invalid_unicode_payload"


def test_latest_run_does_not_parse_fetched_fields_as_html():
    page = (ROOT / "docs/latest-run.html").read_text(encoding="utf-8")
    assert "innerHTML" not in page
    assert "el.textContent = out;" in page


@pytest.mark.parametrize(
    "path",
    [
        "docs/latest-run.html",
        "docs/latest-audit.html",
        "proofs/latest-audit.html",
        "proofs/template.html",
    ],
)
def test_fetched_audit_urls_use_scheme_validator(path):
    page = (ROOT / path).read_text(encoding="utf-8")
    assert "function safeHttpUrl(" in page
    assert "safeHttpUrl(data.ci_run_url)" in page


@pytest.mark.parametrize("path", ["docs/runs/index.html", "proofs/runs/index.html"])
def test_fetched_run_index_urls_use_scheme_validator(path):
    page = (ROOT / path).read_text(encoding="utf-8")
    assert "function safeHttpUrl(" in page
    assert "safeHttpUrl(r.ci_run_url)" in page


def test_all_certificate_renderers_include_signed_governance_fields():
    paths = ["proofs/template.html", "proofs/latest-audit.html", "docs/latest-audit.html"]
    pages = [(ROOT / path).read_text(encoding="utf-8") for path in paths]
    summary_sections = [page.split('<h2>Certificate summary</h2>', 1)[1].split("</div>\n\n", 1)[0] for page in pages]

    assert summary_sections[0] == summary_sections[1] == summary_sections[2]
    for page, summary in zip(pages, summary_sections):
        assert 'id="governance-scope"' in summary
        assert 'id="crypto-enforced"' in summary
        assert "applies to incoming request envelopes; this certificate is signed regardless" in summary
        assert 'setText("governance-scope", data.governance_scope);' in page
        assert 'typeof data.crypto_enforced === "boolean" ? String(data.crypto_enforced) : undefined' in page
