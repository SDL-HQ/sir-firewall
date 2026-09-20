import importlib.util
import json
from pathlib import Path


def _load_generate_certificate_module():
    module_path = Path(__file__).resolve().parents[1] / "tools" / "generate_certificate.py"
    spec = importlib.util.spec_from_file_location("generate_certificate", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_live_provider_failures_produce_inconclusive():
    mod = _load_generate_certificate_module()
    result = mod._compute_audit_result(
        proof_class="LIVE_GATING_CHECK",
        jailbreaks_leaked=0,
        harmless_blocked=0,
        provider_call_attempts=50,
        provider_call_successes=49,
        provider_call_failures=1,
    )
    assert result == "INCONCLUSIVE"


def test_live_attempts_without_successes_produce_inconclusive():
    mod = _load_generate_certificate_module()
    result = mod._compute_audit_result(
        proof_class="LIVE_GATING_CHECK",
        jailbreaks_leaked=0,
        harmless_blocked=0,
        provider_call_attempts=5,
        provider_call_successes=0,
        provider_call_failures=0,
    )
    assert result == "INCONCLUSIVE"


def test_firewall_only_semantics_unchanged():
    mod = _load_generate_certificate_module()
    passed = mod._compute_audit_result(
        proof_class="FIREWALL_ONLY_AUDIT",
        jailbreaks_leaked=0,
        harmless_blocked=0,
        provider_call_attempts=0,
        provider_call_successes=0,
        provider_call_failures=0,
    )
    failed = mod._compute_audit_result(
        proof_class="FIREWALL_ONLY_AUDIT",
        jailbreaks_leaked=1,
        harmless_blocked=0,
        provider_call_attempts=0,
        provider_call_successes=0,
        provider_call_failures=0,
    )
    assert passed == "AUDIT PASSED"
    assert failed == "AUDIT FAILED"


def test_evidence_contract_allows_inconclusive_result():
    payload = json.loads((Path(__file__).resolve().parents[1] / "spec" / "evidence_contract.v1.json").read_text(encoding="utf-8"))
    enum_vals = payload["properties"]["result"]["enum"]
    assert "INCONCLUSIVE" in enum_vals


def test_latest_audit_targets_only_for_publishable_pass():
    mod = _load_generate_certificate_module()
    latest_targets = mod._select_latest_output_targets(publishable_latest=True, result="AUDIT PASSED")
    assert latest_targets[0] == "proofs/latest-audit.json"
    assert latest_targets[1] == "proofs/latest-audit.html"

    inconclusive_targets = mod._select_latest_output_targets(publishable_latest=True, result="INCONCLUSIVE")
    assert inconclusive_targets[0] == "proofs/local-audit.json"
    assert inconclusive_targets[1] == "proofs/local-audit.html"

    failed_targets = mod._select_latest_output_targets(publishable_latest=True, result="AUDIT FAILED")
    assert failed_targets[0] == "proofs/local-audit.json"
    assert failed_targets[1] == "proofs/local-audit.html"


def test_template_styles_inconclusive_as_non_success():
    template = (Path(__file__).resolve().parents[1] / "proofs" / "template.html").read_text(encoding="utf-8")
    assert 'resolvedResult === "INCONCLUSIVE"' in template
    assert '? "warn"' in template or ' ? "warn"' in template


def _attributable_certificate(**overrides):
    certificate = {
        "sir_firewall_version": "test-version",
        "commit_sha": "a" * 40,
        "ci_run_url": "https://github.com/SDL-HQ/sir-firewall/actions/runs/1",
        "proof_class": "LIVE_GATING_CHECK",
        "provider_call_successes": 1,
        "result": "AUDIT PASSED",
        "date": "2026-09-20T00:00:00Z",
        "payload_hash": "sha256:test",
    }
    certificate.update(overrides)
    return certificate


def _write_minimal_template(directory):
    (directory / "template.html").write_text(
        "__AUDIT_LABEL__ __AUDIT_JSON__ __VERIFY_COMMAND__ "
        "__POINTER_DESCRIPTION__ __CROSS_LINK_HREF__ __CROSS_LINK_TEXT__",
        encoding="utf-8",
    )


def test_passing_live_run_advances_live_pointer(tmp_path):
    mod = _load_generate_certificate_module()
    _write_minimal_template(tmp_path)
    assert mod._publish_latest_live(_attributable_certificate(), tmp_path)
    assert (tmp_path / "latest-live-audit.json").is_file()


def test_failing_live_run_with_provider_success_advances_live_pointer(tmp_path):
    mod = _load_generate_certificate_module()
    cert = _attributable_certificate(result="AUDIT FAILED")
    _write_minimal_template(tmp_path)

    targets = mod._select_latest_output_targets(publishable_latest=True, result=cert["result"])
    assert targets[:2] == ("proofs/local-audit.json", "proofs/local-audit.html")
    assert mod._publish_latest_live(cert, tmp_path)
    assert json.loads((tmp_path / "latest-live-audit.json").read_text(encoding="utf-8")) == cert
    html = (tmp_path / "latest-live-audit.html").read_text(encoding="utf-8")
    assert "latest-live-audit" in html
    assert "regardless of result" in html
    assert "may describe a different run" in html
    assert "View latest passing audit" in html


def test_firewall_only_run_does_not_advance_live_pointer(tmp_path):
    mod = _load_generate_certificate_module()
    cert = _attributable_certificate(proof_class="FIREWALL_ONLY_AUDIT")
    assert not mod._publish_latest_live(cert, tmp_path)
    assert not (tmp_path / "latest-live-audit.json").exists()


def test_live_run_without_provider_success_does_not_advance_live_pointer(tmp_path):
    mod = _load_generate_certificate_module()
    cert = _attributable_certificate(provider_call_successes=0)
    assert not mod._publish_latest_live(cert, tmp_path)
    assert not (tmp_path / "latest-live-audit.json").exists()


def test_live_pointer_reuses_attributable_provenance_bar():
    mod = _load_generate_certificate_module()
    cert = _attributable_certificate(ci_run_url="")
    assert not mod._is_publishable_latest(cert)
    assert not mod._is_publishable_latest_live(cert)


def test_live_template_and_existing_pages_explain_distinct_pointer_semantics():
    root = Path(__file__).resolve().parents[1]
    template = (root / "proofs" / "template.html").read_text(encoding="utf-8")
    assert "__POINTER_DESCRIPTION__" in template
    assert "Overall latest run status" in template
    assert "__CROSS_LINK_HREF__" in template
    for path in (root / "proofs" / "latest-audit.html", root / "docs" / "latest-audit.html"):
        html = path.read_text(encoding="utf-8")
        assert "Overall latest run status" in html
        assert 'href="latest-live-audit.html"' in html


def test_latest_audit_html_exactly_matches_current_template_render(tmp_path):
    root = Path(__file__).resolve().parents[1]
    mod = _load_generate_certificate_module()
    certificate = json.loads((root / "proofs" / "latest-audit.json").read_text(encoding="utf-8"))
    rendered = tmp_path / "latest-audit.html"

    mod._write_primary_audit_html(
        certificate,
        html_out=str(rendered),
        target_json_name="latest-audit.json",
        audit_label="latest-audit",
        verify_command=(
            "curl -s https://raw.githubusercontent.com/SDL-HQ/sir-firewall/main/"
            "proofs/latest-audit.json | python tools/verify_certificate.py -"
        ),
    )

    expected = rendered.read_bytes()
    assert (root / "proofs" / "latest-audit.html").read_bytes() == expected
    assert (root / "docs" / "latest-audit.html").read_bytes() == expected
