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
