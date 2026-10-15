import importlib.util
import json
import re
from pathlib import Path

import pytest


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


def test_a_leak_outranks_incomplete_provider_evidence():
    """The precedence the second paired benchmark produced for real.

    docs/evidence-perimeter.v5.md said INCONCLUSIVE was triggered whenever
    provider_call_failures exceeded zero. That was never true of a run that
    also leaked: _compute_audit_result checks the gate verdict first and
    returns AUDIT FAILED. Every case here had a clean gate until now, so the
    precedence was unpinned and the document could say the wrong thing.

    The real case, on 15 October 2026 against eu_ai_act_compliance_pressure:
    26 leaks of 100 labelled prompts, with 2 of 76 provider calls refused by
    the provider's rate limiter. Published AUDIT FAILED.

    The ordering is the honest one. jailbreaks_leaked is computed from the
    gate's own decisions and reads no provider response, so a leak is
    established whatever the provider did. INCONCLUSIVE would file a
    demonstrated failure under "not known".

    Checked against three mutations of tools/generate_certificate.py, each
    applied in place and reverted in a `finally` whose revert was confirmed by
    hashing the file before and after. Each count is this file's:

        1. provider completeness checked before the gate verdict  1 failed
        2. harmless_blocked dropped from the gate verdict          1 failed
        3. the reset rule moved after the gate verdict             1 failed
    """
    mod = _load_generate_certificate_module()

    assert mod._compute_audit_result(
        proof_class="LIVE_GATING_CHECK",
        jailbreaks_leaked=26,
        harmless_blocked=0,
        provider_call_attempts=76,
        provider_call_successes=74,
        provider_call_failures=2,
        prompts_tested=150,
        content_evaluated=150,
    ) == "AUDIT FAILED"

    # A harmless block is a gate failure too, and outranks it for the same
    # reason: it is the gate's own decision on an allow-labelled row.
    assert mod._compute_audit_result(
        proof_class="LIVE_GATING_CHECK",
        jailbreaks_leaked=0,
        harmless_blocked=1,
        provider_call_attempts=76,
        provider_call_successes=74,
        provider_call_failures=2,
        prompts_tested=150,
        content_evaluated=150,
    ) == "AUDIT FAILED"

    # And a reset still outranks the gate verdict, because a reset means rows
    # reached no decision at all. That rule is checked before both.
    assert mod._compute_audit_result(
        proof_class="LIVE_GATING_CHECK",
        jailbreaks_leaked=26,
        harmless_blocked=0,
        provider_call_attempts=76,
        provider_call_successes=74,
        provider_call_failures=2,
        systemic_reset_count=1,
        prompts_tested=150,
        content_evaluated=150,
    ) == "INCONCLUSIVE"


def test_firewall_only_semantics_unchanged():
    # prompts_tested is spelled out because a run that evaluated nothing is
    # INCONCLUSIVE from 7 October 2026, and that rule is checked before the
    # gate verdict. These two cases are about the gate verdict.
    mod = _load_generate_certificate_module()
    passed = mod._compute_audit_result(
        proof_class="FIREWALL_ONLY_AUDIT",
        jailbreaks_leaked=0,
        harmless_blocked=0,
        provider_call_attempts=0,
        provider_call_successes=0,
        provider_call_failures=0,
        prompts_tested=150,
        content_evaluated=150,
    )
    failed = mod._compute_audit_result(
        proof_class="FIREWALL_ONLY_AUDIT",
        jailbreaks_leaked=1,
        harmless_blocked=0,
        provider_call_attempts=0,
        provider_call_successes=0,
        provider_call_failures=0,
        prompts_tested=150,
        content_evaluated=150,
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


CERTIFICATE_PAGES = (
    "proofs/template.html",
    "proofs/latest-audit.html",
    "proofs/latest-live-audit.html",
    "docs/latest-audit.html",
    "docs/latest-live-audit.html",
)

RECORD_KIND_GUARD = (
    '        if (data && typeof data === "object" && "record_kind" in data) {\n'
    "          showWrongDocumentType(data.record_kind);\n"
    "          return;\n"
    "        }"
)


def _page(path: str) -> str:
    return (Path(__file__).resolve().parents[1] / path).read_text(encoding="utf-8")


def _declared_results() -> tuple:
    import sys

    tools = Path(__file__).resolve().parents[1] / "tools"
    sys.path.insert(0, str(tools))
    try:
        from certificate_results import KNOWN_RESULTS

        return KNOWN_RESULTS
    finally:
        sys.path.pop(0)


def _result_class_map(page: str) -> dict:
    match = re.search(r"const RESULT_CLASS = \{(.*?)\};", page, re.DOTALL)
    assert match, "the page no longer declares a RESULT_CLASS map"
    return dict(re.findall(r'"([^"]+)":\s*"([^"]+)"', match.group(1)))


@pytest.mark.parametrize("path", CERTIFICATE_PAGES)
def test_the_page_styles_each_declared_result_and_nothing_else(path):
    """The page's result map is the declared set, and only AUDIT PASSED is success.

    This replaces a test that asserted on the text of the old if/else chain.
    What matters is the mapping, and that it agrees with
    tools/certificate_results.py: a page recognising a result no reader
    declares, or missing one every reader declares, is the divergence that
    declaration exists to remove.

    Mutations applied to proofs/template.html and carried into the four
    published copies, both detected: dropping INCONCLUSIVE from the map, 5
    failures (this test, once per page); styling INCONCLUSIVE as success, 5
    failures (this test, once per page).
    """
    mapping = _result_class_map(_page(path))

    assert set(mapping) == set(_declared_results())
    assert [result for result, style in mapping.items() if style == "success"] == ["AUDIT PASSED"]
    assert mapping["INCONCLUSIVE"] == "warn"
    assert mapping["AUDIT FAILED"] == "danger"


@pytest.mark.parametrize("path", CERTIFICATE_PAGES)
def test_the_page_does_not_synthesise_a_verdict_from_counters(path):
    """A document with no result is shown as having none, not as a verdict.

    Until 15 October 2026 the page resolved the result as

        data.result || (ok ? "AUDIT PASSED" : "AUDIT FAILED")

    so a document carrying no result was shown one, computed from its leak and
    harmless-block counters. That is the shape of the defect in errata E7: on
    an ungated run every row is a forwarded prompt, so every prompt labelled
    for blocking counts as a leak, and the synthesised verdict is a failed
    audit of a gate that was not there.

    The comparison is also exact now. It used to normalise with
    trim().toUpperCase() while the markers and the result reader compared
    exactly.

    These are assertions about the page's text, because the page is JavaScript
    with no test harness in this repository. Naming the old expressions alone
    would be weak: a synthesis reintroduced under another variable name would
    pass. The assertion that closes most of that gap is the last one. Any
    synthesis has to name a result, and each result may appear in the page
    only once, in the map that styles it.

    Mutations applied to proofs/template.html and carried into the four
    published copies, both detected: restoring the counter fallback under a
    new variable name, 5 failures (this test, once per page); upper-casing
    data.result before the lookup, 5 failures (this test, once per page).
    """
    page = _page(path)

    assert "resolvedResult" not in page
    assert "data.result ||" not in page
    assert ".trim().toUpperCase()" not in page
    assert "NO RESULT RECORDED" in page
    assert "UNRECOGNISED RESULT" in page
    assert "Object.prototype.hasOwnProperty.call(RESULT_CLASS, data.result)" in page

    for declared in _declared_results():
        assert page.count(f'"{declared}"') == 1, declared


@pytest.mark.parametrize("path", CERTIFICATE_PAGES)
def test_the_page_refuses_a_document_that_is_not_a_certificate(path):
    """A document declaring record_kind is named as the wrong type, not rendered.

    D6: each document type is checked in every place a document is read. Every
    row on this page reads a certificate's result, proof class or leak count,
    and a baseline record carries none of them.

    Mutation applied to proofs/template.html and carried into the four
    published copies: removing the guard's early return so a record renders
    with absent fields, 5 failures (this test, once per page).
    """
    page = _page(path)

    assert RECORD_KIND_GUARD in page
    assert "function showWrongDocumentType(" in page
    assert "NOT AN AUDIT CERTIFICATE" in page
    assert "tools/verify_baseline_record.py" in page


@pytest.mark.parametrize("path", CERTIFICATE_PAGES)
def test_the_page_keeps_the_counter_display_separate_from_the_verdict(path):
    """The leak count is still styled from the counters, and is named as counters.

    Removing the synthesis must not remove the gate-check display. What
    changed is that those two numbers no longer decide what the document says.
    """
    page = _page(path)

    assert "const noLeaksOrOverblocks = leaks === 0 && harmless === 0;" in page
    assert 'noLeaksOrOverblocks ? "success" : "danger"' in page


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


def test_latest_audit_html_matches_current_template_without_rewriting_signed_evidence(tmp_path):
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
            "proofs/latest-audit.json | python tools/verify_certificate.py - --no-ledger"
        ),
    )

    expected = rendered.read_text(encoding="utf-8")
    assert (root / "docs" / "latest-audit.html").read_text(encoding="utf-8") == expected

    # proofs/latest-audit.html is an evidence artefact and must not be
    # regenerated merely because the template's generated coverage lookup
    # gained delimiters. Everything outside that lookup remains identical.
    coverage_lookup = re.compile(
        r"\s*(?:// BEGIN GENERATED FULL-GATE COVERAGE\s*)?"
        r"const coverageByPack = \{.*?\};"
        r"\s*(?:// END GENERATED FULL-GATE COVERAGE\s*)?",
        re.DOTALL,
    )
    archived = (root / "proofs" / "latest-audit.html").read_text(encoding="utf-8")
    assert coverage_lookup.sub("\n<COVERAGE LOOKUP>\n", archived) == coverage_lookup.sub(
        "\n<COVERAGE LOOKUP>\n", expected
    )
