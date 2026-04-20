from sir_firewall.model_selection import validate_execution_selection


def test_validate_execution_selection_accepts_supported_pair_in_audit():
    provider, model = validate_execution_selection(provider="openai", model="gpt-4.1-mini", mode="audit", env={})
    assert provider == "openai"
    assert model == "gpt-4.1-mini"


def test_validate_execution_selection_rejects_unsupported_model_for_provider():
    try:
        validate_execution_selection(provider="openai", model="grok-4-1-fast", mode="audit", env={})
        assert False, "expected validation failure"
    except ValueError as exc:
        assert "unsupported model" in str(exc)


def test_validate_execution_selection_requires_provider_secret_in_live_mode():
    try:
        validate_execution_selection(provider="openai", model="gpt-4.1-mini", mode="live", env={})
        assert False, "expected validation failure"
    except ValueError as exc:
        assert "OPENAI_API_KEY" in str(exc)


def test_validate_execution_selection_supports_prefixed_model_when_provider_matches():
    provider, model = validate_execution_selection(provider="xai", model="xai/grok-3-beta", mode="audit", env={})
    assert provider == "xai"
    assert model == "grok-3-beta"
