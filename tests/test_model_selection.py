from sir_firewall.model_selection import normalize_live_invocation_model, validate_execution_selection


def test_validate_execution_selection_accepts_supported_pair_in_audit():
    provider, model = validate_execution_selection(provider="openai", model="gpt-4.1-mini", mode="audit", env={})
    assert provider == "openai"
    assert model == "gpt-4.1-mini"


def test_validate_execution_selection_rejects_unsupported_model_for_provider():
    try:
        validate_execution_selection(provider="openai", model="grok-4.3", mode="audit", env={})
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


def test_normalize_live_invocation_model_prefixes_bare_xai_model():
    normalized = normalize_live_invocation_model(
        provider="xai",
        model="grok-4.3",
        requested_model="grok-4.3",
    )
    assert normalized == "xai/grok-4.3"


def test_normalize_live_invocation_model_keeps_prefixed_xai_model():
    normalized = normalize_live_invocation_model(
        provider="xai",
        model="grok-4.20-0309-non-reasoning",
        requested_model="xai/grok-4.20-0309-non-reasoning",
    )
    assert normalized == "xai/grok-4.20-0309-non-reasoning"


def test_normalize_live_invocation_model_keeps_openai_unchanged():
    normalized = normalize_live_invocation_model(
        provider="openai",
        model="gpt-4.1-mini",
        requested_model="gpt-4.1-mini",
    )
    assert normalized == "gpt-4.1-mini"


def test_validate_execution_selection_accepts_new_openai_models():
    provider, model = validate_execution_selection(provider="openai", model="gpt-5.5", mode="audit", env={})
    assert provider == "openai"
    assert model == "gpt-5.5"


def test_validate_execution_selection_rejects_removed_openai_model():
    try:
        validate_execution_selection(provider="openai", model="gpt-4o-mini", mode="audit", env={})
        assert False, "expected validation failure"
    except ValueError as exc:
        assert "unsupported model" in str(exc)


def test_live_mode_refuses_a_credential_with_a_trailing_newline():
    """Breaking this lets a key pasted with a newline reach the provider.

    SIR never reads this value: litellm reads the environment itself. So the
    whitespace travels with the credential and arrives as an authentication or
    illegal-header error that names no whitespace, and the reasonable
    conclusion from that error is that the key is wrong.
    """
    try:
        validate_execution_selection(
            provider="xai",
            model="grok-4.3",
            mode="live",
            env={"XAI_API_KEY": "not-a-credential\n"},
        )
        assert False, "expected validation failure"
    except ValueError as exc:
        message = str(exc)
        assert "XAI_API_KEY" in message
        assert "0 leading, 1 trailing" in message
        assert "will not strip it" in message


def test_live_mode_refuses_a_credential_with_a_leading_space():
    """Breaking this catches only the trailing case, which is half the paste."""
    try:
        validate_execution_selection(
            provider="xai",
            model="grok-4.3",
            mode="live",
            env={"XAI_API_KEY": "  not-a-credential"},
        )
        assert False, "expected validation failure"
    except ValueError as exc:
        assert "2 leading, 0 trailing" in str(exc)


def test_live_mode_accepts_a_credential_with_no_surrounding_whitespace():
    """Breaking this refuses every live run, which the check must not do.

    No provider credential legitimately carries surrounding whitespace, so the
    refusal above costs nothing that works today. This is what holds that.
    """
    provider, model = validate_execution_selection(
        provider="xai",
        model="grok-4.3",
        mode="live",
        env={"XAI_API_KEY": "not-a-credential"},
    )
    assert (provider, model) == ("xai", "grok-4.3")


def test_an_absent_credential_keeps_the_message_the_cli_test_asserts():
    """Breaking this drifts from tests/test_cli_run_py.py, which asserts it verbatim.

    Whitespace only is absent rather than malformed, so it takes this path and
    not the one above: there is no value to fix the whitespace around.
    """
    expected = "LIVE mode requires your own provider credentials (XAI_API_KEY)"
    for value in ("", "   ", "\n"):
        try:
            validate_execution_selection(
                provider="xai", model="grok-4.3", mode="live", env={"XAI_API_KEY": value}
            )
            assert False, "expected validation failure"
        except ValueError as exc:
            assert expected in str(exc), (value, str(exc))
            assert "will not strip it" not in str(exc)
