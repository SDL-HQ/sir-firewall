from __future__ import annotations

import os
from typing import Mapping

DEFAULT_PROVIDER = "xai"
DEFAULT_MODEL = "grok-4-1-fast"

SUPPORTED_MODELS_BY_PROVIDER: dict[str, tuple[str, ...]] = {
    "xai": (
        "grok-3-beta",
        "grok-4-1-fast",
        "grok-4.20-0309-reasoning",
        "grok-4.20-0309-non-reasoning",
    ),
    "openai": (
        "gpt-4.1-mini",
        "gpt-4.1",
        "gpt-5-mini",
        "gpt-5.4-mini",
        "gpt-5.5",
    ),
}

PROVIDER_SECRET_ENV: dict[str, str] = {
    "xai": "XAI_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def supported_providers() -> tuple[str, ...]:
    return tuple(SUPPORTED_MODELS_BY_PROVIDER.keys())


def normalize_provider(provider: str | None) -> str:
    p = (provider or "").strip().lower()
    return p or DEFAULT_PROVIDER


def _split_model_prefix(model: str | None) -> tuple[str | None, str]:
    raw = str(model or "").strip()
    if "/" not in raw:
        return None, raw
    prefix, rest = raw.split("/", 1)
    prefix = prefix.strip().lower()
    rest = rest.strip()
    if prefix in SUPPORTED_MODELS_BY_PROVIDER and rest:
        return prefix, rest
    return None, raw


def resolve_provider_model(provider: str | None, model: str | None) -> tuple[str, str]:
    explicit_provider = normalize_provider(provider)
    inferred_provider, normalized_model = _split_model_prefix(model)

    if inferred_provider is not None:
        if explicit_provider and explicit_provider != inferred_provider:
            raise ValueError(
                f"provider/model mismatch: --provider {explicit_provider!r} does not match model prefix {inferred_provider!r}"
            )
        explicit_provider = inferred_provider

    if not normalized_model:
        normalized_model = DEFAULT_MODEL

    ensure_supported_provider(explicit_provider)
    ensure_supported_model(explicit_provider, normalized_model)
    return explicit_provider, normalized_model


def ensure_supported_provider(provider: str) -> None:
    if provider not in SUPPORTED_MODELS_BY_PROVIDER:
        raise ValueError(
            f"unsupported provider {provider!r}; supported providers: {', '.join(sorted(supported_providers()))}"
        )


def ensure_supported_model(provider: str, model: str) -> None:
    supported = SUPPORTED_MODELS_BY_PROVIDER.get(provider, ())
    if model not in supported:
        raise ValueError(
            f"unsupported model {model!r} for provider {provider!r}; supported models: {', '.join(supported)}"
        )


def required_secret_for_provider(provider: str) -> str:
    return PROVIDER_SECRET_ENV[provider]


def validate_execution_selection(
    *,
    provider: str | None,
    model: str | None,
    mode: str,
    env: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    resolved_provider, resolved_model = resolve_provider_model(provider, model)

    if mode == "live":
        lookup = env if env is not None else os.environ
        secret_name = required_secret_for_provider(resolved_provider)
        if not str(lookup.get(secret_name, "")).strip():
            raise ValueError(
                "LIVE mode requires your own provider credentials "
                f"({secret_name}) for provider '{resolved_provider}'. SIR does not ship keys."
            )

    return resolved_provider, resolved_model


def normalize_live_invocation_model(*, provider: str, model: str, requested_model: str | None = None) -> str:
    """
    Return the model string that should be handed to the downstream LiteLLM call.

    Rules are intentionally narrow:
    - xai + bare model -> prefix with "xai/"
    - xai + already provider-qualified request -> keep as-is
    - non-xai providers -> unchanged
    """
    if provider != "xai":
        return model

    requested = str(requested_model or "").strip()
    if requested.lower().startswith("xai/"):
        return requested

    if model.lower().startswith("xai/"):
        return model

    return f"xai/{model}"
