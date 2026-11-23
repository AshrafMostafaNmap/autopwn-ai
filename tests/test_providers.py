"""Provider readiness and error messages: what the operator sees when a provider
is not set up, not running, or rejects the request."""
from __future__ import annotations

import pytest

import autopwn.llm.catalog as catalog
from autopwn.config import LLMConfig
from autopwn.llm.catalog import PROVIDERS, is_local_endpoint
from autopwn.llm.provider import (
    LLMProvider,
    MissingAPIKey,
    MissingEndpoint,
    ProviderUnreachable,
    explain_error,
)


def _provider(model, base=None, key=None):
    pid = model.split("/", 1)[0]
    cfg = LLMConfig(model=model, provider=pid, api_key_env=PROVIDERS[pid].env_var, api_base=base,
                    require_tool_calling=False)
    cfg.api_key_value = key
    return LLMProvider(cfg)


def test_local_runtime_not_running(monkeypatch):
    monkeypatch.setattr(catalog, "endpoint_reachable", lambda base, timeout=1.5: False)
    with pytest.raises(ProviderUnreachable, match="LM Studio .* is not running at http://localhost:1234/v1"):
        _provider("lm_studio/qwen", "http://localhost:1234/v1").ensure_ready()


@pytest.mark.parametrize("model", ["azure/my-deployment", "openai_compatible/my-model"])
def test_endpoint_required(model):
    with pytest.raises(MissingEndpoint, match="needs an endpoint"):
        _provider(model, key="k").ensure_ready()


def test_bedrock_needs_cloud_credentials(monkeypatch, tmp_path):
    for v in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    with pytest.raises(MissingAPIKey, match="AWS_ACCESS_KEY_ID"):
        _provider("bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0").ensure_ready()
    monkeypatch.setenv("AWS_PROFILE", "lab")
    _provider("bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0").ensure_ready()


def test_keyless_compatible_server_never_gets_the_openai_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-openai-key")
    kw = _provider("openai_compatible/m", "http://10.0.0.9:8000/v1")._common_kwargs(None)
    assert kw["api_key"] == "not-needed" and kw["model"] == "openai/m"
    assert PROVIDERS["openai_compatible"].env_var != "OPENAI_API_KEY"


def test_local_endpoint_detection():
    assert is_local_endpoint("http://localhost:11434") and is_local_endpoint("http://127.0.0.1:1234/v1")
    assert not is_local_endpoint("https://api.example.com/v1") and not is_local_endpoint(None)


def _named(name, msg):
    return type(name, (Exception,), {})(msg)


def test_error_messages_are_actionable():
    bad_key = _named("BadRequestError", 'XaiException - {"code":"invalid-argument","error":"Incorrect API key provided."}')
    assert "rejected the API key" in explain_error(bad_key, "xai/grok-4.20")
    nf = _named("NotFoundError", "Model not found, inaccessible, and/or not deployed")
    assert "cannot access it" in explain_error(nf, "fireworks_ai/accounts/fireworks/models/x")
    down = _named("InternalServerError", "Lm_studioException - Connection error.")
    assert "local model server" in explain_error(down, "lm_studio/qwen")
    mistral = _named("AuthenticationError", 'MistralException - {"detail":"Invalid API Key"}')
    assert "(Invalid API Key)" in explain_error(mistral, "mistral/mistral-large-latest")


def test_every_featured_model_is_tool_capable():
    for p in PROVIDERS.values():
        for mid in p.featured:
            if mid.startswith("openrouter/"):
                continue
            info = catalog.model_info(mid)
            assert info, f"{mid} missing from the model map"
            assert info.get("supports_function_calling") is not False, mid


def test_status_marks_local_runtimes_that_are_down(make_session, monkeypatch):
    import autopwn.engine as engine
    engine._PROBE_CACHE.clear()
    monkeypatch.setattr(engine, "endpoint_reachable", lambda base, timeout=0.8: "11434" in base)
    rows = {r["id"]: r for r in make_session().provider_status()}
    assert rows["ollama"]["connected"] and not rows["lm_studio"]["connected"]
    assert rows["lm_studio"]["source"] == "not running"
    assert rows["openai_compatible"]["source"] == "needs an endpoint"
    engine._PROBE_CACHE.clear()
