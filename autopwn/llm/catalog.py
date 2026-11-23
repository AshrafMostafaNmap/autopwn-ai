"""Providers and their tool-capable models. LiteLLM's model map, plus live lists
for OpenRouter (with free/tools flags) and local runtimes.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class ProviderInfo:
    id: str                          # litellm prefix, e.g. "anthropic"
    label: str
    env_var: str = ""                # where a key is read from if not stored locally
    requires_key: bool = True
    api_base: str | None = None      # default endpoint (local runtimes / gateways)
    needs_api_base: bool = False     # the operator must supply an endpoint
    catalog_keys: tuple[str, ...] = ()   # litellm_provider values in the model map
    featured: tuple[str, ...] = ()       # sensible defaults, shown first
    note: str = ""
    credentials_env: tuple[str, ...] = ()   # keyless providers: env that proves credentials exist


PROVIDERS: dict[str, ProviderInfo] = {p.id: p for p in [
    ProviderInfo("anthropic", "Anthropic", "ANTHROPIC_API_KEY", catalog_keys=("anthropic",),
                 featured=("anthropic/claude-sonnet-5-5", "anthropic/claude-opus-5-5",
                           "anthropic/claude-haiku-5-5")),
    ProviderInfo("openai", "OpenAI", "OPENAI_API_KEY", catalog_keys=("openai",),
                 featured=("openai/gpt-5.5", "openai/gpt-5.4-mini")),
    ProviderInfo("gemini", "Google Gemini", "GEMINI_API_KEY", catalog_keys=("gemini",),
                 featured=("gemini/gemini-3.1-pro-preview", "gemini/gemini-3.5-flash")),
    ProviderInfo("openrouter", "OpenRouter", "OPENROUTER_API_KEY", catalog_keys=("openrouter",),
                 featured=("openrouter/openrouter/free",),
                 note="one key, hundreds of models — live list incl. free ones"),
    ProviderInfo("groq", "Groq", "GROQ_API_KEY", catalog_keys=("groq",),
                 featured=("groq/openai/gpt-oss-120b",)),
    ProviderInfo("mistral", "Mistral", "MISTRAL_API_KEY", catalog_keys=("mistral",),
                 featured=("mistral/mistral-large-latest", "mistral/mistral-medium-latest")),
    ProviderInfo("deepseek", "DeepSeek", "DEEPSEEK_API_KEY", catalog_keys=("deepseek",),
                 featured=("deepseek/deepseek-chat",)),
    ProviderInfo("xai", "xAI", "XAI_API_KEY", catalog_keys=("xai",), featured=("xai/grok-4.20",)),
    ProviderInfo("together_ai", "Together AI", "TOGETHERAI_API_KEY", catalog_keys=("together_ai",),
                 featured=("together_ai/openai/gpt-oss-120b",
                           "together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo"),
                 note="serverless models only — dedicated ones need a deployment"),
    ProviderInfo("fireworks_ai", "Fireworks AI", "FIREWORKS_AI_API_KEY", catalog_keys=("fireworks_ai",),
                 featured=("fireworks_ai/accounts/fireworks/models/gpt-oss-120b",)),
    ProviderInfo("azure", "Azure OpenAI", "AZURE_API_KEY", needs_api_base=True,
                 catalog_keys=("azure",), note="set your Azure endpoint as the API base"),
    ProviderInfo("bedrock", "AWS Bedrock", requires_key=False, catalog_keys=("bedrock_converse", "bedrock"),
                 credentials_env=("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE"),
                 note="uses AWS credentials from your environment / profile"),
    ProviderInfo("ollama", "Ollama (local)", requires_key=False, api_base="http://localhost:11434",
                 catalog_keys=("ollama", "ollama_chat"), note="local — no key needed"),
    ProviderInfo("lm_studio", "LM Studio (local)", requires_key=False,
                 api_base="http://localhost:1234/v1", catalog_keys=("lm_studio",),
                 note="local — no key needed"),
    ProviderInfo("openai_compatible", "OpenAI-compatible", "OPENAI_COMPATIBLE_API_KEY",
                 requires_key=False, needs_api_base=True,
                 note="any OpenAI-compatible server (vLLM, gateways); key optional"),
]}

LOCAL_PROVIDERS = frozenset(p.id for p in PROVIDERS.values() if not p.requires_key and p.api_base)


def endpoint_reachable(api_base: str, timeout: float = 1.5) -> bool:
    """Is something listening at this endpoint? (Local runtimes may not be started.)"""
    import socket
    from urllib.parse import urlparse
    u = urlparse(api_base if "://" in api_base else f"http://{api_base}")
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        with socket.create_connection((u.hostname or "localhost", port), timeout=timeout):
            return True
    except OSError:
        return False


def is_local_endpoint(api_base: str | None) -> bool:
    from urllib.parse import urlparse
    if not api_base:
        return False
    host = urlparse(api_base if "://" in api_base else f"http://{api_base}").hostname or ""
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".localhost")


def provider_requires_key(provider_id: str) -> bool:
    info = PROVIDERS.get(provider_id)
    return info.requires_key if info else True


def provider_of(model: str) -> str:
    return model.split("/", 1)[0] if "/" in model else "openai"


def litellm_model(model: str) -> str:
    """The model id to hand LiteLLM. Our 'openai_compatible' provider is LiteLLM's
    'openai' route pointed at a custom api_base."""
    if model.startswith("openai_compatible/"):
        return "openai/" + model.split("/", 1)[1]
    return model


@dataclass
class ModelEntry:
    id: str                       # provider-prefixed
    provider: str
    context: int | None = None
    tools: bool | None = None     # None = unknown (local / not in the map)
    featured: bool = False
    free: bool = False            # costs nothing to call (OpenRouter ":free" etc.)

    @property
    def name(self) -> str:
        return self.id.split("/", 1)[1] if "/" in self.id else self.id


@lru_cache(maxsize=1)
def _model_map() -> dict:
    try:
        import litellm
        return dict(litellm.model_cost)
    except Exception:
        return {}


def model_info(model: str) -> dict | None:
    """Catalog entry for a model id (with or without the provider prefix).

    Never touches the network: live catalogs are consulted only if already
    fetched (call `warm_live()` from a worker thread first)."""
    live = _live_entry(model)
    if live is not None:
        return {"litellm_provider": live.provider, "mode": "chat",
                "max_input_tokens": live.context, "supports_function_calling": live.tools,
                "free": live.free}
    mm = _model_map()
    if model in mm:
        return mm[model]
    if "/" in model:
        bare = model.split("/", 1)[1]
        if bare in mm:
            return mm[bare]
    return None


def list_models(provider_id: str, *, tool_capable_only: bool = True,
                api_base: str | None = None) -> list[ModelEntry]:
    """Models for a provider, featured first. Local runtimes are queried live."""
    info = PROVIDERS.get(provider_id)
    if info is None:
        return []
    if provider_id in ("ollama", "lm_studio"):
        live = _local_models(provider_id, api_base or info.api_base)
        if live:
            return live
    if provider_id == "openrouter":
        live = openrouter_models()
        if live:
            shown = [m for m in live if m.tools or not tool_capable_only]
            for m in shown:
                m.featured = m.id in info.featured
            return sorted(shown, key=lambda m: (not m.featured, not m.free, m.id))

    out: dict[str, ModelEntry] = {}
    for key, v in _model_map().items():
        if not isinstance(v, dict) or v.get("litellm_provider") not in info.catalog_keys:
            continue
        if v.get("mode") not in (None, "chat"):
            continue
        tools = bool(v.get("supports_function_calling"))
        if tool_capable_only and not tools:
            continue
        mid = key if key.startswith(provider_id + "/") else f"{provider_id}/{key}"
        out[mid] = ModelEntry(mid, provider_id, v.get("max_input_tokens"), tools,
                              featured=mid in info.featured)
    for fid in info.featured:                       # always offer the featured ids
        out.setdefault(fid, ModelEntry(fid, provider_id, featured=True,
                                       tools=(model_info(fid) or {}).get("supports_function_calling")))
    return sorted(out.values(), key=lambda m: (not m.featured, m.id))


def _local_models(provider_id: str, api_base: str | None) -> list[ModelEntry]:
    """Ask a local runtime which models it has pulled (short timeout, best effort)."""
    if not api_base:
        return []
    try:
        import httpx
        if provider_id == "ollama":
            r = httpx.get(api_base.rstrip("/") + "/api/tags", timeout=1.5)
            names = [m["name"] for m in r.json().get("models", [])]
        else:
            r = httpx.get(api_base.rstrip("/") + "/models", timeout=1.5)
            names = [m["id"] for m in r.json().get("data", [])]
    except Exception:
        return []
    return [ModelEntry(f"{provider_id}/{n}", provider_id, tools=None) for n in names]


OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
_LIVE_TTL = 600.0                                   # seconds
_live_lock = threading.Lock()
_live: dict[str, tuple[float, dict[str, ModelEntry]]] = {}


def _is_free(pricing: dict | None) -> bool:
    p = pricing or {}
    try:
        return float(p.get("prompt", 1)) == 0.0 and float(p.get("completion", 1)) == 0.0
    except (TypeError, ValueError):
        return False


def openrouter_models(*, force: bool = False, timeout: float = 6.0) -> list[ModelEntry]:
    """OpenRouter's live model list (public endpoint, no key needed), cached for
    ten minutes. Returns [] if it cannot be reached — callers fall back to the
    static map."""
    now = time.time()
    with _live_lock:
        hit = _live.get("openrouter")
        if hit and not force and now - hit[0] < _LIVE_TTL:
            return list(hit[1].values())
    try:
        import httpx
        r = httpx.get(OPENROUTER_MODELS_URL, timeout=timeout)
        r.raise_for_status()
        rows = r.json().get("data", [])
    except Exception:
        return list(hit[1].values()) if hit else []
    entries: dict[str, ModelEntry] = {}
    for m in rows:
        mid = m.get("id")
        if not mid:
            continue
        full = f"openrouter/{mid}"
        entries[full] = ModelEntry(full, "openrouter", m.get("context_length"),
                                   "tools" in (m.get("supported_parameters") or []),
                                   free=_is_free(m.get("pricing")) or mid.endswith(":free"))
    with _live_lock:
        _live["openrouter"] = (now, entries)
    return list(entries.values())


def warm_live(provider_id: str) -> None:
    """Fetch a provider's live catalog if it has one (call off the UI thread)."""
    if provider_id == "openrouter":
        openrouter_models()


def _live_entry(model: str) -> ModelEntry | None:
    if not model.startswith("openrouter/"):
        return None
    with _live_lock:
        hit = _live.get("openrouter")
    return hit[1].get(model) if hit else None
