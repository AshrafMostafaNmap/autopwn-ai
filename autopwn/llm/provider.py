"""LLMProvider: our own message/tool types over LiteLLM, so the agent is written
once against this interface whatever provider is behind it.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ..config import LLMConfig
from .catalog import litellm_model, provider_of


# ── errors ───────────────────────────────────────────────────────────────────
class LLMError(Exception):
    """Base for LLM-layer failures."""


class ModelNotToolCapable(LLMError):
    """The configured model does not support tool/function calling."""


class MissingAPIKey(LLMError):
    """No API key available for a provider that needs one."""


class MissingEndpoint(LLMError):
    """The provider needs an endpoint (API base) and none is set."""


class ProviderUnreachable(LLMError):
    """A local runtime (Ollama, LM Studio, a local server) is not running."""


# ── wire types (ours, provider-agnostic) ─────────────────────────────────────
@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None


@dataclass
class ToolSpec:
    """A tool the model may call. `parameters` is a JSON-Schema object."""
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})

    def to_openai(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolCall:
    """A tool invocation the model requested."""
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Message:
    """One chat message in our own shape. Roles: system | user | assistant | tool."""
    role: str
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None     # when role == "tool"
    name: str | None = None             # tool name when role == "tool"
    tokens: int | None = field(default=None, repr=False, compare=False)   # counted once, cached

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content, "tool_call_id": self.tool_call_id,
                "name": self.name,
                "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments}
                               for c in self.tool_calls]}

    @classmethod
    def from_dict(cls, d: dict) -> Message:
        return cls(d["role"], d.get("content"),
                   [ToolCall(c["id"], c["name"], c.get("arguments") or {}) for c in d.get("tool_calls") or []],
                   d.get("tool_call_id"), d.get("name"))

    def to_openai(self) -> dict:
        import json
        msg: dict[str, Any] = {"role": self.role}
        if self.content is not None:
            msg["content"] = self.content
        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                }
                for tc in self.tool_calls
            ]
            msg.setdefault("content", None)
        if self.role == "tool":
            msg["tool_call_id"] = self.tool_call_id
            if self.name:
                msg["name"] = self.name
        return msg

    # convenient constructors
    @classmethod
    def system(cls, text: str) -> Message: return cls("system", text)
    @classmethod
    def user(cls, text: str) -> Message: return cls("user", text)
    @classmethod
    def assistant(cls, text: str | None = None, tool_calls: list[ToolCall] | None = None) -> Message:
        return cls("assistant", text, tool_calls or [])
    @classmethod
    def tool(cls, tool_call_id: str, content: str, name: str | None = None) -> Message:
        return cls("tool", content, tool_call_id=tool_call_id, name=name)


@dataclass
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: Usage = field(default_factory=Usage)
    model: str = ""
    raw: Any = None

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


# ── the adapter ──────────────────────────────────────────────────────────────
class LLMProvider:
    """Provider-agnostic chat/completion with normalized tool-calling."""

    def __init__(self, config: LLMConfig):
        self.config = config
        # Import lazily so the package imports without litellm installed
        # (CLI help, tests that don't touch the LLM, etc.).
        import litellm  # noqa: F401
        self._litellm = litellm
        # Keep LiteLLM quiet and predictable.
        litellm.drop_params = True          # ignore params a given provider doesn't support
        if hasattr(litellm, "suppress_debug_info"):
            litellm.suppress_debug_info = True

    # ── capability gate ───────────────────────────────────────────────────────
    def tool_support(self) -> bool | None:
        """True / False when a catalog knows the model; None when it doesn't
        (local or brand-new models). Unknown is not the same as unsupported.
        Live provider catalogs (OpenRouter) are authoritative for their models."""
        from .catalog import model_info, provider_of, warm_live
        warm_live(provider_of(self.config.model))
        info = model_info(self.config.model)
        if info is None:
            return None
        if info.get("supports_function_calling") is not None:
            return bool(info["supports_function_calling"])
        try:
            return bool(self._litellm.supports_function_calling(model=self.config.model))
        except Exception:
            return None

    def supports_tools(self) -> bool:
        return self.tool_support() is not False

    def ensure_ready(self) -> list[str]:
        """Startup gate. Call once before the agent loop begins. Returns
        non-fatal warnings (e.g. tool support could not be verified).

        - verifies an API key exists when the provider needs one
        - rejects a model the catalog knows cannot call tools
        """
        warnings: list[str] = []
        from .catalog import PROVIDERS, endpoint_reachable, is_local_endpoint, provider_of
        pid = provider_of(self.config.model)
        info = PROVIDERS.get(pid)
        label = info.label if info else pid
        if info is not None and info.needs_api_base and not self.config.api_base:
            raise MissingEndpoint(f"{label} needs an endpoint (API base URL) — set it in /provider")
        if info is not None and info.credentials_env and not _has_credentials(info.credentials_env):
            raise MissingAPIKey(f"{label} needs credentials in the environment "
                                f"({' / '.join(info.credentials_env)}, or ~/.aws/credentials)")
        if is_local_endpoint(self.config.api_base) and not endpoint_reachable(self.config.api_base):
            raise ProviderUnreachable(f"{label} is not running at {self.config.api_base} — start it, "
                                      f"or change the endpoint in /provider")
        if self.config.requires_key and not self.config.api_key():
            where = f"${self.config.api_key_env}" if self.config.api_key_env else "a key"
            raise MissingAPIKey(
                f"no API key for '{self.config.model}': connect the provider in the app "
                f"(/provider) or set {where} in the environment"
            )
        if self.config.require_tool_calling:
            support = self.tool_support()
            if support is False:
                raise ModelNotToolCapable(
                    f"model '{self.config.model}' does not support tool-calling, which the "
                    f"agent requires. Choose a tool-capable model (/model)."
                )
            if support is None:
                warnings.append(f"tool-calling support for '{self.config.model}' is unverified "
                                f"(not in the model catalog) — the first request will confirm it")
        return warnings

    # ── completion ────────────────────────────────────────────────────────────
    def _common_kwargs(self, tools: list[ToolSpec] | None) -> dict:
        kw: dict[str, Any] = {
            "model": litellm_model(self.config.model),
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "timeout": self.config.timeout,
            # transient failures (rate limits, 5xx, dropped connections) are retried
            # with exponential backoff before the turn reports an error
            "num_retries": self.config.retries,
        }
        if self.config.api_base:
            kw["api_base"] = self.config.api_base
        key = self.config.api_key()
        if key:
            kw["api_key"] = key
        elif not self.config.requires_key and self.config.api_base:
            # keyless server on the OpenAI route: an explicit placeholder stops the
            # client from picking up (and sending) an unrelated OPENAI_API_KEY
            kw["api_key"] = "not-needed"
        if tools:
            kw["tools"] = [t.to_openai() for t in tools]
            kw["tool_choice"] = "auto"
        return kw

    def complete(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        **extra: Any,
    ) -> LLMResponse:
        """One non-streaming round-trip. Returns our normalized response."""
        payload = [m.to_openai() for m in messages]
        try:
            resp = self._litellm.completion(messages=payload, **{**self._common_kwargs(tools), **extra})
        except Exception as e:                       # normalize provider errors
            raise LLMError(explain_error(e, self.config.model)) from e
        return self._parse(resp)

    def stream(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        **extra: Any,
    ) -> Iterator[str]:
        """Yield text chunks as they arrive (content only; tool-call streaming is
        assembled later when the agent loop needs it)."""
        payload = [m.to_openai() for m in messages]
        try:
            stream = self._litellm.completion(
                messages=payload, stream=True, **{**self._common_kwargs(tools), **extra}
            )
            for chunk in stream:
                delta = chunk.choices[0].delta
                piece = getattr(delta, "content", None)
                if piece:
                    yield piece
        except Exception as e:
            raise LLMError(explain_error(e, self.config.model)) from e

    # ── response parsing ──────────────────────────────────────────────────────
    def _parse(self, resp: Any) -> LLMResponse:
        import json
        choice = resp.choices[0]
        msg = choice.message
        tool_calls: list[ToolCall] = []
        for tc in (getattr(msg, "tool_calls", None) or []):
            fn = tc.function
            try:
                args = json.loads(fn.arguments) if fn.arguments else {}
            except (json.JSONDecodeError, TypeError):
                args = {"_raw": fn.arguments}
            tool_calls.append(ToolCall(id=tc.id, name=fn.name, arguments=args))

        usage = Usage()
        u = getattr(resp, "usage", None)
        if u is not None:
            usage.prompt_tokens = getattr(u, "prompt_tokens", 0) or 0
            usage.completion_tokens = getattr(u, "completion_tokens", 0) or 0
            usage.total_tokens = getattr(u, "total_tokens", 0) or 0
        # LiteLLM attaches a cost estimate on the hidden params when available.
        try:
            hidden = getattr(resp, "_hidden_params", {}) or {}
            usage.cost_usd = hidden.get("response_cost")
        except Exception:
            pass

        return LLMResponse(
            content=getattr(msg, "content", None),
            tool_calls=tool_calls,
            finish_reason=getattr(choice, "finish_reason", None),
            usage=usage,
            model=getattr(resp, "model", self.config.model),
            raw=resp,
        )


# ── provider errors → messages an operator can act on ─────────────────────────
def _upstream_detail(text: str) -> str:
    """Pull the human part out of a provider's JSON error blob."""
    import re
    for pattern in (r'"raw"\s*:\s*"((?:[^"\\]|\\.)*)"', r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"',
                    r'"detail"\s*:\s*"((?:[^"\\]|\\.)*)"', r'"error"\s*:\s*"((?:[^"\\]|\\.)*)"'):
        m = re.search(pattern, text)
        if m and m.group(1) and m.group(1) != "Provider returned error":
            return m.group(1).replace('\\"', '"')[:240]
    return text.strip().splitlines()[0][:240] if text.strip() else ""


def _has_credentials(names: tuple[str, ...]) -> bool:
    import os
    from pathlib import Path
    if any(os.environ.get(n) for n in names):
        return True
    return Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")).expanduser().is_file()


def explain_error(e: Exception, model: str) -> str:
    """Turn a LiteLLM/provider exception into a short, actionable message."""
    name = type(e).__name__
    detail = _upstream_detail(str(e))
    free = ":free" in model or model.endswith("/free")
    if name == "RateLimitError":
        hint = (" Free models are shared and often busy — retry in a moment, or switch "
                "(/model) to openrouter/openrouter/free, which routes to an available free model."
                if free else " Retry shortly or pick another model (/model).")
        return f"rate limited by the provider for {model}: {detail}.{hint}"
    low = f"{detail} {e}".lower()
    local = provider_of(model) in ("ollama", "lm_studio", "openai_compatible")
    if local and any(s in low for s in ("connection refused", "connection error", "connecterror",
                                        "failed to establish", "name or service not known")):
        return (f"could not reach the local model server for {model} — is it running? "
                f"Start it, or check the endpoint in /provider.")
    if name == "BadRequestError" and any(s in low for s in ("api key", "api_key", "apikey", "unauthorized")):
        name = "AuthenticationError"
    if "unable to locate credentials" in low:
        return f"no cloud credentials found for {model} — configure them (e.g. AWS_PROFILE) and retry."
    if name in ("AuthenticationError", "PermissionDeniedError"):
        return (f"the provider rejected the API key for {model} ({detail}). "
                f"Reconnect it in /provider.")
    if name == "NotFoundError":
        if "inaccessible" in low:
            return (f"{model} was not found or this API key cannot access it ({detail}). "
                    f"Check the key in /provider or pick another model in /model.")
        return f"model not found: {model} ({detail}). Pick an available one in /model."
    if name == "ContextWindowExceededError":
        return f"the conversation no longer fits {model}'s context window — use /compact or /new."
    if name in ("Timeout", "APIConnectionError"):
        return f"could not reach the provider for {model} ({detail}). Check the network and retry."
    if name in ("ServiceUnavailableError", "InternalServerError"):
        return f"the provider had a server error for {model} ({detail}). Retry shortly."
    if name == "BadRequestError" and "tool" in detail.lower():
        return f"{model} rejected the tool definitions ({detail}). Choose a model with tool support (/model)."
    return f"{name}: {detail}" if detail else name
