"""LLM integration layer — our own types over LiteLLM (provider-agnostic)."""
import os

# LiteLLM fetches its model map from GitHub on import (seconds, or a long hang on a
# slow link); the copy bundled with the package is used unless the operator opts in.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

from .provider import (  # noqa: E402
    LLMError,
    LLMProvider,
    LLMResponse,
    Message,
    MissingAPIKey,
    ModelNotToolCapable,
    ToolCall,
    ToolSpec,
    Usage,
)

__all__ = [
    "LLMProvider", "Message", "ToolSpec", "ToolCall", "LLMResponse", "Usage",
    "LLMError", "ModelNotToolCapable", "MissingAPIKey",
]
