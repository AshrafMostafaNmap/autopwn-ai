"""Token counting for context budgeting."""
from __future__ import annotations

from collections.abc import Callable

from .catalog import litellm_model, model_info
from .provider import Message

Counter = Callable[[Message], int]

DEFAULT_WINDOW = 32_000            # unknown/local models: assume a modest window


def _count(model: str, msg: Message) -> int:
    try:
        import litellm
        return int(litellm.token_counter(model=litellm_model(model), messages=[msg.to_openai()]))
    except Exception:
        text = (msg.content or "") + "".join(f"{c.name}{c.arguments}" for c in msg.tool_calls)
        return max(1, len(text) // 4) + 4


def make_counter(model: str) -> Counter:
    """A counter that tokenizes each message once and caches the result on it."""
    def count(msg: Message) -> int:
        if msg.tokens is None:
            msg.tokens = _count(model, msg)
        return msg.tokens
    return count


def context_window(model: str) -> int:
    info = model_info(model) or {}
    return int(info.get("max_input_tokens") or info.get("max_tokens") or DEFAULT_WINDOW)
