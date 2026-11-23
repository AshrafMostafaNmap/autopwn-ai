"""Check that an API key works before it is saved.

Each provider is asked for its model list (or key info), which is free: no
tokens are spent. The key always travels in a header, never in the URL.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from .catalog import PROVIDERS, endpoint_reachable

_BEARER = "bearer"
# provider → (url, auth style)
_ENDPOINTS: dict[str, tuple[str, str]] = {
    "anthropic": ("https://api.anthropic.com/v1/models", "anthropic"),
    "openai": ("https://api.openai.com/v1/models", _BEARER),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/models", "google"),
    "openrouter": ("https://openrouter.ai/api/v1/key", _BEARER),
    "groq": ("https://api.groq.com/openai/v1/models", _BEARER),
    "mistral": ("https://api.mistral.ai/v1/models", _BEARER),
    "deepseek": ("https://api.deepseek.com/models", _BEARER),
    "xai": ("https://api.x.ai/v1/models", _BEARER),
    "together_ai": ("https://api.together.xyz/v1/models", _BEARER),
    "fireworks_ai": ("https://api.fireworks.ai/inference/v1/models", _BEARER),
}


@dataclass
class KeyCheck:
    ok: bool                 # safe to save
    verified: bool           # the provider confirmed it
    message: str


def _headers(style: str, key: str) -> dict[str, str]:
    if style == "anthropic":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    if style == "google":
        return {"x-goog-api-key": key}
    return {"Authorization": f"Bearer {key}"}


def check_key(provider_id: str, key: str | None, api_base: str | None = None, *,
              timeout: float = 10.0, client: httpx.Client | None = None) -> KeyCheck:
    info = PROVIDERS.get(provider_id)
    label = info.label if info else provider_id
    base = api_base or (info.api_base if info else None)
    if info is not None and info.needs_api_base and not base:
        return KeyCheck(False, False, f"{label} needs an endpoint (API base URL)")
    if info is not None and not info.requires_key and base:
        if endpoint_reachable(base, timeout=2.0):
            return KeyCheck(True, True, f"{label} is reachable at {base}")
        return KeyCheck(True, False, f"{label} is not running at {base} yet — saved; start it before chatting")
    if not key:
        return KeyCheck(False, False, "paste a key first")
    endpoint = _ENDPOINTS.get(provider_id)
    if endpoint is None:
        return KeyCheck(True, False, f"saved — {label} keys can't be checked in advance")
    url, style = endpoint
    own = client is None
    client = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        resp = client.get(url, headers=_headers(style, key))
    except httpx.HTTPError as e:
        return KeyCheck(True, False, f"saved, but {label} could not be reached to check it ({type(e).__name__})")
    finally:
        if own:
            client.close()
    if resp.status_code < 300:
        return KeyCheck(True, True, f"{label} key works")
    body = resp.text[:2000].lower()
    rejected = resp.status_code in (401, 403) or (
        resp.status_code == 400 and any(s in body for s in ("api key", "api_key", "apikey")))
    if rejected:
        return KeyCheck(False, False, f"{label} rejected this key (HTTP {resp.status_code}) — check it and try again")
    if resp.status_code == 429:
        return KeyCheck(True, True, f"{label} key accepted (rate-limited right now)")
    return KeyCheck(True, False, f"saved, but {label} answered HTTP {resp.status_code} — could not confirm the key")
