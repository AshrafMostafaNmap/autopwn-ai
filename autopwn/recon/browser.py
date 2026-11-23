"""Cookie intake for the vault: cookie values become placeholders before any
browser data reaches the model (the browser itself lives in autopwn/browser)."""
from __future__ import annotations


def ingest_cookies(cookies: list[dict], *, vault, redactor=None) -> list[dict]:
    """Tokenize cookie VALUES into the vault; return cookies with placeholders.

    This is the cookie → placeholder flow the data-governance DoD requires, and
    it is pure/testable with no browser. The returned list is safe for the LLM;
    the vault holds the real values for local re-injection."""
    safe: list[dict] = []
    for c in cookies:
        name = c.get("name", "")
        value = c.get("value", "")
        placeholder = vault.tokenize(value, kind="cookie", hint=f"cookie:{name}") if value else value
        safe.append({
            "name": name,
            "value": placeholder,                 # «secret:cookie.N» — never the real value
            "domain": c.get("domain", ""),
            "path": c.get("path", "/"),
            "httpOnly": c.get("httpOnly", False),
            "secure": c.get("secure", False),
        })
    return safe
