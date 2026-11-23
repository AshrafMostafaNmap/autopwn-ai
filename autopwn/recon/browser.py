"""Browser recon through Playwright (optional): rendered DOM, links, requests and
cookies. Cookie values are vaulted; only placeholders reach the model.
"""
from __future__ import annotations

from dataclasses import dataclass

from .target_model import Surface


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


@dataclass
class PageCapture:
    url: str
    title: str
    cookies: list[dict]                 # placeholder-only (LLM-safe)
    links: list[str]
    requests: list[str]


class BrowserSession:
    """Lazy Playwright wrapper. One session per target; close when done."""

    def __init__(self, *, headless: bool = True, storage_state: str | None = None):
        self.headless = headless
        self.storage_state = storage_state      # path to the operator's auth session
        self._pw = None
        self._browser = None
        self._context = None

    @staticmethod
    def _require():
        try:
            import playwright.sync_api  # noqa: F401
        except Exception as e:
            raise RuntimeError(
                "Browser recon needs Playwright. Install with "
                "`pip install autopwn-ai[browser]` then `playwright install chromium`. "
                f"import failed: {e}"
            ) from e

    def start(self):
        self._require()
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        self._context = self._browser.new_context(
            storage_state=self.storage_state or None,
            user_agent="AutoPwn-Recon/0.1 (+purple-team)",
        )
        return self

    def capture(self, url: str, *, vault, redactor=None, timeout: float = 20000) -> tuple[Surface, PageCapture]:
        if self._context is None:
            self.start()
        requests: list[str] = []
        page = self._context.new_page()
        page.on("request", lambda r: requests.append(r.url))
        page.goto(url, wait_until="networkidle", timeout=timeout)
        title = page.title()
        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
        raw_cookies = self._context.cookies()
        safe_cookies = ingest_cookies(raw_cookies, vault=vault, redactor=redactor)
        page.close()

        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        surface = Surface(host=host, domain="web", scheme=urlparse(url).scheme, title=title)
        surface.endpoints = [link for link in links if host in link][:50]
        surface.notes.append(f"browser: {len(links)} links, {len(raw_cookies)} cookie(s) vaulted, "
                             f"{len(set(requests))} requests")
        return surface, PageCapture(url=url, title=title, cookies=safe_cookies,
                                    links=links[:100], requests=sorted(set(requests))[:100])

    def close(self) -> None:
        for obj in (self._context, self._browser):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._context = self._browser = self._pw = None
