"""A real, headless Chromium driven through Playwright — one per session.

Everything a person would read in DevTools is captured as the agent browses:
Elements, Console, Sources, Network, Performance/Memory, Application and
Security. Playwright's sync API must stay on one thread, so the browser lives on
its own worker thread and every call is marshalled onto it.

Governance: top-level navigations to hosts outside scope are aborted inside the
browser (redirects included); typed values may hold «secret:…» placeholders that
are resolved locally; cookie and storage values are vaulted before anything is
returned; links that look state-changing (logout, delete, …) are never followed.
"""
from __future__ import annotations

import json
import re
import secrets
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from . import checks

USER_AGENT_SUFFIX = " AutoPwnAI/0.1 (+authorized security testing)"
SKIP_LINK = re.compile(r"logout|log-out|signout|sign-out|delete|remove|destroy|drop|reset|unsubscribe|"
                       r"deactivate|cancel|revoke|purge|wipe", re.I)
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
BODY_TYPES = ("script", "xhr", "fetch", "document")
MAX_BODY = 2_000_000

_SNAPSHOT_JS = """() => {
  const sel = 'a[href],button,input,select,textarea,[role=button],[role=link],[onclick],summary,form';
  const out = []; let n = 0;
  for (const el of document.querySelectorAll(sel)) {
    const r = el.getBoundingClientRect();
    const visible = !!(r.width || r.height) && getComputedStyle(el).visibility !== 'hidden';
    const ref = 'e' + (++n);
    el.setAttribute('data-autopwn-ref', ref);
    out.push({ref, tag: el.tagName.toLowerCase(), type: el.type || '', name: el.name || el.id || '',
      text: (el.innerText || el.value || el.placeholder || el.getAttribute('aria-label') || '').trim().slice(0, 80),
      href: el.getAttribute('href') || '', action: el.getAttribute('action') || '', visible});
    if (n >= 300) break;
  }
  return out;
}"""

_DOM_JS = """(selector) => {
  const q = s => Array.from(document.querySelectorAll(s));
  const comments = []; const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  while (walker.nextNode() && comments.length < 30) comments.push(walker.currentNode.nodeValue.trim().slice(0, 200));
  const forms = q('form').slice(0, 30).map(f => ({action: f.getAttribute('action') || '', method: (f.method || 'get').toUpperCase(),
    inputs: Array.from(f.elements).slice(0, 40).map(i => ({name: i.name || '', type: i.type || i.tagName.toLowerCase(),
      autocomplete: i.getAttribute('autocomplete') || '', hidden: i.type === 'hidden', required: !!i.required}))}));
  const handlers = q('*').filter(e => Array.from(e.attributes).some(a => a.name.startsWith('on'))).length;
  const el = selector ? document.querySelector(selector) : null;
  return {title: document.title, url: location.href, forms, comments,
    links: q('a[href]').slice(0, 300).map(a => a.href),
    iframes: q('iframe').map(f => f.src).slice(0, 20),
    meta: q('meta[name],meta[http-equiv]').map(m => (m.name || m.httpEquiv) + '=' + (m.content || '').slice(0, 120)).slice(0, 30),
    inline_scripts: q('script:not([src])').length, external_scripts: q('script[src]').map(s => s.src).slice(0, 100),
    inline_handlers: handlers, html: el ? el.outerHTML.slice(0, 20000) : null};
}"""

_APP_JS = """async () => {
  const dump = s => { const o = {}; for (let i = 0; i < s.length; i++) { const k = s.key(i); o[k] = s.getItem(k); } return o; };
  let idb = [], caches_ = [], workers = [];
  try { idb = (await indexedDB.databases()).map(d => ({name: d.name, version: d.version})); } catch (e) {}
  try { caches_ = await caches.keys(); } catch (e) {}
  try { workers = (await navigator.serviceWorker.getRegistrations()).map(r => ({scope: r.scope,
        script: (r.active || r.installing || r.waiting || {}).scriptURL || ''})); } catch (e) {}
  const manifest = (document.querySelector('link[rel=manifest]') || {}).href || '';
  return {localStorage: dump(localStorage), sessionStorage: dump(sessionStorage), indexedDB: idb,
          cacheStorage: caches_, serviceWorkers: workers, manifest,
          frames: Array.from(document.querySelectorAll('iframe')).map(f => f.src)};
}"""

_PERF_JS = """() => {
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const res = performance.getEntriesByType('resource');
  const by = {}; let bytes = 0;
  for (const r of res) { by[r.initiatorType] = (by[r.initiatorType] || 0) + 1; bytes += r.transferSize || 0; }
  const mem = performance.memory ? {usedJSHeapSize: performance.memory.usedJSHeapSize,
      totalJSHeapSize: performance.memory.totalJSHeapSize, jsHeapSizeLimit: performance.memory.jsHeapSizeLimit} : null;
  return {timing: {ttfb: Math.round(nav.responseStart || 0), domContentLoaded: Math.round(nav.domContentLoadedEventEnd || 0),
      load: Math.round(nav.loadEventEnd || 0)}, resources: res.length, resourceTypes: by, transferBytes: bytes,
      memory: mem, domNodes: document.getElementsByTagName('*').length};
}"""


def _tls_info(url: str) -> dict | None:
    """Certificate and protocol of the page's host, read directly over TLS."""
    import socket
    import ssl
    u = urlsplit(url)
    host, port = u.hostname or "", u.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
            info = {"protocol": s.version(), "cipher": (s.cipher() or ("",))[0]}
    except OSError as e:
        return {"error": str(e)[:160]}
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        info.update({"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                     "valid_from": cert.not_valid_before_utc.isoformat(),
                     "valid_to": cert.not_valid_after_utc.isoformat(),
                     "self_signed": cert.subject == cert.issuer})
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            info["names"] = san.get_values_for_type(x509.DNSName)[:20]
        except x509.ExtensionNotFound:
            pass
    except Exception:
        pass
    return info


def _doc_key(url: str) -> str:
    return url.split("#", 1)[0]


class BrowserUnavailable(RuntimeError):
    pass


def browser_available() -> tuple[bool, str]:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False, "Playwright is not installed — run: autopwnai tools install browser"
    return True, ""


class BrowserEngine:
    def __init__(self, *, guard=None, vault=None, artifacts_dir: Path | None = None, headless: bool = True,
                 storage_state: str | None = None, nav_timeout_ms: int = 20_000):
        self.guard, self.vault = guard, vault
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else None
        self.headless, self.storage_state, self.nav_timeout_ms = headless, storage_state, nav_timeout_ms
        self._exec = ThreadPoolExecutor(max_workers=1, thread_name_prefix="autopwn-browser")
        self._pw = self._browser = self._context = self.page = None
        self.launched_with = ""
        self.network: deque[dict] = deque(maxlen=3000)
        self.console: deque[dict] = deque(maxlen=800)
        self.websockets: list[str] = []
        self.blocked: list[str] = []
        self.bodies: dict[str, str] = {}             # url → text body of scripts / API responses
        self.documents: dict[str, dict] = {}         # url → {status, headers} of top-level documents
        self.visited: dict[str, dict] = {}           # pages opened or crawled
        self._pending: list = []
        self._seq = 0

    # ── thread marshalling ─────────────────────────────────────────────────────
    def call(self, fn, *args, timeout: float = 600.0, **kw):
        return self._exec.submit(self._guarded, fn, *args, **kw).result(timeout=timeout)

    def _guarded(self, fn, *args, **kw):
        self._ensure()
        try:
            return fn(*args, **kw)
        finally:
            self._drain()

    def close(self) -> None:
        def stop():
            for obj in (self._context, self._browser):
                try:
                    if obj is not None:
                        obj.close()
                except Exception:
                    pass
            try:
                if self._pw is not None:
                    self._pw.stop()
            except Exception:
                pass
            self._pw = self._browser = self._context = self.page = None
        if self._pw is not None:
            try:
                self._exec.submit(stop).result(timeout=30)
            except Exception:
                pass
        self._exec.shutdown(wait=False, cancel_futures=True)

    # ── launch ─────────────────────────────────────────────────────────────────
    def _ensure(self) -> None:
        if self.page is not None:
            return
        ok, why = browser_available()
        if not ok:
            raise BrowserUnavailable(why)
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        errors = []
        for label, kw in (("chromium", {}), ("chrome", {"channel": "chrome"}), ("msedge", {"channel": "msedge"})):
            try:
                self._browser = self._pw.chromium.launch(headless=self.headless, **kw)
                self.launched_with = label
                break
            except Exception as e:
                errors.append(f"{label}: {str(e).splitlines()[0][:120]}")
        if self._browser is None:
            self._pw.stop()
            self._pw = None
            raise BrowserUnavailable("no browser could be started — run: autopwnai tools install browser "
                                     f"({'; '.join(errors)})")
        probe = self._browser.new_context()
        ua = probe.new_page().evaluate("navigator.userAgent")
        probe.close()
        opts: dict[str, Any] = {"ignore_https_errors": True, "user_agent": ua.replace("Headless", "") + USER_AGENT_SUFFIX,
                                "java_script_enabled": True}
        if self.storage_state and Path(self.storage_state).is_file():
            opts["storage_state"] = self.storage_state
        self._context = self._browser.new_context(**opts)
        self._context.set_default_navigation_timeout(self.nav_timeout_ms)
        self._context.set_default_timeout(10_000)
        self._context.route("**/*", self._route)
        self.page = self._context.new_page()
        self._attach(self.page)

    def _attach(self, page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", lambda r: self._mark(r, failed=r.failure or "failed"))
        page.on("console", lambda m: self.console.append({"type": m.type, "text": m.text[:2000],
                                                          "url": (m.location or {}).get("url", ""),
                                                          "page": page.url, "t": time.time()}))
        page.on("pageerror", lambda e: self.console.append({"type": "pageerror", "text": str(e)[:2000],
                                                            "page": page.url, "t": time.time()}))
        page.on("websocket", lambda ws: self.websockets.append(ws.url))

    def _route(self, route, request) -> None:
        """Navigations are fetched here without following redirects, so every hop
        is checked against scope before the browser may go there (Playwright does
        not route redirect hops on its own)."""
        if not (request.is_navigation_request() and self.guard is not None):
            route.continue_()
            return
        if not self.guard.check_host(request.url).allowed:
            self.blocked.append(request.url)
            route.abort("blockedbyclient")
            return
        try:
            resp = route.fetch(max_redirects=0)
        except Exception:
            route.abort("failed")
            return
        location = resp.headers.get("location")
        if 300 <= resp.status < 400 and location:
            target = urljoin(request.url, location)
            if not self.guard.check_host(target).allowed:
                self.blocked.append(target)
                route.abort("blockedbyclient")
                return
        route.fulfill(response=resp)

    # ── capture ────────────────────────────────────────────────────────────────
    def _on_request(self, req) -> None:
        self._seq += 1
        headers = {k: ("«redacted»" if k.lower() in SENSITIVE_HEADERS else v) for k, v in req.headers.items()}
        self.network.append({"id": self._seq, "url": req.url, "method": req.method, "type": req.resource_type,
                             "headers": headers, "post": len(req.post_data or "") if req.post_data else 0,
                             "page": self.page.url if self.page else "", "t": time.time(), "_req": req})

    def _on_response(self, resp) -> None:
        entry = self._mark(resp.request, status=resp.status)
        if entry is None:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        entry["response_headers"] = {k: ("«redacted»" if k in SENSITIVE_HEADERS else v) for k, v in headers.items()}
        entry["mime"] = headers.get("content-type", "").split(";")[0]
        if resp.request.resource_type == "document" and resp.request.frame == (self.page.main_frame if self.page else None):
            self.documents[_doc_key(resp.url)] = {"status": resp.status, "headers": headers, "_resp": resp}
        if resp.request.resource_type in BODY_TYPES or entry["mime"].endswith(("javascript", "json")):
            self._pending.append(resp)

    def _mark(self, req, **fields):
        for entry in reversed(self.network):
            if entry.get("_req") is req:
                entry.update(fields)
                return entry
        return None

    def _drain(self) -> None:
        pending, self._pending = self._pending, []
        for resp in pending:
            if resp.url in self.bodies or len(self.bodies) > 400:
                continue
            try:
                body = resp.body()
            except Exception:
                continue
            if len(body) <= MAX_BODY:
                self.bodies[resp.url] = body.decode("utf-8", "replace")

    # ── helpers ────────────────────────────────────────────────────────────────
    def _target(self, target: str):
        t = (target or "").strip()
        if re.fullmatch(r"e\d+", t):
            return self.page.locator(f'[data-autopwn-ref="{t}"]').first
        if t.startswith(("text=", "role=", "xpath=", "//")):
            return self.page.locator(t).first
        return self.page.locator(t).first

    def _inject(self, value: str) -> str:
        return self.vault.inject(value) if self.vault is not None else value

    def _placeholder(self, value: str, kind: str, hint: str) -> str:
        if not value:
            return value
        if self.vault is not None:
            return self.vault.tokenize(value, kind=kind, hint=hint)
        return f"{value[:4]}…({len(value)} chars)"

    def _page_info(self, resp=None) -> dict:
        page = self.page
        doc = self.documents.get(_doc_key(page.url)) or {}
        status = resp.status if resp is not None else doc.get("status")
        info = {"url": page.url, "title": page.title(), "status": status}
        self.visited[page.url] = {"title": info["title"], "status": status, "t": time.time()}
        return info

    def _settle(self) -> None:
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass

    # ── Recorder: open / interact ──────────────────────────────────────────────
    def open(self, url: str) -> dict:
        def go():
            before = len(self.blocked)
            try:
                resp = self.page.goto(url, wait_until="domcontentloaded")
            except Exception as e:
                if len(self.blocked) > before or "ERR_BLOCKED_BY_CLIENT" in str(e):
                    raise BrowserUnavailable(f"blocked by the scope gate: {url} led to {self.blocked[-1]}, "
                                             "which is outside scope") from None
                raise
            self._settle()
            self._assert_in_scope()
            return self._page_info(resp)
        return self.call(go)

    def _assert_in_scope(self) -> None:
        """Second line of defence: whatever happened, never stay on an out-of-scope page."""
        if self.guard is None or self.page.url.startswith(("about:", "data:", "chrome-error:")):
            return
        if not self.guard.check_host(self.page.url).allowed:
            where = self.page.url
            self.blocked.append(where)
            self.page.goto("about:blank")
            raise BrowserUnavailable(f"blocked by the scope gate: the page moved to {where}, outside scope")

    def snapshot(self) -> dict:
        return self.call(lambda: {**self._page_info(), "elements": self.page.evaluate(_SNAPSHOT_JS)})

    def click(self, target: str) -> dict:
        def do():
            self._target(target).click(timeout=8000)
            self._settle()
            self._assert_in_scope()
            return self._page_info()
        return self.call(do)

    def fill(self, target: str, value: str) -> dict:
        def do():
            self._target(target).fill(self._inject(value), timeout=8000)
            return {"filled": target, "url": self.page.url}
        return self.call(do)

    def press(self, key: str, target: str | None = None) -> dict:
        def do():
            (self._target(target).press if target else self.page.keyboard.press)(key)
            self._settle()
            return self._page_info()
        return self.call(do)

    def login(self, url: str, username: str, password: str, *, user_field: str = "", pass_field: str = "",
              submit: str = "") -> dict:
        def do():
            self.page.goto(url, wait_until="domcontentloaded")
            self._settle()
            pf = self._target(pass_field) if pass_field else self.page.locator("input[type=password]").first
            uf = (self._target(user_field) if user_field else self.page.locator(
                "input[type=email], input[name*=user i], input[name*=login i], input[name*=email i], "
                "input[type=text]").first)
            uf.fill(self._inject(username), timeout=8000)
            pf.fill(self._inject(password), timeout=8000)
            before = self.page.url
            if submit:
                self._target(submit).click(timeout=8000)
            else:
                pf.press("Enter")
            self._settle()
            still_login = self.page.locator("input[type=password]").count() > 0 and self.page.url == before
            status = (self.documents.get(_doc_key(self.page.url)) or {}).get("status")
            return {**self._page_info(), "logged_in": not still_login and (status or 200) < 400,
                    "cookies": len(self._context.cookies())}
        return self.call(do)

    def save_session(self, path: Path) -> str:
        def do():
            path.parent.mkdir(parents=True, exist_ok=True)
            self._context.storage_state(path=str(path))
            path.chmod(0o600)
            return str(path)
        return self.call(do)

    # ── Elements ───────────────────────────────────────────────────────────────
    def dom(self, selector: str = "") -> dict:
        return self.call(lambda: self.page.evaluate(_DOM_JS, selector or None))

    # ── Console ────────────────────────────────────────────────────────────────
    def console_messages(self, level: str = "") -> list[dict]:
        def do():
            msgs = [m for m in self.console if not level or m["type"] == level]
            return [{k: v for k, v in m.items() if k != "t"} for m in msgs][-200:]
        return self.call(do)

    # ── Sources ────────────────────────────────────────────────────────────────
    def sources(self) -> dict:
        def do():
            scripts = [e for e in self.network if e.get("type") == "script"]
            out, endpoints, maps = [], set(), []
            for e in scripts:
                body = self.bodies.get(e["url"], "")
                ref = checks.source_map_ref(body)
                if ref:
                    maps.append(urljoin(e["url"], ref))
                endpoints.update(checks.endpoints_in(body))
                out.append({"url": e["url"], "status": e.get("status"), "bytes": len(body), "source_map": bool(ref)})
            inline = self.page.evaluate("() => Array.from(document.querySelectorAll('script:not([src])'))"
                                        ".map(s => s.textContent)")
            for code in inline:
                endpoints.update(checks.endpoints_in(code))
            exposed = []
            for m in dict.fromkeys(maps):
                if self.guard is not None and not self.guard.check_host(m).allowed:
                    continue
                try:
                    r = self._context.request.get(m, timeout=8000)
                    if r.ok and r.text().lstrip().startswith("{"):
                        data = json.loads(r.text())
                        exposed.append({"url": m, "sources": (data.get("sources") or [])[:30]})
                except Exception:
                    continue
            secrets_found = []
            for e in scripts:
                for issue in checks.script_issues(self.page.url, e["url"], self.bodies.get(e["url"], "")):
                    if issue.class_id == "secret_in_client_code":
                        secrets_found.append({"script": e["url"], "kind": issue.param, "evidence": issue.evidence})
            return {"scripts": out, "inline_scripts": len(inline), "endpoints": sorted(endpoints)[:300],
                    "source_maps": exposed, "secrets": secrets_found}
        return self.call(do)

    # ── Network ────────────────────────────────────────────────────────────────
    def network_log(self, filter_text: str = "", types: list[str] | None = None, limit: int = 150) -> dict:
        def do():
            rows = [e for e in self.network if (not filter_text or filter_text in e["url"])
                    and (not types or e.get("type") in types)]
            clean = [{k: v for k, v in e.items() if not k.startswith("_") and k != "t"} for e in rows][-limit:]
            return {"requests": clean, "total": len(rows), "api": self._api_map(), "websockets": self.websockets[-50:],
                    "blocked_navigations": self.blocked[-20:]}
        return self.call(do)

    def _api_map(self) -> list[dict]:
        apis: dict[tuple[str, str], dict] = {}
        for e in self.network:
            if e.get("type") not in ("xhr", "fetch") and not str(e.get("mime", "")).endswith("json"):
                continue
            u = urlsplit(e["url"])
            path = re.sub(r"/\d+(?=/|$)", "/{id}", u.path)
            key = (e["method"], f"{u.scheme}://{u.netloc}{path}")
            a = apis.setdefault(key, {"method": e["method"], "endpoint": key[1], "params": set(), "statuses": set(),
                                      "content_type": e.get("mime", "")})
            a["params"].update(k for k, _ in parse_qsl(u.query))
            if e.get("status"):
                a["statuses"].add(e["status"])
        return [{**a, "params": sorted(a["params"]), "statuses": sorted(a["statuses"])} for a in apis.values()]

    # ── Performance / Memory ───────────────────────────────────────────────────
    def performance(self) -> dict:
        def do():
            data = self.page.evaluate(_PERF_JS)
            try:
                cdp = self._context.new_cdp_session(self.page)
                cdp.send("Performance.enable")
                metrics = {m["name"]: m["value"] for m in cdp.send("Performance.getMetrics")["metrics"]}
                cdp.detach()
                data["cdp"] = {k: metrics[k] for k in ("JSHeapUsedSize", "JSHeapTotalSize", "Nodes", "Documents",
                                                       "JSEventListeners", "LayoutCount", "ScriptDuration",
                                                       "TaskDuration") if k in metrics}
            except Exception:
                pass
            return data
        return self.call(do)

    # ── Application ────────────────────────────────────────────────────────────
    def application(self) -> dict:
        def do():
            data = self.page.evaluate(_APP_JS)
            raw_storage = {"localStorage": data["localStorage"], "sessionStorage": data["sessionStorage"]}
            safe_storage = {area: {k: self._placeholder(v, "storage", f"{area}:{k}")
                                   if checks.SENSITIVE_KEY.search(k) or checks.JWT.search(str(v)) or len(str(v)) > 40
                                   else v for k, v in items.items()}
                            for area, items in raw_storage.items()}
            cookies = []
            for c in self._context.cookies():
                cookies.append({"name": c["name"], "value": self._placeholder(c.get("value", ""), "cookie",
                                                                               f"cookie:{c['name']}"),
                                "domain": c.get("domain"), "path": c.get("path"), "httpOnly": c.get("httpOnly"),
                                "secure": c.get("secure"), "sameSite": c.get("sameSite"),
                                "expires": c.get("expires")})
            manifest = None
            if data.get("manifest") and (self.guard is None or self.guard.check_host(data["manifest"]).allowed):
                try:
                    r = self._context.request.get(data["manifest"], timeout=8000)
                    manifest = json.loads(r.text()) if r.ok else None
                except Exception:
                    manifest = None
            return {"cookies": cookies, **safe_storage, "indexedDB": data["indexedDB"],
                    "cacheStorage": data["cacheStorage"], "serviceWorkers": data["serviceWorkers"],
                    "manifest": manifest, "frames": data["frames"], "_raw_storage": raw_storage,
                    "_raw_cookies": self._context.cookies()}
        return self.call(do)

    # ── Security ───────────────────────────────────────────────────────────────
    def security(self) -> dict:
        def do():
            doc = self.documents.get(_doc_key(self.page.url)) or {}
            headers = doc.get("headers") or {}
            tls = _tls_info(self.page.url) if self.page.url.startswith("https://") else None
            present = {name: headers.get(key) for key, name in checks.SECURITY_HEADERS.items() if key in headers}
            missing = [name for key, name in checks.SECURITY_HEADERS.items() if key not in headers]
            insecure = sorted({e["url"] for e in self.network if self.page.url.startswith("https://")
                               and e["url"].startswith("http://")})
            return {"url": self.page.url, "https": self.page.url.startswith("https://"), "tls": tls,
                    "security_headers": present, "missing_headers": missing,
                    "csp": headers.get("content-security-policy", ""),
                    "cors": {k: headers[k] for k in headers if k.startswith("access-control-")},
                    "mixed_content": insecure[:20], "server": headers.get("server", ""),
                    "x_powered_by": headers.get("x-powered-by", "")}
        return self.call(do)

    # ── screenshot ─────────────────────────────────────────────────────────────
    def screenshot(self, full_page: bool = True) -> str:
        def do():
            d = self.artifacts_dir or Path.cwd()
            d.mkdir(parents=True, exist_ok=True)
            path = d / f"screenshot-{int(time.time() * 1000)}.png"
            self.page.screenshot(path=str(path), full_page=full_page)
            return str(path)
        return self.call(do)

    # ── crawl (all pages) ──────────────────────────────────────────────────────
    def crawl(self, start: str, *, max_pages: int = 40, max_depth: int = 3, delay: float = 0.2) -> dict:
        def do():
            seen: set[str] = set()
            queue: deque[tuple[str, int]] = deque([(start, 0)])
            pages, skipped, outside = [], [], set()
            forms_total = 0
            while queue and len(pages) < max_pages:
                url, depth = queue.popleft()
                key = url.split("#")[0] + ("#" + url.split("#", 1)[1] if "#/" in url else "")
                if key in seen:
                    continue
                seen.add(key)
                if self.guard is not None and not self.guard.check_host(url).allowed:
                    outside.add(urlsplit(url).netloc)
                    continue
                try:
                    resp = self.page.goto(url, wait_until="domcontentloaded")
                    self._settle()
                except Exception as e:
                    pages.append({"url": url, "error": str(e).splitlines()[0][:160]})
                    continue
                info = self._page_info(resp)
                dom = self.page.evaluate(_DOM_JS, None)
                forms_total += len(dom["forms"])
                params = sorted({k for k, _ in parse_qsl(urlsplit(self.page.url).query)} |
                                {i["name"] for f in dom["forms"] for i in f["inputs"] if i["name"]})
                pages.append({"url": self.page.url, "title": info["title"], "status": info["status"],
                              "forms": len(dom["forms"]), "params": params, "depth": depth})
                if depth >= max_depth:
                    continue
                for link in dom["links"]:
                    if SKIP_LINK.search(link):
                        skipped.append(link)
                        continue
                    if link.startswith(("mailto:", "tel:", "javascript:")):
                        continue
                    queue.append((link, depth + 1))
                time.sleep(delay)
            return {"pages": pages, "api": self._api_map(), "skipped_state_changing": sorted(set(skipped))[:50],
                    "outside_scope": sorted(outside), "forms": forms_total,
                    "scripts": sorted({e["url"] for e in self.network if e.get("type") == "script"})[:200],
                    "websockets": self.websockets[-50:]}
        return self.call(do, timeout=1800)

    # ── passive audit of everything seen so far ───────────────────────────────
    def audit(self) -> list[checks.Issue]:
        def do():
            issues: list[checks.Issue] = []
            for url, doc in list(self.documents.items()):
                if self.guard is not None and not self.guard.check_host(url).allowed:
                    continue
                issues += checks.header_issues(url, doc.get("headers") or {})
            for e in self.network:
                if e.get("type") in ("xhr", "fetch") and e.get("response_headers"):
                    issues += [i for i in checks.header_issues(e["url"], e["response_headers"])
                               if i.class_id == "cors_misconfig"]
            page_url = self.page.url
            issues += checks.cookie_issues(page_url, self._context.cookies())
            storage = self.page.evaluate("() => { const d = s => { const o = {}; for (let i = 0; i < s.length; i++)"
                                         " { const k = s.key(i); o[k] = s.getItem(k); } return o; };"
                                         " return {localStorage: d(localStorage), sessionStorage: d(sessionStorage)}; }")
            issues += checks.storage_issues(page_url, storage)
            for e in self.network:
                if e.get("type") == "script":
                    issues += checks.script_issues(e.get("page") or page_url, e["url"], self.bodies.get(e["url"], ""))
            issues += checks.console_issues(page_url, list(self.console))
            issues += checks.mixed_content_issues(page_url, list(self.network))
            for e in [e for e in self.network if e.get("type") == "script"]:
                ref = checks.source_map_ref(self.bodies.get(e["url"], ""))
                if not ref:
                    continue
                map_url = urljoin(e["url"], ref)
                if self.guard is not None and not self.guard.check_host(map_url).allowed:
                    continue
                try:
                    r = self._context.request.get(map_url, timeout=8000)
                    if r.ok and '"mappings"' in r.text()[:5000]:
                        issues.append(checks.Issue("exposed_source_map", map_url,
                                                   f"source map for {e['url']} is downloadable",
                                                   evidence=f"GET {map_url} → {r.status}"))
                except Exception:
                    continue
            unique: dict[tuple, checks.Issue] = {}
            for i in issues:
                unique.setdefault((i.class_id, urlsplit(i.url).netloc, i.param or urlsplit(i.url).path), i)
            return list(unique.values())
        return self.call(do)

    # ── DOM XSS (safe verification) ────────────────────────────────────────────
    def dom_xss(self, url: str, params: list[str] | None = None) -> list[dict]:
        """Put a harmless marker element into each URL / hash parameter and check
        whether the page turns it into a real DOM node. No script ever runs."""
        def do():
            results = []
            u = urlsplit(url)
            query = parse_qsl(u.query, keep_blank_values=True)
            frag_path, _, frag_query = u.fragment.partition("?")
            fquery = parse_qsl(frag_query, keep_blank_values=True)
            names = params or [k for k, _ in query] + [k for k, _ in fquery]
            for name in dict.fromkeys(names):
                marker = "apx" + secrets.token_hex(4)
                payload = f'{marker}"\'><i id="{marker}">x</i>'
                q2 = [(k, payload if k == name else v) for k, v in query]
                f2 = [(k, payload if k == name else v) for k, v in fquery]
                frag = frag_path + ("?" + urlencode(f2) if f2 else "") if u.fragment else ""
                test_url = urlunsplit((u.scheme, u.netloc, u.path, urlencode(q2), frag))
                try:
                    self.page.goto("about:blank")
                    self.page.goto(test_url, wait_until="domcontentloaded")
                    self._settle()
                    hit = self.page.evaluate("(m) => !!document.getElementById(m)", marker)
                except Exception as e:
                    results.append({"param": name, "error": str(e).splitlines()[0][:160]})
                    continue
                sink = ""
                if hit:
                    sink = self.page.evaluate("(m) => { const e = document.getElementById(m);"
                                              " return e && e.parentElement ? e.parentElement.outerHTML.slice(0, 300) : ''; }",
                                              marker)
                results.append({"param": name, "vulnerable": bool(hit), "url": test_url, "marker": marker,
                                "where": "fragment" if name in dict(fquery) else "query", "sink": sink})
            return results
        return self.call(do)
