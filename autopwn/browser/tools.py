"""Browser tools for the agent (and the MCP server): one per DevTools tab, plus
interaction, crawling, a passive audit and a safe DOM-XSS check."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..agent.tools import ToolRegistry, ToolResult
from ..detect.model import Candidate
from .engine import BrowserEngine, BrowserUnavailable

ACTIVE = ("browser_open", "browser_crawl", "browser_login", "browser_dom_xss")
OBJ = {"type": "object"}


def register_browser_tools(registry: ToolRegistry, *, engine: Callable[[], BrowserEngine], ctx=None,
                           pipeline=None, target_model=None, redactor=None) -> None:

    def wrap(fn):
        def handler(args: dict[str, Any], _ctx) -> ToolResult:
            try:
                return fn(args)
            except BrowserUnavailable as e:
                return ToolResult.fail(str(e))
            except TimeoutError:
                return ToolResult.fail("the browser timed out")
            except Exception as e:
                msg = str(e).splitlines()[0][:300] if str(e) else type(e).__name__
                return ToolResult.fail(f"browser error: {msg}")
        return handler

    def scrub(obj):
        return redactor.scrub_obj(obj) if redactor is not None else obj

    def observe(pages: list[dict], api: list[dict]) -> None:
        if target_model is None:
            return
        from ..recon.target_model import Surface
        by_host: dict[str, Surface] = {}
        for p in pages:
            u = urlsplit(p.get("url", ""))
            if not u.hostname:
                continue
            s = by_host.setdefault(u.hostname, Surface(host=u.hostname, domain="web", scheme=u.scheme))
            s.endpoints.append(u.path or "/")
            s.params.extend(p.get("params") or [])
        for a in api:
            u = urlsplit(a["endpoint"])
            if u.hostname in by_host:
                by_host[u.hostname].endpoints.append(u.path)
                by_host[u.hostname].params.extend(a.get("params") or [])
        for s in by_host.values():
            target_model.observe(s)

    def add(name, desc, fn, props=None, required=(), phase="recon", approval=False):
        params = {**OBJ, "properties": props or {}}
        if required:
            params["required"] = list(required)
        registry.add(name, desc, wrap(fn), phase=phase, parameters=params, requires_approval=approval)

    url_prop = {"url": {"type": "string", "description": "page URL (must be in scope)"}}
    target_prop = {"target": {"type": "string", "description": "element ref from browser_snapshot (e.g. e12) "
                              "or a CSS / text= selector"}}

    add("browser_open", "Open a page in the real headless browser (JavaScript runs, SPAs render). Everything "
        "it loads is captured for the other browser_* tools.",
        lambda a: ToolResult(content="opened", data=engine().open(a["url"])), url_prop, ["url"])
    add("browser_snapshot", "Interactive elements of the current page (links, buttons, inputs, forms) with refs "
        "to use in browser_click / browser_fill.",
        lambda a: _snapshot(engine()), {})
    add("browser_click", "Click an element (ref from browser_snapshot or a selector). Links that look "
        "state-changing should not be clicked.",
        lambda a: ToolResult(content="clicked", data=engine().click(a["target"])), target_prop, ["target"])
    add("browser_fill", "Type into an input. Values may contain «secret:…» placeholders; the real value is used "
        "locally and never returned.",
        lambda a: ToolResult(content="filled", data=engine().fill(a["target"], a.get("value", ""))),
        {**target_prop, "value": {"type": "string"}}, ["target", "value"])
    add("browser_press", "Press a key (Enter, Tab, Escape…), optionally on an element.",
        lambda a: ToolResult(content="pressed", data=engine().press(a["key"], a.get("target"))),
        {"key": {"type": "string"}, **target_prop}, ["key"])

    def login(a):
        res = engine().login(a["url"], a["username"], a["password"], user_field=a.get("user_field", ""),
                             pass_field=a.get("pass_field", ""), submit=a.get("submit", ""))
        if res.get("logged_in") and ctx is not None:
            res["session_file"] = engine().save_session(ctx.run_dir / "browser" / "session.json")
        return ToolResult(content="logged in" if res.get("logged_in") else "login did not succeed", data=res,
                          ok=bool(res.get("logged_in")), error="" if res.get("logged_in") else "still on the login form")

    add("browser_login", "Sign in to the target with the operator's test account so the crawl and checks cover "
        "authenticated pages. Pass credentials as «secret:…» placeholders from the vault. The session is "
        "saved locally for the rest of the run.",
        login, {**url_prop, "username": {"type": "string"}, "password": {"type": "string"},
                "user_field": {"type": "string"}, "pass_field": {"type": "string"}, "submit": {"type": "string"}},
        ["url", "username", "password"], approval=True)

    def dom(a):
        d = engine().dom(a.get("selector", ""))
        if not a.get("selector"):
            d.pop("html", None)
        d["links"] = d["links"][:80]
        return ToolResult(content=f"{d['title']}: {len(d['forms'])} form(s), {len(d['links'])} link(s), "
                                  f"{len(d['comments'])} HTML comment(s), {d['inline_handlers']} inline handler(s)",
                          data=scrub(d))
    add("browser_dom", "Elements tab: forms and their fields (hidden ones too), links, iframes, meta tags, HTML "
        "comments, inline scripts and event handlers; with a selector, that element's HTML.",
        dom, {"selector": {"type": "string"}})

    def console(a):
        msgs = engine().console_messages(a.get("level", ""))
        return ToolResult(content=f"{len(msgs)} console message(s)", data={"messages": scrub(msgs)})
    add("browser_console", "Console tab: console messages and uncaught page errors (stack traces, debug output, "
        "leaked internals).", console, {"level": {"type": "string", "enum": ["", "error", "warning", "log",
                                                                              "info", "pageerror"]}})

    def sources(a):
        s = engine().sources()
        return ToolResult(content=f"{len(s['scripts'])} script(s), {len(s['endpoints'])} endpoint(s) in code, "
                                  f"{len(s['source_maps'])} exposed source map(s), {len(s['secrets'])} secret(s)",
                          data=scrub(s))
    add("browser_sources", "Sources tab: every script the app loaded, API endpoints referenced in the code, "
        "downloadable source maps (and the original file names they reveal) and secrets in JavaScript.",
        sources, {})

    def network(a):
        n = engine().network_log(a.get("filter", ""), a.get("types"), int(a.get("limit") or 150))
        return ToolResult(content=f"{n['total']} request(s), {len(n['api'])} API endpoint(s), "
                                  f"{len(n['websockets'])} websocket(s)", data=scrub(n))
    add("browser_network", "Network tab: requests and responses (method, status, type, headers — credentials "
        "redacted), the API map of XHR/fetch calls with their parameters, websockets and navigations the scope "
        "gate blocked.",
        network, {"filter": {"type": "string"}, "types": {"type": "array", "items": {"type": "string"}},
                  "limit": {"type": "integer"}})

    add("browser_performance", "Performance and Memory tabs: navigation timing, resources by type, bytes, DOM "
        "size, JS heap and event-listener counts.",
        lambda a: ToolResult(content="performance metrics", data=engine().performance()), {})

    def application(a):
        app = engine().application()
        app.pop("_raw_storage", None)
        app.pop("_raw_cookies", None)
        return ToolResult(content=f"{len(app['cookies'])} cookie(s), {len(app['localStorage'])} localStorage and "
                                  f"{len(app['sessionStorage'])} sessionStorage key(s), {len(app['indexedDB'])} "
                                  f"IndexedDB, {len(app['serviceWorkers'])} service worker(s)", data=app)
    add("browser_application", "Application tab: cookies with their flags, Local and Session Storage, IndexedDB, "
        "Cache Storage, service workers, the web app manifest and frames. Secret-looking values come back as "
        "«secret:…» placeholders.", application, {})

    add("browser_security", "Security tab: TLS protocol and certificate, security headers present/missing, the "
        "CSP, CORS headers, mixed content and server banners.",
        lambda a: ToolResult(content="security overview", data=scrub(engine().security())), {})

    def screenshot(a):
        path = engine().screenshot(bool(a.get("full_page", True)))
        rel = str(Path(path).relative_to(ctx.run_dir)) if ctx is not None else path
        return ToolResult(content=f"screenshot saved: {rel}", data={"path": rel}, artifacts=[rel] if ctx else [])
    add("browser_screenshot", "Save a screenshot of the current page as evidence.", screenshot,
        {"full_page": {"type": "boolean"}})

    def crawl(a):
        res = engine().crawl(a["url"], max_pages=min(int(a.get("max_pages") or 40), 200),
                             max_depth=min(int(a.get("max_depth") or 3), 6))
        observe(res["pages"], res["api"])
        return ToolResult(content=f"crawled {len(res['pages'])} page(s), {len(res['api'])} API endpoint(s), "
                                  f"{res['forms']} form(s); skipped {len(res['skipped_state_changing'])} "
                                  f"state-changing link(s)", data=scrub(res))
    add("browser_crawl", "Crawl the whole app in the real browser — JavaScript-rendered pages and #/routes "
        "included — staying in scope and never following logout/delete-style links. Builds the page list, "
        "forms, parameters and the API map.",
        crawl, {**url_prop, "max_pages": {"type": "integer", "maximum": 200},
                "max_depth": {"type": "integer", "maximum": 6}}, ["url"])

    def audit(a):
        issues = engine().audit()
        added = []
        for i in issues:
            if pipeline is not None:
                f = pipeline.add(Candidate(i.class_id, host=urlsplit(i.url).hostname or "", url=i.url, param=i.param,
                                           confidence=i.confidence, method="direct", note=i.note,
                                           evidence_response=i.evidence[:2000],
                                           steps=[f"observed by the browser on {i.url}"]))
                added.append(f.id)
        rows = [{"class": i.class_id, "url": i.url, "issue": i.note} for i in issues]
        return ToolResult(content=f"{len(issues)} client-side issue(s) from everything the browser has seen"
                                  + ("; added as suspected findings — run verify_findings" if added else ""),
                          data={"issues": scrub(rows)})
    add("browser_audit", "Passive audit of everything the browser has captured so far: security headers, CSP, "
        "CORS with credentials, cookie flags, tokens in browser storage, vulnerable JS libraries, secrets in "
        "scripts, exposed source maps, console leaks, mixed content. Results become findings.",
        audit, {}, phase="detection")

    def dom_xss(a):
        results = engine().dom_xss(a["url"], a.get("params"))
        hits = [r for r in results if r.get("vulnerable")]
        for r in hits:
            if pipeline is not None:
                pipeline.add(Candidate("dom_xss", host=urlsplit(r["url"]).hostname or "", url=r["url"],
                                       param=r["param"], confidence=0.95, method="direct",
                                       note=f"marker element <i id={r['marker']}> was created from the "
                                            f"{r['where']} parameter '{r['param']}' — HTML injection into the DOM; "
                                            "no script was executed",
                                       evidence_request=f"GET {r['url']}", evidence_response=r.get("sink", ""),
                                       steps=["open the URL with a harmless <i id=marker> payload",
                                              "check document.getElementById(marker) exists"]))
        return ToolResult(content=f"{len(hits)} of {len(results)} parameter(s) inject into the DOM",
                          data={"results": results})
    add("browser_dom_xss", "Safely verify DOM-based XSS on a URL: each query or #fragment parameter gets a "
        "harmless marker element; if the page creates that element, the parameter reaches an HTML sink. No "
        "script runs.", dom_xss,
        {**url_prop, "params": {"type": "array", "items": {"type": "string"}}}, ["url"], phase="detection")

    registry.mark_scoped(active=ACTIVE)


def _snapshot(engine: BrowserEngine) -> ToolResult:
    s = engine.snapshot()
    visible = [e for e in s["elements"] if e["visible"]]
    return ToolResult(content=f"{s['title']} — {len(visible)} interactive element(s)", data=s)
