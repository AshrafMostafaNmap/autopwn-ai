"""The browser toolset against a real headless Chromium/Chrome and the planted
single-page app. Skipped when no browser is available."""
from __future__ import annotations

import pytest

from autopwn.browser import checks
from autopwn.eval.weblab import FAKE_AWS_KEY, GROUND_TRUTH, WebLab
from autopwn.llm.provider import ToolCall


def _browser_ok() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    with sync_playwright() as p:
        for kw in ({}, {"channel": "chrome"}):
            try:
                p.chromium.launch(headless=True, **kw).close()
                return True
            except Exception:
                continue
    return False


needs_browser = pytest.mark.skipif(not _browser_ok(), reason="no headless browser available")


@pytest.fixture(scope="module")
def lab():
    with WebLab() as w:
        yield w


@pytest.fixture
def session(make_session, lab):
    s = make_session(targets=["127.0.0.1"])
    s.set_scope(authorized=True)
    yield s
    s.close()


def _call(s, name, **args):
    return s.registry.dispatch(ToolCall("t", name, args), s.ctx)


@needs_browser
def test_devtools_tabs(session, lab):
    assert _call(session, "browser_open", url=lab.base_url + "/#/products").ok
    snap = _call(session, "browser_snapshot").data
    assert any(e["text"] == "Login" for e in snap["elements"])
    assert "Unhandled error" in _call(session, "browser_console").data["messages"][0]["text"]
    src = _call(session, "browser_sources").data
    assert "/api/search" in src["endpoints"] and src["source_maps"][0]["sources"] == ["src/app.ts", "src/secrets.ts"]
    assert src["secrets"][0]["kind"] == "AWS access key" and FAKE_AWS_KEY not in str(src)
    net = _call(session, "browser_network", types=["fetch"]).data
    assert any(a["endpoint"].endswith("/api/products") and a["params"] == ["limit"] for a in net["api"])
    app = _call(session, "browser_application").data
    assert app["localStorage"]["auth_token"].startswith("«secret:")              # token never returned
    assert {c["name"] for c in app["cookies"]} >= {"session", "theme"}
    assert app["manifest"]["name"] == "Lab Shop"
    sec = _call(session, "browser_security").data
    assert "unsafe-eval" in sec["csp"] and "X-Frame-Options" in sec["missing_headers"]
    perf = _call(session, "browser_performance").data
    assert perf["domNodes"] > 0 and perf["resources"] >= 2
    shot = _call(session, "browser_screenshot")
    assert shot.ok and (session.ctx.run_dir / shot.data["path"]).is_file()


@needs_browser
def test_crawl_audit_and_dom_xss_find_everything(session, lab):
    crawl = _call(session, "browser_crawl", url=lab.base_url + "/", max_pages=20).data
    paths = {p["url"].replace(lab.base_url, "") for p in crawl["pages"]}
    assert {"/", "/#/products", "/login", "/#/product/1"} <= paths            # JS-only routes reached
    _call(session, "browser_audit")
    hits = _call(session, "browser_dom_xss", url=lab.base_url + "/#/search?q=x").data["results"]
    assert hits[0]["vulnerable"] and hits[0]["where"] == "fragment"
    assert not _call(session, "browser_dom_xss", url=lab.base_url + "/?q=1").data["results"][0]["vulnerable"]
    _call(session, "verify_findings")
    from autopwn.detect.signatures import VULN_CLASSES
    by_title = {vc.title: cid for cid, vc in VULN_CLASSES.items()}
    verified = {by_title.get(f.title) for f in session.findings() if f.status.value == "verified"}
    assert GROUND_TRUTH <= verified, GROUND_TRUTH - verified


@needs_browser
def test_browser_never_leaves_scope(session, lab):
    r = _call(session, "browser_open", url=lab.base_url + "/go?to=http://example.com/")
    assert not r.ok and "scope" in r.error and "example.com" in r.error
    assert not _call(session, "browser_open", url="http://example.com").ok


@needs_browser
def test_deep_scan_workflow(session, lab):
    r = _call(session, "web_deep_scan", url=lab.base_url + "/", max_pages=15, templates=False)
    steps = {s["step"]: s["ok"] for s in r.data["steps"]}
    assert steps["crawl every page in the browser"] and steps["client-side audit"]
    assert any(k.startswith("DOM XSS") for k in steps)
    assert r.data["pages"] >= 10 and "finding" in r.content


def test_passive_checks_without_a_browser():
    hs = checks.header_issues("https://a.lab/", {"Access-Control-Allow-Origin": "https://evil.example",
                                                 "Access-Control-Allow-Credentials": "true",
                                                 "Content-Security-Policy": "script-src * 'unsafe-inline'"})
    assert {i.class_id for i in hs} == {"security_misconfig", "weak_csp", "cors_misconfig"}
    assert checks.storage_issues("u", {"localStorage": {"theme": "dark", "accessToken": "x" * 40}})[0].param == "accessToken"
    libs = checks.script_issues("u", "s.js", "/*! jQuery v3.7.1 */ /*! Bootstrap v3.3.7 */")
    assert [i.param for i in libs] == ["Bootstrap"]
    assert checks.source_map_ref("x\n//# sourceMappingURL=app.js.map") == "app.js.map"
    assert checks.endpoints_in('fetch("/api/v1/users?id=1"); x="/graphql"') == ["/api/v1/users", "/graphql"]
    assert checks.mixed_content_issues("https://a/", [{"url": "http://cdn/x.js"}])
    assert not checks.cookie_issues("https://a/", [{"name": "theme", "httpOnly": False}])
