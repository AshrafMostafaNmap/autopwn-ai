"""`web_deep_scan`: the full web methodology in one call, in a fixed order.

Every step goes through the tool registry, so the scope gate, the audit trail
and the findings pipeline apply exactly as when the agent calls the tools one by
one. A step that cannot run (scanner missing, nothing to test) is reported and
the scan moves on.
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ..agent.tools import ToolRegistry, ToolResult
from ..llm.provider import ToolCall

MAX_PARAM_PAGES = 15


def _param_pages(pages: list[dict]) -> list[str]:
    urls = [p["url"] for p in pages if parse_qsl(urlsplit(p.get("url", "")).query)
            or "?" in urlsplit(p.get("url", "")).fragment]
    return list(dict.fromkeys(urls))[:MAX_PARAM_PAGES]


def _param_endpoints(pages: list[dict], api: list[dict]) -> list[str]:
    urls = [p["url"] for p in pages if parse_qsl(urlsplit(p.get("url", "")).query)]
    urls += [a["endpoint"] + "?" + "&".join(f"{k}=1" for k in a["params"]) for a in api if a.get("params")]
    return list(dict.fromkeys(urls))[:MAX_PARAM_PAGES]


def register_workflows(registry: ToolRegistry, *, ctx=None) -> None:

    def run(name: str, **args) -> ToolResult:
        if registry.get(name) is None:
            return ToolResult.fail(f"{name} is not available")
        return registry.dispatch(ToolCall(f"wf-{name}", name, args), ctx)

    def say(text: str) -> None:
        if ctx is not None:
            ctx.logger.info("agent.message", text=text)

    def web_deep_scan(args: dict[str, Any], _ctx) -> ToolResult:
        url = (args.get("url") or "").strip()
        if not url:
            return ToolResult.fail("'url' is required")
        if "://" not in url:
            url = "https://" + url
        max_pages = int(args.get("max_pages") or 40)
        steps: list[dict] = []

        def step(label: str, name: str, **kw) -> ToolResult:
            say(f"deep scan · {label}")
            t = time.time()
            res = run(name, **kw)
            steps.append({"step": label, "tool": name, "ok": res.ok, "seconds": round(time.time() - t, 1),
                          "result": res.content if res.ok else res.error})
            return res

        first = step("fingerprint", "web_recon", url=url)
        if not first.ok and "scope" in first.error:
            return ToolResult.fail(first.error, steps=steps)
        step("live check", "http_probe", targets=[url])
        crawl = step("crawl every page in the browser", "browser_crawl", url=url, max_pages=max_pages)
        pages = (crawl.data or {}).get("pages", []) if crawl.ok else []
        api = (crawl.data or {}).get("api", []) if crawl.ok else []
        step("client-side audit", "browser_audit")
        step("security overview", "browser_security")
        for t in _param_pages(pages):
            step(f"DOM XSS · {t}", "browser_dom_xss", url=t)
        step("sensitive paths", "content_discovery", url=url)
        if args.get("templates", True):
            step("known issues (nuclei)", "template_scan", targets=[url])
        step(f"server-side checks · {url}", "detect_web", url=url)
        for t in _param_endpoints(pages, api):
            step(f"server-side checks · {t}", "detect_web", url=t)
        step("verify findings", "verify_findings")
        findings = run("list_findings", status="verified")
        done = sum(1 for s in steps if s["ok"])
        summary = (f"deep scan of {url}: {len(pages)} page(s), {len(api)} API endpoint(s), {done}/{len(steps)} "
                   f"step(s) ran; {findings.content if findings.ok else 'no findings list'}")
        return ToolResult(content=summary, data={"steps": steps, "pages": len(pages), "api_endpoints": len(api),
                                                 "verified": (findings.data or {}) if findings.ok else {}})

    registry.add("web_deep_scan",
                 "Run the complete web assessment in order: fingerprint → live check → browser crawl of every "
                 "page (JS-rendered, #/routes, API calls) → client-side audit → security overview → DOM-XSS "
                 "checks on every parameterised page → sensitive paths → nuclei → server-side checks on every "
                 "parameterised URL → verification. Use it first on a web target, then go deeper by hand.",
                 web_deep_scan, phase="detection",
                 parameters={"type": "object", "properties": {
                     "url": {"type": "string"}, "max_pages": {"type": "integer", "maximum": 200},
                     "templates": {"type": "boolean", "description": "include the nuclei template scan "
                                   "(default true; it is the slowest step)"}},
                     "required": ["url"]})
    registry.mark_scoped(active=("web_deep_scan",))
