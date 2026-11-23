"""Agent tools over the external scanners: ProjectDiscovery's httpx, subfinder,
katana, dnsx and nuclei, plus ffuf and gau.

Every run is rate-limited and time-boxed, and intrusive behaviour is switched
off: nuclei excludes DoS, fuzzing, brute-force, RCE, LFI, upload and takeover
templates; ffuf uses a short bundled wordlist at a low rate. Targets pass the
scope gate before any of these run (see govern/scope.py).
"""
from __future__ import annotations

import json
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from ..agent.tools import ToolRegistry, ToolResult
from ..detect.model import Candidate
from ..govern.scope import host_of
from .runner import available, run
from .target_model import Service, Surface

NUCLEI_EXCLUDED_TAGS = "dos,intrusive,fuzz,fuzzing,bruteforce,brute-force,rce,lfi,file-upload,takeover,headless"
NUCLEI_DEFAULT_TAGS = "exposure,misconfig,panel,tech"
NUCLEI_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0, "unknown": 0.0}
RATE = "20"
MAX_ITEMS = 200


def _jsonl(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _targets(args: dict, *keys: str) -> list[str]:
    vals: list[str] = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str):
            vals += [x for x in v.replace(",", " ").split() if x]
        elif isinstance(v, list):
            vals += [str(x) for x in v if str(x).strip()]
    return list(dict.fromkeys(vals))


def _missing(binary: str) -> ToolResult:
    return ToolResult.fail(f"{binary} is not installed — run: autopwnai tools install {binary}", missing=binary)


def _failed(res) -> ToolResult:
    detail = res.error or (res.stderr or "").strip().splitlines()[-1:] or [f"exit {res.returncode}"]
    return ToolResult.fail(f"{res.binary} failed: {detail if isinstance(detail, str) else detail[0]}"[:400])


def _ffuf_input(row: dict) -> str:
    """ffuf's JSON output base64-encodes the inputs; the URL is the fallback."""
    import base64
    raw = str((row.get("input") or {}).get("FUZZ", ""))
    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        if decoded.isprintable():
            return decoded.lstrip("/")
    except (ValueError, UnicodeDecodeError):
        pass
    url = str(row.get("url") or "")
    return urlsplit(url).path.lstrip("/") if url else raw


def wordlist_path() -> str:
    return str(resources.files("autopwn.recon").joinpath("wordlists/common.txt"))


def register_scanner_tools(registry: ToolRegistry, *, ctx=None, vault=None, redactor=None,
                           target_model=None, pipeline=None) -> None:
    guard = lambda: registry.guard  # noqa: E731 — read at call time (set after registration)

    def store(name: str, payload: Any) -> str | None:
        if ctx is None:
            return None
        safe = redactor.scrub_obj(payload) if redactor is not None else payload
        path = ctx.artifact_path(f"{name}-{ctx.run_id}.json")
        path.write_text(json.dumps(safe, indent=2, default=str), encoding="utf-8")
        rel = str(path.relative_to(ctx.run_dir))
        ctx.store.add_artifact(ctx.run_id, kind="scan", path=rel, meta={"tool": name})
        return rel

    def observe(surface: Surface) -> None:
        if target_model is not None:
            target_model.observe(surface)

    # ── httpx ──────────────────────────────────────────────────────────────────
    def http_probe(args: dict, _ctx) -> ToolResult:
        targets = _targets(args, "targets", "url", "host")
        if not targets:
            return ToolResult.fail("'targets' is required")
        if not available("httpx"):
            return _missing("httpx")
        res = run("httpx", ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-web-server",
                            "-ip", "-cdn", "-follow-redirects", "-rate-limit", RATE, "-timeout", "10",
                            "-no-color", "-disable-update-check"],
                  input_text="\n".join(targets) + "\n", timeout=300, vault=vault)
        rows = _jsonl(res.stdout)
        if not rows and not res.ok:
            return _failed(res)
        live = []
        for r in rows[:MAX_ITEMS]:
            item = {"url": r.get("url"), "status": r.get("status_code") or r.get("status-code"),
                    "title": r.get("title", ""), "server": r.get("webserver", ""),
                    "tech": r.get("tech") or r.get("technologies") or [], "ip": r.get("host", ""),
                    "cdn": r.get("cdn_name") or ("cdn" if r.get("cdn") else "")}
            live.append(item)
            host = host_of(item["url"] or "")
            if host:
                observe(Surface(host=host, domain="web", scheme=urlsplit(item["url"]).scheme,
                                server=item["server"] or "", title=item["title"] or "",
                                tech=list(item["tech"])[:10]))
        store("http_probe", rows)
        return ToolResult(content=f"{len(live)} live web service(s) of {len(targets)} target(s)",
                          data={"live": live})

    registry.add("http_probe",
                 "Probe hosts/URLs with httpx: which are live, status, title, server, technologies, "
                 "CDN. Fast and non-intrusive (GET, rate-limited).",
                 http_probe, phase="recon",
                 parameters={"type": "object", "properties": {
                     "targets": {"type": "array", "items": {"type": "string"},
                                 "description": "hosts or URLs (all must be in scope)"}},
                     "required": ["targets"]})

    # ── subfinder ──────────────────────────────────────────────────────────────
    def subdomain_discovery(args: dict, _ctx) -> ToolResult:
        domain = (args.get("domain") or "").strip()
        if not domain:
            return ToolResult.fail("'domain' is required")
        if not available("subfinder"):
            return _missing("subfinder")
        res = run("subfinder", ["-d", domain, "-silent", "-oJ", "-timeout", "30", "-max-time", "3",
                                "-disable-update-check"], timeout=240, vault=vault)
        hosts = sorted({r.get("host", "").lower() for r in _jsonl(res.stdout) if r.get("host")})
        if not hosts and not res.ok:
            return _failed(res)
        g = guard()
        inside, outside = g.filter_hosts(hosts) if g is not None else (hosts, [])
        store("subdomain_discovery", {"domain": domain, "in_scope": inside, "out_of_scope": outside})
        note = (f" {len(outside)} found outside scope are listed but must not be tested unless the "
                f"operator adds them (/scope)." if outside else "")
        return ToolResult(content=f"{len(hosts)} subdomain(s) of {domain}, {len(inside)} in scope.{note}",
                          data={"in_scope": inside[:MAX_ITEMS], "out_of_scope": outside[:MAX_ITEMS]})

    registry.add("subdomain_discovery",
                 "Passive subdomain discovery with subfinder (public sources only — sends nothing to "
                 "the target). Results are split into in-scope and out-of-scope.",
                 subdomain_discovery, phase="recon",
                 parameters={"type": "object", "properties": {"domain": {"type": "string"}},
                             "required": ["domain"]})

    # ── dnsx ───────────────────────────────────────────────────────────────────
    def dns_records(args: dict, _ctx) -> ToolResult:
        hosts = _targets(args, "hosts", "host")
        if not hosts:
            return ToolResult.fail("'hosts' is required")
        if not available("dnsx"):
            return _missing("dnsx")
        res = run("dnsx", ["-silent", "-json", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp",
                           "-retry", "2", "-disable-update-check"],
                  input_text="\n".join(host_of(h) or h for h in hosts) + "\n", timeout=120, vault=vault)
        rows = _jsonl(res.stdout)
        if not rows and not res.ok:
            return _failed(res)
        records = {r.get("host"): {k: r.get(k) for k in ("a", "aaaa", "cname", "mx", "ns", "txt") if r.get(k)}
                   for r in rows}
        return ToolResult(content=f"DNS records for {len(records)} host(s)", data={"records": records})

    registry.add("dns_records",
                 "Full DNS records (A, AAAA, CNAME, MX, NS, TXT) with dnsx — SPF/DMARC, takeover-prone "
                 "CNAMEs, mail and name servers.",
                 dns_records, phase="recon",
                 parameters={"type": "object", "properties": {
                     "hosts": {"type": "array", "items": {"type": "string"}}}, "required": ["hosts"]})

    # ── gau ────────────────────────────────────────────────────────────────────
    def known_urls(args: dict, _ctx) -> ToolResult:
        domain = host_of(args.get("domain") or "")
        if not domain:
            return ToolResult.fail("'domain' is required")
        if not available("gau"):
            return _missing("gau")
        res = run("gau", ["--threads", "2", "--timeout", "30", "--blacklist",
                          "png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,ico,mp4", domain], timeout=240, vault=vault)
        urls = list(dict.fromkeys(u.strip() for u in res.stdout.splitlines() if u.strip().startswith("http")))
        if not urls and not res.ok:
            return _failed(res)
        params = sorted({p.split("=")[0] for u in urls for p in urlsplit(u).query.split("&") if "=" in p})
        store("known_urls", urls)
        observe(Surface(host=domain, domain="web", endpoints=[urlsplit(u).path for u in urls[:MAX_ITEMS]]))
        return ToolResult(content=f"{len(urls)} archived URL(s) for {domain}, {len(params)} distinct parameter(s)",
                          data={"sample": urls[:60], "parameters": params[:MAX_ITEMS]})

    registry.add("known_urls",
                 "Historical URLs for a domain from public archives (Wayback, Common Crawl, OTX) with gau "
                 "— passive; reveals old endpoints and parameters.",
                 known_urls, phase="recon",
                 parameters={"type": "object", "properties": {"domain": {"type": "string"}},
                             "required": ["domain"]})

    # ── katana ─────────────────────────────────────────────────────────────────
    def crawl(args: dict, _ctx) -> ToolResult:
        url = (args.get("url") or "").strip()
        if not url:
            return ToolResult.fail("'url' is required")
        if not available("katana"):
            return _missing("katana")
        depth = str(max(1, min(int(args.get("depth") or 2), 3)))
        res = run("katana", ["-u", url, "-d", depth, "-jsonl", "-silent", "-nc", "-rl", RATE, "-c", "5",
                             "-timeout", "10", "-ct", "120", "-fs", "fqdn", "-disable-update-check"],
                  timeout=200, vault=vault)
        rows = _jsonl(res.stdout)
        if not rows and not res.ok:
            return _failed(res)
        endpoints = list(dict.fromkeys((r.get("request") or {}).get("endpoint") or r.get("endpoint") or ""
                                       for r in rows))
        endpoints = [e for e in endpoints if e][:MAX_ITEMS]
        forms = sum(1 for r in rows if (r.get("response") or {}).get("forms"))
        host = host_of(url)
        observe(Surface(host=host, domain="web", endpoints=[urlsplit(e).path or "/" for e in endpoints]))
        store("crawl", endpoints)
        return ToolResult(content=f"crawled {url} (depth {depth}): {len(endpoints)} endpoint(s), {forms} with forms",
                          data={"endpoints": endpoints})

    registry.add("crawl",
                 "Crawl a web app with katana (same host only, depth ≤ 3, rate-limited) to map endpoints, "
                 "parameters and forms.",
                 crawl, phase="recon",
                 parameters={"type": "object", "properties": {
                     "url": {"type": "string"}, "depth": {"type": "integer", "minimum": 1, "maximum": 3}},
                     "required": ["url"]})

    # ── ffuf ───────────────────────────────────────────────────────────────────
    def content_discovery(args: dict, _ctx) -> ToolResult:
        url = (args.get("url") or "").strip().rstrip("/")
        if not url:
            return ToolResult.fail("'url' is required")
        if not available("ffuf"):
            return _missing("ffuf")
        res = run("ffuf", ["-u", f"{url}/FUZZ", "-w", wordlist_path(), "-mc", "200,204,301,302,307,401,403",
                           "-rate", RATE, "-t", "10", "-maxtime", "120", "-timeout", "10", "-s", "-json",
                           "-noninteractive"], timeout=180, vault=vault)
        rows = _jsonl(res.stdout)
        if not rows and not res.ok and res.returncode not in (0, None):
            return _failed(res)
        hits = [{"path": "/" + _ffuf_input(r), "status": r.get("status"),
                 "length": r.get("length"), "redirect": r.get("redirectlocation", "")} for r in rows][:MAX_ITEMS]
        observe(Surface(host=host_of(url), domain="web", endpoints=[h["path"] for h in hits]))
        store("content_discovery", hits)
        return ToolResult(content=f"{len(hits)} path(s) found under {url}", data={"found": hits})

    registry.add("content_discovery",
                 "Discover common sensitive paths (admin panels, backups, .git, .env, API docs) with ffuf "
                 "using a short built-in list at a low request rate.",
                 content_discovery, phase="recon",
                 parameters={"type": "object", "properties": {"url": {"type": "string"}},
                             "required": ["url"]})

    # ── nuclei ─────────────────────────────────────────────────────────────────
    def template_scan(args: dict, _ctx) -> ToolResult:
        targets = _targets(args, "targets", "url", "host")
        if not targets:
            return ToolResult.fail("'targets' is required")
        if not available("nuclei"):
            return _missing("nuclei")
        from .installer import template_count
        if template_count() == 0:
            return ToolResult.fail("nuclei has no templates yet — run: autopwnai tools update nuclei")
        argv = ["-jsonl", "-silent", "-nc", "-duc", "-rl", RATE, "-c", "10", "-timeout", "10",
                "-pt", "http", "-etags", NUCLEI_EXCLUDED_TAGS]
        severity = args.get("severity")
        if severity:
            argv += ["-severity", ",".join(severity) if isinstance(severity, list) else str(severity)]
        tags = args.get("tags")
        if tags:
            argv += ["-tags", ",".join(tags) if isinstance(tags, list) else str(tags)]
        elif not args.get("full"):
            argv += ["-tags", NUCLEI_DEFAULT_TAGS]
        res = run("nuclei", argv, input_text="\n".join(targets) + "\n", timeout=900, vault=vault)
        rows = _jsonl(res.stdout)
        if not rows and not res.ok:
            return _failed(res)
        findings: list[dict] = []
        grouped: dict[tuple[str, str], dict] = {}
        for r in rows[:MAX_ITEMS]:
            key = (str(r.get("template-id") or ""), str(r.get("matched-at") or r.get("host") or ""))
            g = grouped.get(key)
            if g is None:
                grouped[key] = {"row": r, "matchers": [m for m in [r.get("matcher-name")] if m]}
            elif r.get("matcher-name") and r["matcher-name"] not in g["matchers"]:
                g["matchers"].append(r["matcher-name"])        # one result per template+URL
        added = 0
        for (template, matched), g in grouped.items():
            r, matchers = g["row"], g["matchers"]
            info = r.get("info") or {}
            sev = str(info.get("severity", "unknown")).lower()
            cls = info.get("classification") or {}
            cwe = cls.get("cwe-id") or [""]
            name = str(info.get("name") or template)
            findings.append({"template": template, "name": name, "severity": sev, "matched_at": matched,
                             "matchers": matchers, "extracted": (r.get("extracted-results") or [])[:5],
                             "cve": cls.get("cve-id") or []})
            if pipeline is None or sev in ("info", "unknown"):
                continue                     # informational matches stay in the output, not the report
            req = redactor.scrub(str(r.get("request") or "")[:2000]) if redactor else ""
            resp = redactor.scrub(str(r.get("response") or "")[:2000]) if redactor else ""
            detail = f" ({', '.join(matchers)})" if matchers else ""
            pipeline.add(Candidate(
                "template_finding", host=host_of(matched), url=matched if "://" in matched else "",
                confidence=0.85, method="direct", key=template, title=name,
                cvss=float((cls.get("cvss-score") or NUCLEI_CVSS.get(sev, 0.0)) or 0.0),
                cwe=(cwe[0] if isinstance(cwe, list) and cwe else str(cwe or "")).upper(),
                description=str(info.get("description") or "")[:1000],
                remediation=str(info.get("remediation") or "")[:1000],
                references=list(info.get("reference") or [])[:5],
                note=f"nuclei template {template} matched{detail}",
                evidence_request=req, evidence_response=resp,
                steps=[f"nuclei -id {template} -u {matched}"]))
            added += 1
        store("template_scan", rows)
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        summary = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items(), key=lambda x: -NUCLEI_CVSS.get(x[0], 0)))
        tail = (f"; {added} added to findings as suspected — run verify_findings next" if added
                else "; nothing above informational")
        return ToolResult(content=f"nuclei: {len(findings)} result(s)" + (f" — {summary}" if summary else "") + tail,
                          data={"matches": findings})

    registry.add("template_scan",
                 "Scan with nuclei's community templates for known CVEs, exposures and misconfigurations. "
                 "By default it runs the exposure, misconfiguration, admin-panel and technology checks; "
                 "pass tags to focus (e.g. ['cve'] for a CVE sweep) or full=true for everything (slow). Safe mode: DoS, fuzzing, brute-force, RCE, LFI, "
                 "upload and takeover templates are excluded; rate-limited. Matches become suspected findings.",
                 template_scan, phase="detection",
                 parameters={"type": "object", "properties": {
                     "targets": {"type": "array", "items": {"type": "string"}},
                     "severity": {"type": "array", "items": {"type": "string",
                                  "enum": ["info", "low", "medium", "high", "critical"]}},
                     "tags": {"type": "array", "items": {"type": "string"},
                              "description": "limit to template tags, e.g. ['cve','exposure','misconfig']"},
                     "full": {"type": "boolean",
                              "description": "run every safe HTTP template (slow) instead of the "
                                             "default exposure/misconfig/panel/tech set"}},
                     "required": ["targets"]})

    registry.mark_scoped(active=("http_probe", "crawl", "content_discovery", "template_scan"),
                         passive=("subdomain_discovery", "dns_records", "known_urls"))


def port_discovery_naabu(host: str, *, ports: str = "100", vault=None) -> list[Service] | None:
    """Fast connect-scan port discovery (no root) when nmap is missing."""
    if not available("naabu"):
        return None
    res = run("naabu", ["-host", host, "-top-ports", ports, "-scan-type", "c", "-rate", "200", "-json",
                        "-silent", "-disable-update-check"], timeout=180, vault=vault)
    rows = _jsonl(res.stdout)
    if not rows and not res.ok:
        return None
    return [Service(port=int(r["port"]) if not isinstance(r.get("port"), dict) else int(r["port"].get("Port", 0)))
            for r in rows if r.get("port")]
