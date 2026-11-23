"""Detection and verification tools for the agent."""
from __future__ import annotations

from typing import Any

from .. import playbooks
from ..agent.tools import ToolRegistry, ToolResult
from . import mobile as dmob
from . import network as dnet
from . import server as dsrv
from . import web as dweb
from .signatures import VULN_CLASSES


def _summarize(findings, redactor) -> dict:
    by_class: dict[str, int] = {}
    rows = []
    for f in findings:
        by_class[f.title] = by_class.get(f.title, 0) + 1
        rows.append({"id": f.id, "title": f.title, "severity": f.severity.rating.value,
                     "cvss": f.severity.cvss_score, "status": f.status.value,
                     "where": f.target.url or f.target.host,
                     "param": f.target.param or "", "note": f.safe_poc})
    safe = redactor.scrub_obj(rows) if redactor else rows
    return {"count": len(findings), "by_class": by_class, "findings": safe}


def register_detection_tools(
    registry: ToolRegistry,
    *,
    ctx=None,
    pipeline,
    verifier,
    coverage,
    target_model,
    redactor=None,
) -> None:

    def get_playbook(args: dict[str, Any], _ctx) -> ToolResult:
        domain = args.get("domain", "")
        text = playbooks.load(domain)
        if not text:
            return ToolResult.fail(f"no playbook for '{domain}'", available=playbooks.available())
        return ToolResult(content=text, data={"domain": domain})

    registry.add("get_playbook",
                 "Load the methodology playbook for a domain (web/network/server/mobile).",
                 get_playbook, phase="planning",
                 parameters={"type": "object",
                             "properties": {"domain": {"type": "string",
                                            "enum": playbooks.available()}},
                             "required": ["domain"]})

    def detect_web(args: dict[str, Any], _ctx) -> ToolResult:
        url = args.get("url")
        if not url:
            return ToolResult.fail("'url' is required")
        cands = dweb.detect_all(url, params=args.get("params"))
        findings = pipeline.add_all([c for c in cands if c.class_id in VULN_CLASSES])
        from urllib.parse import urlparse
        host = cands[0].host if cands else (urlparse(url if '://' in url else 'https://' + url).hostname or url)
        coverage.mark_checked_many(host, "web")
        return ToolResult(content=f"web detection: {len(findings)} suspected on {host}",
                          data=_summarize(findings, redactor))

    registry.add("detect_web",
                 "Run safe web vulnerability detection against a URL (missing "
                 "headers, cookie flags, exposed files/panels, reflected XSS, "
                 "SQLi error probe). Produces SUSPECTED findings; verify them next.",
                 detect_web, phase="detection",
                 parameters={"type": "object",
                             "properties": {"url": {"type": "string"},
                                            "params": {"type": "array", "items": {"type": "string"},
                                                       "description": "optional parameter names to test"}},
                             "required": ["url"]})

    def _need_surface(host):
        s = target_model.get(host)
        if s is None:
            return None, ToolResult.fail(f"no recon surface for '{host}' — run recon first")
        return s, None

    def detect_network(args: dict[str, Any], _ctx) -> ToolResult:
        host = args.get("host")
        if not host:
            return ToolResult.fail("'host' is required")
        surface, err = _need_surface(host)
        if err:
            return err
        findings = pipeline.add_all(dnet.detect_from_surface(surface))
        coverage.mark_checked_many(host, "network")
        return ToolResult(content=f"network detection: {len(findings)} suspected on {host}",
                          data=_summarize(findings, redactor))

    registry.add("detect_network",
                 "Flag weak/exposed services from a host's recon surface "
                 "(cleartext services, unauthenticated datastores). SUSPECTED until verified.",
                 detect_network, phase="detection",
                 parameters={"type": "object", "properties": {"host": {"type": "string"}},
                             "required": ["host"]})

    def detect_server(args: dict[str, Any], _ctx) -> ToolResult:
        host = args.get("host")
        if not host:
            return ToolResult.fail("'host' is required")
        surface, err = _need_surface(host)
        if err:
            return err
        findings = pipeline.add_all(dsrv.detect_from_surface(surface))
        coverage.mark_checked_many(host, "server")
        return ToolResult(content=f"server detection: {len(findings)} suspected on {host}",
                          data=_summarize(findings, redactor))

    registry.add("detect_server",
                 "Flag server/infra issues from recon (weak/expired TLS, outdated "
                 "software banner). SUSPECTED until verified.",
                 detect_server, phase="detection",
                 parameters={"type": "object", "properties": {"host": {"type": "string"}},
                             "required": ["host"]})

    def detect_mobile(args: dict[str, Any], _ctx) -> ToolResult:
        path = args.get("path")
        if not path:
            return ToolResult.fail("'path' to an APK is required")
        from ..recon import mobile as rmobile
        _surface, raw = rmobile.apk_inventory(path)
        host = _surface.host
        findings = pipeline.add_all(dmob.detect_from_inventory(raw, host))
        coverage.mark_checked_many(host, "mobile")
        return ToolResult(content=f"mobile detection: {len(findings)} suspected in {host}",
                          data=_summarize(findings, redactor))

    registry.add("detect_mobile",
                 "Static Android detection from an APK (hardcoded secrets, cleartext "
                 "traffic, debuggable, exported components). SUSPECTED until verified.",
                 detect_mobile, phase="detection",
                 parameters={"type": "object", "properties": {"path": {"type": "string"}},
                             "required": ["path"]})

    def verify_findings(args: dict[str, Any], _ctx) -> ToolResult:
        promoted = pipeline.verify_all(verifier)
        coverage.record_round(len(promoted))
        return ToolResult(
            content=f"verified {len(promoted)} finding(s) non-destructively; "
                    f"{len(pipeline.suspected())} remain suspected",
            data={"verified": _summarize(promoted, redactor),
                  "still_suspected": len(pipeline.suspected()),
                  "coverage": coverage.status()})

    registry.add("verify_findings",
                 "Safely (non-destructively) verify all suspected findings. "
                 "Promotes confirmed ones to VERIFIED — the false-positive filter. "
                 "Only verified findings are reportable.",
                 verify_findings, phase="verify",
                 parameters={"type": "object", "properties": {}})

    def list_findings(args: dict[str, Any], _ctx) -> ToolResult:
        status = args.get("status")
        if status == "verified":
            fs = pipeline.reportable()
        elif status == "suspected":
            fs = pipeline.suspected()
        else:
            fs = pipeline.all()
        return ToolResult(content=f"{len(fs)} finding(s)", data=_summarize(fs, redactor))

    registry.add("list_findings",
                 "List findings, optionally filtered by status (verified/suspected).",
                 list_findings, phase="verify",
                 parameters={"type": "object",
                             "properties": {"status": {"type": "string",
                                            "enum": ["verified", "suspected", "all"]}}})

    def coverage_status(args: dict[str, Any], _ctx) -> ToolResult:
        return ToolResult(content="coverage " + ("COMPLETE" if coverage.is_complete() else "in progress"),
                          data=coverage.status())

    registry.add("coverage_status",
                 "Report scan coverage and whether the 'coverage-complete' signal "
                 "is met (checklist done + plateau, or budget).",
                 coverage_status, phase="verify",
                 parameters={"type": "object", "properties": {}})

    registry.mark_scoped(active=("detect_web", "detect_network", "detect_server"))
