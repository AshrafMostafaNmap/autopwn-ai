"""Recon tools for the agent. Raw output is stored locally; the model only sees
the scrubbed attack-surface summary.
"""
from __future__ import annotations

import json
from typing import Any

from ..agent.tools import ToolRegistry, ToolResult
from ..govern import Redactor, Vault
from . import mobile, network, server, web
from .target_model import TargetModel

ACTIVE_RECON = ("web_recon", "network_scan", "tls_inspect")
PASSIVE_RECON = ("dns_lookup",)


def register_recon_tools(
    registry: ToolRegistry,
    *,
    ctx=None,
    vault: Vault,
    redactor: Redactor,
    target_model: TargetModel,
) -> None:

    def _store_raw(name: str, host: str, raw: dict, finding_id=None) -> None:
        if ctx is None:
            return
        # raw may hold secrets → scrub before it ever touches disk we might ship,
        # but keep it local; we scrub cookie/token shapes defensively.
        safe_raw = redactor.scrub_obj(raw)
        path = ctx.artifact_path(f"{name}-{host}-{ctx.run_id}.json".replace("/", "_"))
        path.write_text(json.dumps(safe_raw, indent=2, default=str), encoding="utf-8")
        rel = str(path.relative_to(ctx.run_dir))
        ctx.store.add_artifact(ctx.run_id, kind="recon", path=rel,
                               finding_id=finding_id, meta={"tool": name, "host": host})

    def _emit(name: str, surface, raw: dict) -> ToolResult:
        merged = target_model.observe(surface)
        _store_raw(name, surface.host, raw)
        # the agent sees the scrubbed surface only
        safe = redactor.scrub_obj(merged.to_dict())
        return ToolResult(content=merged.summary(), data=safe)

    def web_recon(args: dict[str, Any], _ctx) -> ToolResult:
        url = args.get("url") or args.get("target")
        if not url:
            return ToolResult.fail("'url' is required")
        surface, raw = web.http_probe(url, vault=vault, redactor=redactor)
        return _emit("web_recon", surface, raw)

    registry.add(
        "web_recon",
        "Safe HTTP recon of a web target (GET only): server, tech fingerprint, "
        "title, security-header posture, cookies (vaulted), DNS. Non-destructive.",
        web_recon, phase="recon",
        parameters={"type": "object",
                    "properties": {"url": {"type": "string", "description": "target URL or host"}},
                    "required": ["url"]},
    )

    def dns_lookup(args: dict[str, Any], _ctx) -> ToolResult:
        host = args.get("host")
        if not host:
            return ToolResult.fail("'host' is required")
        return ToolResult(content=f"DNS {host}", data=web.dns_lookup(host))

    registry.add("dns_lookup", "Resolve A/AAAA records for a host.", dns_lookup,
                 phase="recon",
                 parameters={"type": "object", "properties": {"host": {"type": "string"}},
                             "required": ["host"]})

    def network_scan(args: dict[str, Any], _ctx) -> ToolResult:
        host = args.get("host")
        if not host:
            return ToolResult.fail("'host' is required")
        ports = args.get("ports")
        if isinstance(ports, str):
            ports = [int(p) for p in ports.replace(",", " ").split() if p.strip().isdigit()]
        surface, raw = network.scan_host(host, ports=ports, vault=vault)
        return _emit("network_scan", surface, raw)

    registry.add(
        "network_scan",
        "Non-destructive service discovery on a host (nmap -sV if present, else a "
        "TCP connect scan). Returns open ports/services with banners. Supports "
        "local/LAN hosts.",
        network_scan, phase="recon",
        parameters={"type": "object",
                    "properties": {"host": {"type": "string"},
                                   "ports": {"type": "string", "description": "optional comma/space list of ports"}},
                    "required": ["host"]},
    )

    def tls_inspect(args: dict[str, Any], _ctx) -> ToolResult:
        host = args.get("host")
        if not host:
            return ToolResult.fail("'host' is required")
        port = int(args.get("port", 443))
        surface, raw = server.inspect(host, port)
        return _emit("tls_inspect", surface, raw)

    registry.add(
        "tls_inspect",
        "Inspect a host's TLS: negotiated protocol/cipher, certificate subject/"
        "issuer/validity/SAN, and flags (expired, self-signed, weak protocol). "
        "Read-only single handshake.",
        tls_inspect, phase="recon",
        parameters={"type": "object",
                    "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
                    "required": ["host"]},
    )

    def apk_inventory(args: dict[str, Any], _ctx) -> ToolResult:
        path = args.get("path")
        if not path:
            return ToolResult.fail("'path' to an APK is required")
        surface, raw = mobile.apk_inventory(path, vault=vault)
        return _emit("apk_inventory", surface, raw)

    registry.add(
        "apk_inventory",
        "Static inventory of an Android APK (read-only): dex/libs/assets, "
        "permissions, package, embedded URLs, and hardcoded secrets (vaulted). "
        "Groundwork for mobile detection.",
        apk_inventory, phase="recon",
        parameters={"type": "object",
                    "properties": {"path": {"type": "string", "description": "local path to the .apk"}},
                    "required": ["path"]},
    )

    registry.mark_scoped(active=ACTIVE_RECON, passive=PASSIVE_RECON)
