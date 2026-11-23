"""AutoPwn AI as an MCP server: its recon, detection, verification, reporting
and memory tools for any MCP client (Claude Desktop, IDEs, other agents).

The same governance applies as in the app: the hard scope gate checks every
target, secrets are vaulted, everything is written to the run's audit log, and
the toolset stays non-destructive. Scope is fixed when the server starts.

    autopwnai mcp-serve -t app.lab -t "*.app.lab" --authorize
"""
from __future__ import annotations

import anyio

from ..llm.provider import ToolCall

# control tools that only make sense inside AutoPwn's own agent loop
HIDDEN = frozenset({"advance_phase", "finish", "record_observation"})


WEB = frozenset({"web_recon", "http_probe", "crawl", "content_discovery", "template_scan", "subdomain_discovery",
                 "known_urls", "dns_records", "dns_lookup", "tls_inspect", "detect_web", "verify_findings",
                 "list_findings", "generate_report", "coverage_status", "get_playbook", "web_deep_scan"})
TOOLSETS = ("all", "web", "browser")


def exposed_tools(session, toolset: str = "all") -> list:
    tools = [t for t in session.registry.tools() if t.source == "native" and t.name not in HIDDEN]
    if toolset == "browser":
        return [t for t in tools if t.name.startswith("browser_") or t.name in ("web_deep_scan", "verify_findings",
                                                                               "list_findings", "generate_report")]
    if toolset == "web":
        return [t for t in tools if t.name.startswith("browser_") or t.name in WEB]
    return tools


def build_server(session, toolset: str = "all"):
    from mcp import types
    from mcp.server.lowlevel import Server

    from .. import __version__

    scope = ", ".join(session.targets) or "nothing"
    instructions = (
        f"AutoPwn AI purple-team tools ({toolset} toolset). Only targets in scope can be tested "
        f"(in scope: {scope}); calls outside it are refused. Verification is non-destructive. "
        "Typical web flow: web_deep_scan(url) for the full assessment, then browser_open / browser_snapshot / "
        "browser_click / browser_fill to explore, browser_network / browser_sources / browser_application / "
        "browser_security / browser_console to inspect like DevTools, browser_dom_xss and detect_web to test, "
        "verify_findings → list_findings → generate_report.")

    async def list_tools(_ctx, _params):
        return types.ListToolsResult(tools=[
            types.Tool(name=t.name, description=t.description,
                       input_schema=t.parameters or {"type": "object", "properties": {}})
            for t in exposed_tools(session, toolset)])

    async def call_tool(_ctx, params):
        allowed = {t.name for t in exposed_tools(session, toolset)}
        if params.name not in allowed:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"unknown tool {params.name}")],
                                        is_error=True)
        call = ToolCall("mcp", params.name, dict(params.arguments or {}))
        session.audit.record("mcp.call", tool=params.name)
        result = await anyio.to_thread.run_sync(session.registry.dispatch, call, session.ctx)
        structured = result.data if result.ok and isinstance(result.data, dict) and result.data else None
        return types.CallToolResult(content=[types.TextContent(type="text", text=result.render())],
                                    structured_content=structured, is_error=not result.ok)

    return Server("autopwn-ai", version=__version__, title="AutoPwn AI",
                  instructions=instructions, on_list_tools=list_tools, on_call_tool=call_tool)


async def serve_stdio(session, toolset: str = "all") -> None:
    from mcp.server.stdio import stdio_server
    server = build_server(session, toolset)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
