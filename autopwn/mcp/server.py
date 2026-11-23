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


def exposed_tools(session) -> list:
    return [t for t in session.registry.tools() if t.source == "native" and t.name not in HIDDEN]


def build_server(session):
    from mcp import types
    from mcp.server.lowlevel import Server

    from .. import __version__

    scope = ", ".join(session.targets) or "nothing"
    instructions = (
        "AutoPwn AI purple-team tools. Only targets in scope can be tested "
        f"(in scope: {scope}); calls outside it are refused. Verification is non-destructive. "
        "Typical flow: http_probe / web_recon / network_scan → detect_* / template_scan → "
        "verify_findings → list_findings → generate_report.")

    async def list_tools(_ctx, _params):
        return types.ListToolsResult(tools=[
            types.Tool(name=t.name, description=t.description,
                       input_schema=t.parameters or {"type": "object", "properties": {}})
            for t in exposed_tools(session)])

    async def call_tool(_ctx, params):
        if params.name in HIDDEN or session.registry.get(params.name) is None:
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


async def serve_stdio(session) -> None:
    from mcp.server.stdio import stdio_server
    server = build_server(session)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
