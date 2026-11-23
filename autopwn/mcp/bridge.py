"""Expose MCP tools as native agent tools."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ..agent.tools import Tool, ToolRegistry, ToolResult

# invoker(tool_name, arguments) -> (text, structured_or_None)
Invoker = Callable[[str, dict], "tuple[str, dict | None]"]

_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")
_MAX_NAME = 64


def qualified_name(server: str, tool: str) -> str:
    """LLM APIs accept only `[A-Za-z0-9_-]{1,64}` as tool names."""
    return f"{_UNSAFE.sub('_', server)}__{_UNSAFE.sub('_', tool)}"[:_MAX_NAME]


def _unique(name: str, registry: ToolRegistry) -> str:
    if name not in registry:
        return name
    for i in range(2, 100):
        suffix = f"_{i}"
        candidate = name[: _MAX_NAME - len(suffix)] + suffix
        if candidate not in registry:
            return candidate
    raise ValueError(f"cannot find a free tool name for {name}")


def make_tool(server: str, tool_def: dict, invoker: Invoker, *, trusted: bool,
              name: str | None = None) -> Tool:
    remote = tool_def["name"]
    params = tool_def.get("inputSchema") or tool_def.get("parameters") or {
        "type": "object", "properties": {}}

    def handler(args: dict[str, Any], _ctx) -> ToolResult:
        text, data = invoker(remote, args)
        return ToolResult(ok=True, content=text or "", data=data or {})

    return Tool(name=name or qualified_name(server, remote),
                description=tool_def.get("description") or f"{remote} (MCP server {server})",
                parameters=params, handler=handler, source=f"mcp:{server}",
                requires_approval=not trusted)


def register_mcp_tools(registry: ToolRegistry, server: str, tool_defs: list[dict],
                       invoker: Invoker, *, trusted: bool = False) -> list[str]:
    added = []
    for td in tool_defs:
        name = _unique(qualified_name(server, td["name"]), registry)
        registry.register(make_tool(server, td, invoker, trusted=trusted, name=name))
        added.append(name)
    return added
