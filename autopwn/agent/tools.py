"""Tool harness: registry, dispatch, structured results. Destructive tools are
refused at registration.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..llm.provider import ToolCall, ToolSpec

if TYPE_CHECKING:                       # avoid a hard import cycle at runtime
    from ..core.context import RunContext


class ToolError(Exception):
    """A handler may raise this for an expected, user-meaningful failure.
    It is caught and turned into a structured error result, not propagated."""


@dataclass
class ToolResult:
    """What a tool hands back. `render()` is what the model actually sees."""
    ok: bool = True
    content: str = ""                    # human/model-readable summary
    data: dict[str, Any] = field(default_factory=dict)   # structured payload
    error: str = ""
    final: bool = False                  # True = this tool ends the agent loop
    artifacts: list[str] = field(default_factory=list)   # run-dir relative paths

    @classmethod
    def fail(cls, error: str, **data: Any) -> ToolResult:
        return cls(ok=False, error=error, data=data)

    @classmethod
    def done(cls, content: str, **data: Any) -> ToolResult:
        """A terminal result — the agent's final answer."""
        return cls(ok=True, content=content, data=data, final=True)

    def render(self) -> str:
        """Serialize for the `tool` message fed back to the model."""
        if not self.ok:
            return json.dumps({"error": self.error, **self.data}, ensure_ascii=False, default=str)
        if self.data and not self.content:
            return json.dumps(self.data, ensure_ascii=False, default=str)
        if self.data:
            return json.dumps({"summary": self.content, **self.data}, ensure_ascii=False, default=str)
        return self.content or "(ok)"


# handler(args, ctx) -> ToolResult   (ctx may be None in tests)
Handler = Callable[[dict[str, Any], "RunContext | None"], ToolResult]


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    handler: Handler | None = None
    requires_approval: bool = False      # gate even in autonomous mode
    phase: str | None = None             # which methodology phase it belongs to
    destructive: bool = False            # refused at registration: the toolset is non-destructive
    source: str = "native"               # "native" | "mcp:<server>"
    scoped: bool = False                 # its target arguments must be in scope
    active: bool = False                 # sends traffic to the target: needs authorization too

    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.parameters)


class ToolRegistry:
    """Holds tools and dispatches calls. One registry per run."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self.guard = None                    # ScopeGuard, set by the session

    def mark_scoped(self, *, active: tuple[str, ...] = (), passive: tuple[str, ...] = ()) -> None:
        for name in active + passive:
            if (t := self._tools.get(name)) is not None:
                t.scoped, t.active = True, name in active

    def register(self, tool: Tool) -> Tool:
        if tool.destructive:
            # non-destruction is guaranteed by never admitting a destructive tool
            raise ToolError(f"refusing to register destructive tool '{tool.name}' (the toolset is non-destructive)")
        if tool.name in self._tools:
            raise ToolError(f"duplicate tool name: {tool.name}")
        self._tools[tool.name] = tool
        return tool

    def add(self, name: str, description: str, handler: Handler, **kw) -> Tool:
        """Convenience for registering a native tool inline."""
        return self.register(Tool(name=name, description=description, handler=handler, **kw))

    def unregister_source(self, source: str) -> list[str]:
        """Remove every tool from one source (e.g. 'mcp:github' on disconnect)."""
        gone = [n for n, t in self._tools.items() if t.source == source]
        for n in gone:
            del self._tools[n]
        return gone

    def tools(self) -> list[Tool]:
        return list(self._tools.values())

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def specs(self, phase: str | None = None) -> list[ToolSpec]:
        """Tool specs to expose to the model. If `phase` is given, tools tagged
        for a *different* phase are hidden (untagged tools are always shown)."""
        out = []
        for t in self._tools.values():
            if phase is not None and t.phase is not None and t.phase != phase:
                continue
            out.append(t.spec())
        return out

    def names(self) -> list[str]:
        return list(self._tools)

    def dispatch(self, call: ToolCall, ctx: RunContext | None = None) -> ToolResult:
        tool = self._tools.get(call.name)
        if tool is None:
            return ToolResult.fail(f"unknown tool '{call.name}'",
                                   available=list(self._tools))
        if tool.handler is None:
            return ToolResult.fail(f"tool '{call.name}' has no handler")
        if tool.scoped and self.guard is not None:
            decision = self.guard.check(call.arguments or {}, active=tool.active)
            if not decision.allowed:
                if ctx is not None:
                    ctx.logger.warning("tool.blocked", tool=call.name, reason=decision.reason)
                return ToolResult.fail(f"blocked by the scope gate: {decision.reason}", blocked=True)
        started = time.time()
        try:
            result = tool.handler(call.arguments or {}, ctx)
        except ToolError as e:
            result = ToolResult.fail(str(e))
        except Exception as e:                      # never leak a traceback to the model
            result = ToolResult.fail(f"{type(e).__name__}: {e}")
        if ctx is not None:
            ctx.logger.info(
                "tool.result", tool=call.name, ok=result.ok,
                ms=round((time.time() - started) * 1000, 1),
                final=result.final, source=tool.source,
            )
            for art in result.artifacts:
                ctx.store.add_artifact(ctx.run_id, kind="raw", path=art, meta={"tool": call.name})
        return result
