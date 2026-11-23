"""MCP client: one server connection, bridged to synchronous callers.

The SDK is async; the agent loop is not. Each client runs its own event loop on a
daemon thread, and the whole session lives inside a single task because anyio
cancel scopes must be entered and exited by the same task.
"""
from __future__ import annotations

import asyncio
import os
import threading

from ..agent.tools import ToolError, ToolRegistry
from .bridge import register_mcp_tools
from .config import MCPServerConfig

_CONNECTION_ERRORS = ("ClosedResourceError", "BrokenResourceError", "EndOfStream",
                      "BrokenPipeError", "ConnectionError", "RemoteProtocolError")


class MCPClient:
    def __init__(self, config: MCPServerConfig, *, errlog_path: str | None = None):
        self.config = config
        self.errlog_path = errlog_path
        self.tool_names: list[str] = []
        self.server_name = ""
        self.has_resources = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._session = None
        self._runner = None
        self._shutdown: asyncio.Event | None = None
        self._lock = threading.Lock()

    @property
    def connected(self) -> bool:
        return self._session is not None

    def connect(self, timeout: float = 45.0) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True,
                                        name=f"mcp-{self.config.name}")
        self._thread.start()
        ready = self._loop.create_future()
        self._runner = asyncio.run_coroutine_threadsafe(self._serve(ready), self._loop)
        try:
            asyncio.run_coroutine_threadsafe(_wait(ready), self._loop).result(timeout=timeout)
        except BaseException as e:
            self._teardown()
            raise RuntimeError(f"MCP server '{self.config.name}' failed to start: {_reason(e)}") from e

    def close(self) -> None:
        if self._loop is not None and self._shutdown is not None:
            self._loop.call_soon_threadsafe(self._shutdown.set)
            if self._runner is not None:
                try:
                    self._runner.result(timeout=10.0)
                except Exception:
                    pass
        self._teardown()

    def _teardown(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5.0)
        self._loop = self._thread = self._session = self._runner = None

    async def _serve(self, ready: asyncio.Future) -> None:
        from mcp import ClientSession
        self._shutdown = asyncio.Event()
        errlog = open(self.errlog_path or os.devnull, "a", encoding="utf-8")
        try:
            async with self._transport(errlog) as streams:
                read, write = streams[0], streams[1]
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    info = getattr(init, "server_info", None) or getattr(init, "serverInfo", None)
                    self.server_name = getattr(info, "name", "") or ""
                    caps = getattr(init, "capabilities", None)
                    self.has_resources = bool(getattr(caps, "resources", None))
                    self._session = session
                    if not ready.done():
                        ready.set_result(True)
                    await self._shutdown.wait()
        except BaseException as e:
            if not ready.done():
                ready.set_exception(e)
            else:
                raise
        finally:
            self._session = None
            errlog.close()

    def _transport(self, errlog):
        cfg = self.config
        if cfg.transport == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client
            params = StdioServerParameters(command=cfg.command, args=list(cfg.args),
                                           env=self._environment())
            return stdio_client(params, errlog=errlog)
        if cfg.transport == "sse":
            from mcp.client.sse import sse_client
            return sse_client(cfg.url, headers=cfg.headers or None, timeout=min(cfg.timeout, 30.0))
        return _http_transport(cfg.url, cfg.headers)

    def _environment(self) -> dict[str, str] | None:
        if not self.config.env:
            return None
        from mcp.client.stdio import get_default_environment
        return {**get_default_environment(), **self.config.env}

    def _call(self, make_coro):
        """Run an SDK call; on a dropped connection reconnect once and retry."""
        for attempt in (1, 2):
            if not self.connected:
                self._reconnect()
            try:
                return asyncio.run_coroutine_threadsafe(make_coro(self._session), self._loop) \
                    .result(timeout=self.config.timeout)
            except Exception as e:
                if attempt == 1 and _is_connection_error(e):
                    self._session = None
                    continue
                raise
        raise RuntimeError(f"MCP server '{self.config.name}' is not reachable")

    def _reconnect(self) -> None:
        with self._lock:
            if self.connected:
                return
            self.close()
            self.connect()

    def list_tools(self) -> list[dict]:
        resp = self._call(lambda s: s.list_tools())
        return [{"name": t.name, "description": t.description or "",
                 "inputSchema": getattr(t, "input_schema", None) or getattr(t, "inputSchema", None)
                 or {"type": "object", "properties": {}}}
                for t in resp.tools]

    def invoke(self, name: str, arguments: dict) -> tuple[str, dict | None]:
        resp = self._call(lambda s: s.call_tool(name, arguments))
        text = "\n".join(t for t in (getattr(b, "text", None) for b in (resp.content or [])) if t)
        if getattr(resp, "is_error", None) or getattr(resp, "isError", None):
            raise ToolError(text or f"MCP tool '{name}' reported an error")
        structured = getattr(resp, "structured_content", None) or getattr(resp, "structuredContent", None)
        return text, structured if isinstance(structured, dict) else None

    def list_resources(self) -> list[dict]:
        resp = self._call(lambda s: s.list_resources())
        return [{"uri": str(r.uri), "name": r.name, "description": getattr(r, "description", "") or "",
                 "mime": getattr(r, "mime_type", None) or getattr(r, "mimeType", None) or ""}
                for r in resp.resources]

    def read_resource(self, uri: str) -> str:
        resp = self._call(lambda s: s.read_resource(uri))
        parts = []
        for c in resp.contents:
            text = getattr(c, "text", None)
            parts.append(text if text is not None else f"[binary {getattr(c, 'mime_type', '') or 'data'}]")
        return "\n".join(parts)

    def surface_into(self, registry: ToolRegistry) -> list[str]:
        defs = self.list_tools()
        names = register_mcp_tools(registry, self.config.name, defs, self.invoke,
                                   trusted=self.config.trusted)
        if self.has_resources and self._resource_count() > 0:
            names += self._register_resource_tools(registry)
        self.tool_names = names
        return names

    def _resource_count(self) -> int:
        """Servers may advertise the capability with nothing behind it."""
        try:
            return len(self.list_resources())
        except Exception:
            return 0

    def _register_resource_tools(self, registry: ToolRegistry) -> list[str]:
        def list_invoker(_name: str, _args: dict) -> tuple[str, dict | None]:
            items = self.list_resources()
            return f"{len(items)} resource(s)", {"resources": items}

        def read_invoker(_name: str, args: dict) -> tuple[str, dict | None]:
            uri = args.get("uri")
            if not uri:
                raise ToolError("'uri' is required")
            return self.read_resource(uri), None

        defs = [({"name": "list_resources", "description": f"List the resources MCP server {self.config.name} exposes.",
                  "inputSchema": {"type": "object", "properties": {}}}, list_invoker),
                ({"name": "read_resource", "description": f"Read one resource from MCP server {self.config.name} by uri.",
                  "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}},
                                  "required": ["uri"]}}, read_invoker)]
        names = []
        for td, invoker in defs:
            names += register_mcp_tools(registry, self.config.name, [td], invoker, trusted=True)
        return names


async def _wait(fut):
    return await fut


def _http_transport(url: str, headers: dict[str, str]):
    from contextlib import asynccontextmanager

    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    @asynccontextmanager
    async def transport():
        async with create_mcp_http_client(headers=headers or None) as http:
            async with streamable_http_client(url, http_client=http) as streams:
                yield streams
    return transport()


_CONNECTION_MESSAGES = ("connection closed", "not connected", "broken pipe", "closed resource",
                        "end of stream", "connection reset")


def _is_connection_error(e: BaseException) -> bool:
    for x in _chain(e):
        if type(x).__name__ in _CONNECTION_ERRORS:
            return True
        if any(m in str(x).lower() for m in _CONNECTION_MESSAGES):
            return True
    return False


def _chain(e: BaseException):
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        yield e
        e = e.__cause__ or e.__context__


def _reason(e: BaseException) -> str:
    if isinstance(e, BaseExceptionGroup):
        return "; ".join(_reason(x) for x in e.exceptions)
    msg = str(e).strip()
    return f"{type(e).__name__}: {msg}" if msg else type(e).__name__
