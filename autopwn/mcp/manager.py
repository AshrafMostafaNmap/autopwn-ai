"""All MCP connections of one session."""
from __future__ import annotations

from pathlib import Path

from ..agent.tools import ToolRegistry
from .client import MCPClient
from .config import MCPServerConfig


class MCPManager:
    def __init__(self, registry: ToolRegistry, *, log_dir: Path):
        self.registry = registry
        self.log_dir = Path(log_dir)
        self._clients: dict[str, MCPClient] = {}
        self._errors: dict[str, str] = {}

    def connect(self, cfg: MCPServerConfig) -> list[str]:
        self.disconnect(cfg.name)
        client = MCPClient(cfg, errlog_path=str(self.log_dir / f"mcp-{cfg.name}.log"))
        try:
            client.connect()
            names = client.surface_into(self.registry)
        except Exception as e:
            client.close()
            self.registry.unregister_source(f"mcp:{cfg.name}")
            self._errors[cfg.name] = str(e)
            raise
        self._clients[cfg.name] = client
        self._errors.pop(cfg.name, None)
        return names

    def disconnect(self, name: str) -> None:
        client = self._clients.pop(name, None)
        if client is not None:
            client.close()
        self.registry.unregister_source(f"mcp:{name}")

    def connect_all(self, configs: list[MCPServerConfig]) -> dict[str, str]:
        results = {}
        for cfg in configs:
            if not cfg.enabled:
                continue
            try:
                results[cfg.name] = f"ok ({len(self.connect(cfg))} tools)"
            except Exception as e:
                results[cfg.name] = f"error: {e}"
        return results

    def status(self, configs: list[MCPServerConfig]) -> list[dict]:
        rows = []
        for cfg in configs:
            client = self._clients.get(cfg.name)
            rows.append({"name": cfg.name, "transport": cfg.transport, "command": cfg.display,
                         "trusted": cfg.trusted, "enabled": cfg.enabled,
                         "connected": bool(client and client.connected),
                         "tools": len(client.tool_names) if client else 0,
                         "server": client.server_name if client else "",
                         "error": self._errors.get(cfg.name, "")})
        return rows

    def connected_names(self) -> list[str]:
        return [n for n, c in self._clients.items() if c.connected]

    def close_all(self) -> None:
        for name in list(self._clients):
            self.disconnect(name)
