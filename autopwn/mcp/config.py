"""MCP server configuration."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

TRANSPORTS = ("stdio", "http", "sse")


@dataclass
class MCPServerConfig:
    name: str
    command: str = ""                       # stdio
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""                           # http / sse
    headers: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"
    trusted: bool = False                   # trusted servers' tools run without approval
    enabled: bool = True
    timeout: float = 60.0                   # per tool call, seconds

    def __post_init__(self) -> None:
        if self.transport not in TRANSPORTS:
            raise ValueError(f"MCP server '{self.name}': unknown transport '{self.transport}'")
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"MCP server '{self.name}': stdio transport needs a command")
        if self.transport != "stdio" and not self.url:
            raise ValueError(f"MCP server '{self.name}': {self.transport} transport needs a url")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPServerConfig:
        known = cls.__dataclass_fields__
        values = {k: v for k, v in data.items() if k in known}
        if "transport" not in values:
            values["transport"] = "stdio" if values.get("command") else "http"
        values["args"] = list(values.get("args") or [])
        values["env"] = dict(values.get("env") or {})
        values["headers"] = dict(values.get("headers") or {})
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def display(self) -> str:
        if self.transport == "stdio":
            return " ".join([self.command, *self.args])
        return f"{self.transport} {self.url}"
