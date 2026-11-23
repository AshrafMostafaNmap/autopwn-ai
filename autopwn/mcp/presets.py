"""Curated MCP servers that can be added with one action."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field

from .config import MCPServerConfig


@dataclass(frozen=True)
class MCPPreset:
    name: str
    title: str
    description: str
    command: str
    args: tuple[str, ...] = ()
    requires: str = ""                      # launcher that must be on PATH
    trusted: bool = False
    env_required: tuple[str, ...] = ()
    notes: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def available(self) -> bool:
        return not self.requires or shutil.which(self.requires) is not None

    @property
    def missing_env(self) -> list[str]:
        return [v for v in self.env_required if not os.environ.get(v)]

    def to_config(self, *, directory: str | None = None) -> MCPServerConfig:
        directory = directory or os.getcwd()
        args = [a.replace("{dir}", directory) for a in self.args]
        return MCPServerConfig(name=self.name, command=self.command, args=args,
                               transport="stdio", trusted=self.trusted)


PRESETS: dict[str, MCPPreset] = {p.name: p for p in [
    MCPPreset("fetch", "Web fetch", "Fetch a URL and return it as clean Markdown (research, advisories).",
              "uvx", ("mcp-server-fetch",), requires="uvx", tags=("web", "research")),
    MCPPreset("filesystem", "Filesystem", "Read and write files inside one directory (evidence, notes).",
              "npx", ("-y", "@modelcontextprotocol/server-filesystem", "{dir}"), requires="npx",
              notes="limited to the directory you choose", tags=("files",)),
    MCPPreset("git", "Git", "Inspect a repository: log, diff, show — e.g. secrets in history.",
              "uvx", ("mcp-server-git", "--repository", "{dir}"), requires="uvx",
              notes="the directory must be a git repository", tags=("code",)),
    MCPPreset("browser", "Browser (Playwright)", "Drive a real browser: navigate, read the page, fill forms.",
              "npx", ("-y", "@playwright/mcp@latest", "--headless"), requires="npx",
              notes="downloads a browser on first use", tags=("web",)),
    MCPPreset("thinking", "Sequential thinking", "Structured step-by-step reasoning scratchpad.",
              "npx", ("-y", "@modelcontextprotocol/server-sequential-thinking"), requires="npx",
              trusted=True, tags=("reasoning",)),
    MCPPreset("knowledge-graph", "Knowledge graph", "Persistent entity/relation memory across sessions.",
              "npx", ("-y", "@modelcontextprotocol/server-memory"), requires="npx",
              trusted=True, tags=("memory",)),
    MCPPreset("time", "Time", "Current time and timezone conversion.",
              "uvx", ("mcp-server-time",), requires="uvx", trusted=True, tags=("utility",)),
]}
