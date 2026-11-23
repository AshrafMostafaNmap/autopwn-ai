"""Layered configuration: defaults → config.toml → app settings → environment.
Secrets are referenced by environment-variable name, never stored.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

# First match wins. An explicit path (CLI / env) overrides all of these.
_CONFIG_NAMES = ("config.toml", "autopwn.toml")
_ENV_CONFIG = "AUTOPWN_CONFIG"


class ConfigError(Exception):
    """Raised when config is malformed or a required secret is missing."""


@dataclass
class LLMConfig:
    # Provider-agnostic model id in LiteLLM form, e.g. "anthropic/claude-sonnet-5-5",
    # "openai/gpt-4o", "gemini/gemini-1.5-pro", "ollama/llama3.1".
    model: str = "anthropic/claude-sonnet-5-5"
    provider: str = "anthropic"            # informational / grouping only
    api_key_env: str = "ANTHROPIC_API_KEY"  # NAME of the env var, not the key
    api_base: str | None = None            # for local models / gateways (Ollama, vLLM, OpenRouter)
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: int = 120
    retries: int = 2                       # transient-error retries (429/5xx/network)
    # Tool-calling is mandatory for the agent; the startup gate enforces this.
    require_tool_calling: bool = True
    # A key supplied at runtime from the local credential store (the TUI's
    # "connect provider"). Never serialized, never shown in repr/logs.
    api_key_value: str | None = field(default=None, repr=False, compare=False)

    def api_key(self) -> str | None:
        """Resolve the real key — runtime credential first, then the environment.
        Stays local, never logged."""
        if self.api_key_value:
            return self.api_key_value
        if not self.api_key_env:
            return None
        return os.environ.get(self.api_key_env)

    @property
    def requires_key(self) -> bool:
        """Local runtimes (Ollama, LM Studio, vLLM…) need no key; hosted
        providers do — even when routed through a custom api_base gateway."""
        # The model id is the source of truth ("ollama/llama3.1" → ollama); the
        # `provider` field only matters for a bare id with no prefix.
        from .llm.catalog import provider_requires_key
        prov = self.model.split("/", 1)[0] if "/" in self.model else self.provider
        return provider_requires_key(prov)


@dataclass
class ProfileConfig:
    """A safety/behavior profile. `destructive` is always False; the curated
    toolset is what actually guarantees it."""
    name: str = "safe"
    destructive: bool = False
    max_steps: int = 40
    rate_limit_rps: float = 5.0


@dataclass
class ScopeConfig:
    """Soft scope: declared targets the agent is authorized to assess. Enforced
    at run start via the scope prompt + ack. Empty = declare interactively."""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    authorized_ack: bool = False           # the operator's authorization acknowledgement


@dataclass
class RunConfig:
    root: str = "runs"                     # directory that holds per-run folders
    profile: str = "safe"                  # which [profiles.*] to activate


@dataclass
class LoggingConfig:
    level: str = "info"                    # debug | info | warning | error
    json: bool = True                      # write events.jsonl (structured)
    console: bool = True                   # mirror to the rich console


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    run: RunConfig = field(default_factory=RunConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    profiles: dict[str, ProfileConfig] = field(default_factory=dict)
    # MCP servers declared in config.toml as [[mcp.servers]] tables
    # (name, command, args, env, trusted, enabled). Merged with the app's own list.
    mcp_servers: list[dict] = field(default_factory=list)
    # where this config came from (None = built-in defaults only)
    source: Path | None = None

    def active_profile(self) -> ProfileConfig:
        prof = self.profiles.get(self.run.profile)
        if prof is None:
            # fall back to a safe default rather than failing a run
            return ProfileConfig(name=self.run.profile)
        return prof


def _default_profiles() -> dict[str, ProfileConfig]:
    return {
        "safe": ProfileConfig("safe", destructive=False, max_steps=40, rate_limit_rps=5.0),
        "standard": ProfileConfig("standard", destructive=False, max_steps=80, rate_limit_rps=10.0),
    }


def _coerce(cls, data: dict[str, Any], *, _where: str):
    """Build a dataclass from a dict, ignoring unknown keys with a clear error
    on type mismatch. Keeps config forgiving but typed."""
    known = {f.name for f in cls.__dataclass_fields__.values()}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{_where}] unknown keys: {', '.join(sorted(unknown))}")
    return cls(**{k: v for k, v in data.items() if k in known})


def find_config(explicit: str | os.PathLike | None = None) -> Path | None:
    """Resolve which config file to use. Precedence: explicit arg → $AUTOPWN_CONFIG
    → ./config.toml (or autopwn.toml) walking up to the filesystem root."""
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            raise ConfigError(f"config file not found: {p}")
        return p
    env = os.environ.get(_ENV_CONFIG)
    if env:
        p = Path(env).expanduser()
        if not p.is_file():
            raise ConfigError(f"$ {_ENV_CONFIG} points to a missing file: {p}")
        return p
    here = Path.cwd()
    for folder in (here, *here.parents):
        for name in _CONFIG_NAMES:
            cand = folder / name
            if cand.is_file():
                return cand
    return None


def load_config(explicit: str | os.PathLike | None = None) -> Config:
    """Load config from disk (or pure defaults if no file is found)."""
    path = find_config(explicit)
    if path is None:
        cfg = Config(profiles=_default_profiles())
        return cfg

    with path.open("rb") as fh:
        raw = tomllib.load(fh)

    cfg = Config(
        llm=_coerce(LLMConfig, raw.get("llm", {}), _where="llm"),
        run=_coerce(RunConfig, raw.get("run", {}), _where="run"),
        scope=_coerce(ScopeConfig, raw.get("scope", {}), _where="scope"),
        logging=_coerce(LoggingConfig, raw.get("logging", {}), _where="logging"),
        profiles={},
        source=path,
    )

    servers = (raw.get("mcp") or {}).get("servers", [])
    for i, srv in enumerate(servers):
        if not isinstance(srv, dict) or not srv.get("name") or not (srv.get("command") or srv.get("url")):
            raise ConfigError(f"[mcp.servers][{i}] needs 'name' and either 'command' or 'url'")
    cfg.mcp_servers = [dict(s) for s in servers]

    profiles = raw.get("profiles", {})
    for name, pdata in profiles.items():
        pdata = {**pdata, "name": pdata.get("name", name)}
        cfg.profiles[name] = _coerce(ProfileConfig, pdata, _where=f"profiles.{name}")
    if not cfg.profiles:
        cfg.profiles = _default_profiles()

    # environment overrides (handy for CI / containers / quick swaps)
    apply_env_overrides(cfg)
    return cfg


def apply_env_overrides(cfg: Config) -> None:
    """A few env knobs so the container can run without editing the file."""
    if v := os.environ.get("AUTOPWN_MODEL"):
        cfg.llm.model = v
    if v := os.environ.get("AUTOPWN_API_BASE"):
        cfg.llm.api_base = v
    if v := os.environ.get("AUTOPWN_PROFILE"):
        cfg.run.profile = v
    if v := os.environ.get("AUTOPWN_RUN_ROOT"):
        cfg.run.root = v
    if v := os.environ.get("AUTOPWN_LOG_LEVEL"):
        cfg.logging.level = v


def with_overrides(cfg: Config, **llm_kwargs) -> Config:
    """Return a copy of the config with LLM fields overridden (used by the CLI
    when the user passes --model, etc. at run start)."""
    llm = replace(cfg.llm, **{k: v for k, v in llm_kwargs.items() if v is not None})
    return replace(cfg, llm=llm)
