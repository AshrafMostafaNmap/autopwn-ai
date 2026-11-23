"""What the first-run setup needs to know about this machine: which providers
are already usable, which scanners are installed, and how to install the rest.
UI-free so the wizard, the CLI and the tests share it.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field

from .llm.catalog import PROVIDERS, endpoint_reachable, is_local_endpoint

TERMS_VERSION = "1"

TERMS = (
    "AutoPwn AI performs real network actions. Use it only against systems you own or are "
    "explicitly authorized in writing to test, within the agreed scope. It verifies findings "
    "non-destructively and never exploits, exfiltrates or disrupts — you remain responsible for "
    "how and where it is used."
)


@dataclass
class ProviderScan:
    id: str
    label: str
    found: str = ""            # how it is already usable ("" = not yet)
    needs_key: bool = True
    needs_endpoint: bool = False
    note: str = ""


@dataclass
class ToolScan:
    name: str
    purpose: str
    path: str | None
    install: str = ""


@dataclass
class Scan:
    providers: list[ProviderScan] = field(default_factory=list)
    tools: list[ToolScan] = field(default_factory=list)
    launchers: dict[str, bool] = field(default_factory=dict)     # uvx / npx for MCP presets
    system: str = ""                                             # "CachyOS · x86_64 · pacman · sudo"

    @property
    def ready_providers(self) -> list[str]:
        return [p.id for p in self.providers if p.found]


def package_manager() -> str:
    from .system import detect_manager
    return detect_manager()


def _provider_found(info, stored: set[str], api_bases: dict[str, str]) -> str:
    if info.id in stored:
        return "key saved"
    if info.env_var and os.environ.get(info.env_var) and info.id != "openai_compatible":
        return f"${info.env_var} found"
    if info.credentials_env:
        hit = next((v for v in info.credentials_env if os.environ.get(v)), None)
        if hit:
            return f"${hit} found"
        if os.path.isfile(os.path.expanduser(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials"))):
            return "~/.aws/credentials found"
        return ""
    base = api_bases.get(info.id) or info.api_base
    if not info.requires_key and base and is_local_endpoint(base) and endpoint_reachable(base, timeout=0.8):
        return f"running at {base}"
    return ""


def scan(stored: set[str] | None = None, api_bases: dict[str, str] | None = None) -> Scan:
    stored, api_bases = stored or set(), api_bases or {}
    out = Scan()
    for info in PROVIDERS.values():
        out.providers.append(ProviderScan(
            info.id, info.label, _provider_found(info, stored, api_bases),
            needs_key=info.requires_key, needs_endpoint=info.needs_api_base,
            note=info.note))
    from .recon import installer
    for row in installer.status():
        hint = "" if row["installed"] else (f"autopwnai tools install {row['name']}" if row["downloadable"]
                                            else row["system_hint"])
        out.tools.append(ToolScan(row["name"], row["purpose"], row["path"], hint))
    out.launchers = {"uvx": bool(shutil.which("uvx")), "npx": bool(shutil.which("npx"))}
    from .system import detect
    out.system = detect().summary()
    return out
