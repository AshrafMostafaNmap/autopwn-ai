"""What the first-run setup needs to know about this machine: which providers
are already usable, which scanners are installed, and how to install the rest.
UI-free so the wizard, the CLI and the tests share it.
"""
from __future__ import annotations

import os
import shutil
import sys
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

    @property
    def ready_providers(self) -> list[str]:
        return [p.id for p in self.providers if p.found]


_GO = "go install -v {pkg}@latest"
TOOLS: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("nmap", "port and service discovery", {"apt": "sudo apt install nmap", "pacman": "sudo pacman -S nmap",
                                            "dnf": "sudo dnf install nmap", "brew": "brew install nmap"}),
    ("nuclei", "template-based vulnerability checks",
     {"go": _GO.format(pkg="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"), "brew": "brew install nuclei"}),
    ("httpx", "HTTP probing and tech detection",
     {"go": _GO.format(pkg="github.com/projectdiscovery/httpx/cmd/httpx"), "brew": "brew install httpx"}),
    ("subfinder", "passive subdomain discovery",
     {"go": _GO.format(pkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
      "brew": "brew install subfinder"}),
    ("ffuf", "content discovery", {"go": _GO.format(pkg="github.com/ffuf/ffuf/v2"), "brew": "brew install ffuf",
                                   "pacman": "sudo pacman -S ffuf"}),
    ("katana", "crawling", {"go": _GO.format(pkg="github.com/projectdiscovery/katana/cmd/katana")}),
    ("dig", "DNS lookups", {"apt": "sudo apt install dnsutils", "pacman": "sudo pacman -S bind",
                            "dnf": "sudo dnf install bind-utils", "brew": "brew install bind"}),
    ("openssl", "TLS inspection", {"apt": "sudo apt install openssl", "pacman": "sudo pacman -S openssl",
                                   "dnf": "sudo dnf install openssl", "brew": "brew install openssl"}),
)


def package_manager() -> str:
    if sys.platform == "darwin":
        return "brew"
    for name in ("apt", "pacman", "dnf"):
        if shutil.which(name if name != "apt" else "apt-get"):
            return name
    return ""


def install_hint(options: dict[str, str]) -> str:
    pm = package_manager()
    if pm in options:
        return options[pm]
    if "go" in options and shutil.which("go"):
        return options["go"]
    return options.get("go") or next(iter(options.values()), "")


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
    for name, purpose, options in TOOLS:
        path = shutil.which(name)
        out.tools.append(ToolScan(name, purpose, path, "" if path else install_hint(options)))
    try:
        import playwright  # noqa: F401
        browser = True
    except ImportError:
        browser = False
    out.tools.append(ToolScan("playwright", "browser recon of client-side apps",
                              "python package" if browser else None,
                              "" if browser else "reinstall with: install.sh --with-browser"))
    out.launchers = {"uvx": bool(shutil.which("uvx")), "npx": bool(shutil.which("npx"))}
    return out
