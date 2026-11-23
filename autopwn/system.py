"""What machine AutoPwn is running on, and how to install system packages on it.

Used by `autopwnai tools install`, `autopwnai doctor`, the setup wizard and the
installer script, so every one of them reports and installs the same way.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# package manager → (install command prefix, needs root)
MANAGERS: dict[str, tuple[list[str], bool]] = {
    "apt": (["apt-get", "install", "-y"], True),
    "dnf": (["dnf", "install", "-y"], True),
    "yum": (["yum", "install", "-y"], True),
    "pacman": (["pacman", "-S", "--needed", "--noconfirm"], True),
    "zypper": (["zypper", "--non-interactive", "install"], True),
    "apk": (["apk", "add"], True),
    "brew": (["brew", "install"], False),
}
_BINARY = {"apt": "apt-get"}

# tool → package name per manager (tools AutoPwn drives that are not downloadable releases)
PACKAGES: dict[str, dict[str, str]] = {
    "nmap": {"apt": "nmap", "dnf": "nmap", "yum": "nmap", "pacman": "nmap", "zypper": "nmap",
             "apk": "nmap", "brew": "nmap"},
    "dig": {"apt": "dnsutils", "dnf": "bind-utils", "yum": "bind-utils", "pacman": "bind",
            "zypper": "bind-utils", "apk": "bind-tools", "brew": "bind"},
    "openssl": {"apt": "openssl", "dnf": "openssl", "yum": "openssl", "pacman": "openssl",
                "zypper": "openssl", "apk": "openssl", "brew": "openssl"},
    "git": {"apt": "git", "dnf": "git", "yum": "git", "pacman": "git", "zypper": "git",
            "apk": "git", "brew": "git"},
}


@dataclass
class SystemInfo:
    os: str                       # linux | darwin | windows | …
    distro: str = ""              # "Arch Linux", "Ubuntu 24.04", "macOS 15.2"
    distro_id: str = ""
    arch: str = ""
    manager: str = ""             # apt | dnf | yum | pacman | zypper | apk | brew | ""
    root: bool = False
    sudo: bool = False
    container: bool = False
    wsl: bool = False
    available: dict[str, bool] = field(default_factory=dict)   # go, git, docker, uvx, npx

    @property
    def can_install_packages(self) -> bool:
        if not self.manager:
            return False
        needs_root = MANAGERS[self.manager][1]
        return not needs_root or self.root or self.sudo

    def summary(self) -> str:
        bits = [self.distro or self.os, self.arch]
        if self.manager:
            bits.append(f"{self.manager}")
        if self.container:
            bits.append("container")
        if self.wsl:
            bits.append("WSL")
        bits.append("root" if self.root else ("sudo" if self.sudo else "no sudo"))
        return " · ".join(b for b in bits if b)


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return out


def detect_manager(os_name: str | None = None, which=shutil.which) -> str:
    if (os_name or sys.platform) == "darwin":
        return "brew" if which("brew") else ""
    for name in ("apt", "dnf", "pacman", "zypper", "apk", "yum"):
        if which(_BINARY.get(name, name)):
            return name
    return ""


def detect(os_release: Path = Path("/etc/os-release")) -> SystemInfo:
    system = platform.system().lower()
    info = SystemInfo(os=system, arch=platform.machine())
    if system == "linux":
        rel = _os_release(os_release)
        info.distro = rel.get("PRETTY_NAME") or rel.get("NAME", "Linux")
        info.distro_id = rel.get("ID", "")
        try:
            info.wsl = "microsoft" in Path("/proc/version").read_text().lower()
        except OSError:
            pass
        info.container = Path("/.dockerenv").exists() or bool(os.environ.get("container"))
    elif system == "darwin":
        info.distro = f"macOS {platform.mac_ver()[0]}".strip()
        info.distro_id = "macos"
    info.manager = detect_manager("darwin" if system == "darwin" else "linux")
    info.root = hasattr(os, "geteuid") and os.geteuid() == 0
    info.sudo = bool(shutil.which("sudo")) and not info.root
    info.available = {t: bool(shutil.which(t)) for t in ("go", "git", "docker", "uvx", "npx", "curl")}
    return info


def install_command(tools: list[str], info: SystemInfo) -> list[str] | None:
    """The command that installs these tools with the system's package manager."""
    if not info.manager:
        return None
    pkgs = sorted({PACKAGES[t][info.manager] for t in tools if t in PACKAGES and info.manager in PACKAGES[t]})
    if not pkgs:
        return None
    base, needs_root = MANAGERS[info.manager]
    cmd = [*base, *pkgs]
    if needs_root and not info.root:
        cmd = ["sudo", *cmd]
    return cmd


def install_hint(tool: str, info: SystemInfo | None = None) -> str:
    info = info or detect()
    cmd = install_command([tool], info)
    return " ".join(cmd) if cmd else f"install '{tool}' with your system's package manager"


def install_packages(tools: list[str], info: SystemInfo | None = None, *, update_index: bool = True) -> int:
    """Run the package manager in the foreground so sudo can ask for the password
    on the operator's own terminal. Returns its exit code."""
    info = info or detect()
    cmd = install_command(tools, info)
    if cmd is None:
        return 1
    if update_index and info.manager in ("apt", "apk"):
        refresh = ["apt-get", "update"] if info.manager == "apt" else ["apk", "update"]
        subprocess.run((["sudo"] if not info.root else []) + refresh, check=False)
    return subprocess.run(cmd, check=False).returncode
