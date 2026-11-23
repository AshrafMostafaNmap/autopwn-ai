"""Install the external scanners the agent drives, without root.

ProjectDiscovery tools, ffuf and gau are downloaded from their official GitHub
releases, verified against the release's SHA-256 checksums and unpacked into
AutoPwn's own bin directory. System packages (nmap, masscan, dig, openssl) are
left to the operating system's package manager — the command is printed.
"""
from __future__ import annotations

import hashlib
import io
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from ..settings import data_dir


def bin_dir() -> Path:
    return data_dir() / "bin"


@dataclass(frozen=True)
class Scanner:
    name: str
    purpose: str
    repo: str = ""                 # GitHub owner/name for release downloads (else a system package)

    @property
    def downloadable(self) -> bool:
        return bool(self.repo)


SCANNERS: dict[str, Scanner] = {s.name: s for s in [
    Scanner("nuclei", "template-based vulnerability checks", "projectdiscovery/nuclei"),
    Scanner("httpx", "HTTP probing, titles, tech detection", "projectdiscovery/httpx"),
    Scanner("subfinder", "passive subdomain discovery", "projectdiscovery/subfinder"),
    Scanner("katana", "web crawling", "projectdiscovery/katana"),
    Scanner("dnsx", "DNS resolution and records", "projectdiscovery/dnsx"),
    Scanner("naabu", "fast port discovery", "projectdiscovery/naabu"),
    Scanner("ffuf", "content discovery", "ffuf/ffuf"),
    Scanner("gau", "known URLs from public archives", "lc/gau"),
    Scanner("nmap", "service and version detection"),
    Scanner("dig", "DNS lookups"),
    Scanner("openssl", "TLS inspection"),
]}


def platform_tags() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Accepted spellings of this OS and CPU in release asset names."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    osn = ("linux",) if system == "linux" else ("darwin", "macos") if system == "darwin" else (system,)
    arch = {"x86_64": ("amd64", "x86_64"), "amd64": ("amd64", "x86_64"),
            "aarch64": ("arm64", "aarch64"), "arm64": ("arm64", "aarch64")}.get(machine, (machine,))
    return osn, arch


def pick_asset(names: list[str], tool: str) -> tuple[str | None, str | None]:
    """(archive, checksums) asset names for this platform."""
    osn, arch = platform_tags()
    archive = None
    for n in names:
        low = n.lower()
        if not low.endswith((".zip", ".tar.gz")) or "musl" in low:
            continue
        if any(f"_{o}_" in low or f"-{o}-" in low for o in osn) and \
                any(low.endswith(f"_{a}.zip") or low.endswith(f"_{a}.tar.gz") or f"_{a}." in low for a in arch):
            archive = n
            break
    sums = next((n for n in names if "checksums" in n.lower() and n.lower().endswith(".txt")), None)
    return archive, sums


def _http(token: str | None = None) -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "autopwn-ai-installer"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(timeout=60.0, follow_redirects=True, headers=headers)


def resolve(name: str) -> str | None:
    """Path of an installed scanner: AutoPwn's bin dir first, then Go's, then PATH."""
    for d in (bin_dir(), Path.home() / "go" / "bin"):
        p = d / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    found = shutil.which(name)
    if found and name == "httpx" and not _is_projectdiscovery_httpx(found):
        return None                    # the Python httpx CLI has the same name
    return found


def _is_projectdiscovery_httpx(path: str) -> bool:
    try:
        out = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return "projectdiscovery" in (out.stdout + out.stderr).lower()


def version_of(name: str) -> str:
    path = resolve(name)
    if not path:
        return ""
    flag = {"nmap": "--version", "openssl": "version", "dig": "-v", "ffuf": "-V", "gau": "--version"}.get(name,
                                                                                                      "-version")
    try:
        out = subprocess.run([path, flag], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", out.stdout + out.stderr)
    return m.group(1) if m else ""


def status() -> list[dict]:
    rows = []
    for s in SCANNERS.values():
        path = resolve(s.name)
        rows.append({"name": s.name, "purpose": s.purpose, "path": path, "installed": bool(path),
                     "downloadable": s.downloadable, "system_hint": system_hint(s)})
    return rows


def system_hint(s: Scanner) -> str:
    from ..system import install_hint
    return install_hint(s.name)


def missing_packages() -> list[str]:
    """System-package tools (nmap, dig, openssl) that are not installed."""
    return [s.name for s in SCANNERS.values() if not s.downloadable and not resolve(s.name)]


class InstallError(RuntimeError):
    pass


def install(name: str, *, token: str | None = None, client: httpx.Client | None = None,
            progress: Callable[[str], None] | None = None) -> Path:
    """Download, verify and unpack one scanner. Returns the installed path."""
    s = SCANNERS.get(name)
    if s is None:
        raise InstallError(f"unknown scanner '{name}'")
    if not s.downloadable:
        raise InstallError(f"{name} is a system package — install it with: {system_hint(s)}")
    say = progress or (lambda _m: None)
    own = client is None
    client = client or _http(token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    try:
        rel = client.get(f"https://api.github.com/repos/{s.repo}/releases/latest")
        if rel.status_code != 200:
            raise InstallError(f"could not read {s.repo} releases (HTTP {rel.status_code})")
        data = rel.json()
        assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
        archive, sums = pick_asset(list(assets), name)
        if archive is None:
            osn, arch = platform_tags()
            raise InstallError(f"no {name} build for {osn[0]}/{arch[0]} in {data.get('tag_name', 'latest')}")
        say(f"{name} {data.get('tag_name', '')}: downloading {archive}")
        blob = client.get(assets[archive]).content
        if sums is None:
            raise InstallError(f"{name}: release has no checksums file — refusing to install unverified")
        expected = _checksum_for(client.get(assets[sums]).text, archive)
        actual = hashlib.sha256(blob).hexdigest()
        if expected != actual:
            raise InstallError(f"{name}: checksum mismatch — download rejected")
        say(f"{name}: checksum verified")
        target = bin_dir() / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_extract(blob, archive, name))
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return target
    except httpx.HTTPError as e:
        raise InstallError(f"{name}: download failed ({type(e).__name__})") from e
    finally:
        if own:
            client.close()


def _checksum_for(text: str, archive: str) -> str | None:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == archive:
            return parts[0].lower()
    return None


def _extract(blob: bytes, archive: str, name: str) -> bytes:
    """Only the tool's own binary is read out of the archive — nothing is written
    from member paths, so a hostile archive cannot place files elsewhere."""
    if archive.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            member = next((m for m in z.namelist() if Path(m).name == name), None)
            if member is None:
                raise InstallError(f"{name} not found inside {archive}")
            return z.read(member)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        member = next((m for m in t.getmembers() if m.isfile() and Path(m.name).name == name), None)
        if member is None:
            raise InstallError(f"{name} not found inside {archive}")
        fh = t.extractfile(member)
        if fh is None:
            raise InstallError(f"{name}: unreadable archive member")
        return fh.read()


TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"


def templates_dir() -> Path:
    """Where nuclei reads its templates (its own config, else ~/nuclei-templates)."""
    import json
    cfg = Path.home() / ".config" / "nuclei" / ".templates-config.json"
    try:
        d = json.loads(cfg.read_text()).get("nuclei-templates-directory")
        if d:
            return Path(d)
    except (OSError, ValueError):
        pass
    return Path.home() / "nuclei-templates"


def template_count() -> int:
    d = templates_dir()
    return sum(1 for _ in d.rglob("*.yaml")) if d.is_dir() else 0


def update_nuclei_templates(progress: Callable[[str], None] | None = None) -> bool:
    """nuclei's own updater first; on slow links its short download timeout fails,
    so fall back to a shallow clone of the official templates repository. Success
    means templates are actually on disk, not just a zero exit code."""
    say = progress or (lambda _m: None)
    path = resolve("nuclei")
    if not path:
        return False
    say("nuclei: updating templates")
    try:
        subprocess.run([path, "-update-templates", "-silent"], capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError):
        pass
    if template_count() > 0:
        return True
    git = shutil.which("git")
    if not git:
        return False
    target = templates_dir()
    say(f"nuclei: downloading templates with git into {target}")
    if target.exists() and not any(target.iterdir()):
        target.rmdir()
    try:
        if (target / ".git").is_dir():
            subprocess.run([git, "-C", str(target), "pull", "--depth", "1", "-q"], timeout=1800, check=False)
        else:
            subprocess.run([git, "clone", "--depth", "1", "-q", TEMPLATES_REPO, str(target)],
                           timeout=1800, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return template_count() > 0
