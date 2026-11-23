"""Service discovery: nmap -sV when installed, otherwise a TCP connect scan."""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from .runner import available, run
from .target_model import Service, Surface

# A compact, high-signal default port set (safe to probe). The agent can request
# a wider set explicitly.
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
             8080, 8443, 9200, 11211, 27017]

_PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


@dataclass
class _Open:
    port: int
    banner: str = ""


def _grab_banner(sock: socket.socket) -> str:
    """Read a volunteered banner (SSH/SMTP/FTP/etc.) without sending anything."""
    try:
        sock.settimeout(1.5)
        data = sock.recv(256)
        return data.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def tcp_connect_scan(host: str, ports: list[int] | None = None,
                     timeout: float = 1.0) -> list[Service]:
    """Non-destructive connect scan. Returns open services with any banner."""
    ports = ports or TOP_PORTS
    services: list[Service] = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, port)) == 0:
                banner = _grab_banner(s)
                services.append(Service(port=port, name=_PORT_NAMES.get(port, ""),
                                        banner=banner[:200]))
        except (socket.gaierror, OSError):
            pass
        finally:
            s.close()
    return services


_NMAP_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$", re.M)


def nmap_scan(host: str, *, top: int = 50, vault=None, timeout: float = 240.0):
    """Version-detection scan with safe flags. Returns (services, raw_stdout)."""
    args = ["-sV", "-Pn", "-T3", "--top-ports", str(top), host]
    res = run("nmap", args, timeout=timeout, vault=vault)
    if not res.ok:
        return None, res
    services: list[Service] = []
    for m in _NMAP_LINE.finditer(res.stdout):
        port, proto, state, name, ver = m.groups()
        if state != "open":
            continue
        services.append(Service(port=int(port), proto=proto, name=name, version=(ver or "").strip()))
    return services, res


def scan_host(host: str, *, ports: list[int] | None = None, vault=None,
              prefer_nmap: bool = True) -> tuple[Surface, dict]:
    """Discover services on one host, nmap-first with a connect-scan fallback."""
    surface = Surface(host=host, domain="network")
    raw: dict = {"host": host}

    if prefer_nmap and available("nmap"):
        services, res = nmap_scan(host, vault=vault)
        if services is not None:
            surface.services = services
            raw["tool"] = "nmap"
            raw["stdout"] = res.stdout[:8000]
            surface.notes.append(f"nmap: {len(services)} open service(s)")
            return surface, raw

    if not ports:
        from .scanners import port_discovery_naabu
        found = port_discovery_naabu(host, vault=vault)
        if found:
            surface.services = [Service(port=s.port, name=_PORT_NAMES.get(s.port, "")) for s in found]
            raw["tool"] = "naabu"
            surface.notes.append(f"naabu: {len(found)} open port(s)")
            return surface, raw

    services = tcp_connect_scan(host, ports)
    surface.services = services
    raw["tool"] = "tcp-connect"
    surface.notes.append(f"connect-scan: {len(services)} open port(s)")
    if any(s.banner for s in services):
        raw["banners"] = {s.port: s.banner for s in services if s.banner}
    return surface, raw
