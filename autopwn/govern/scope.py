"""Hard scope gate: every native tool that touches a target is checked here
before it runs, whatever the model asked for.

A target is in scope when it matches an in-scope entry and no out-of-scope
entry. Entries may be a host (`app.lab`), a wildcard (`*.lab.local`, which
also matches `lab.local`), an IP, a CIDR (`10.0.5.0/24`) or a URL (its host).
Active tools also need the operator's authorization acknowledgement.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

TARGET_KEYS = ("url", "target", "host", "domain", "hosts", "urls", "targets")


def host_of(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if "://" not in v:
        v = "//" + v
    try:
        host = urlsplit(v).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def matches(host: str, entry: str) -> bool:
    entry = entry.strip().lower()
    if not host or not entry:
        return False
    if "/" in entry and "://" not in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            pass
        else:
            ip = _ip(host)
            return ip is not None and ip in net
    if entry.startswith("*."):
        base = entry[2:].rstrip(".")
        return host == base or host.endswith("." + base)
    return host == host_of(entry)


def targets_in(args: dict, keys: Iterable[str] = TARGET_KEYS) -> list[str]:
    out: list[str] = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            out.extend(x for x in v.replace(",", " ").split() if x)
        elif isinstance(v, list):
            out.extend(str(x) for x in v if str(x).strip())
    return out


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""


class ScopeGuard:
    def __init__(self, in_scope: Callable[[], list[str]], out_of_scope: Callable[[], list[str]],
                 authorized: Callable[[], bool]):
        self._in, self._out, self._auth = in_scope, out_of_scope, authorized

    def check_host(self, value: str) -> ScopeDecision:
        host = host_of(value)
        if not host:
            return ScopeDecision(False, f"'{value}' is not a valid host or URL")
        if any(matches(host, e) for e in self._out()):
            return ScopeDecision(False, f"{host} is explicitly OUT of scope")
        scope = self._in()
        if not scope:
            return ScopeDecision(False, "no targets are in scope yet — the operator must set them (/scope)")
        if not any(matches(host, e) for e in scope):
            return ScopeDecision(False, f"{host} is not in scope (in scope: {', '.join(scope)})")
        return ScopeDecision(True)

    def check(self, args: dict, *, active: bool, keys: Iterable[str] = TARGET_KEYS) -> ScopeDecision:
        targets = targets_in(args, keys)
        if not targets:
            return ScopeDecision(True)
        if active and not self._auth():
            return ScopeDecision(False, "testing is not authorized yet — the operator must confirm "
                                        "authorization for these targets (/scope)")
        for t in targets:
            d = self.check_host(t)
            if not d.allowed:
                return d
        return ScopeDecision(True)

    def filter_hosts(self, hosts: Iterable[str]) -> tuple[list[str], list[str]]:
        """Split discovered hosts into (in scope, out of scope)."""
        inside, outside = [], []
        for h in hosts:
            (inside if self.check_host(h).allowed else outside).append(h)
        return inside, outside
