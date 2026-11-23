"""Per-host attack surface, merged across recon tools and persisted to the store."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.context import RunContext


def _dedup(seq) -> list:
    seen, out = set(), []
    for x in seq:
        key = x if isinstance(x, str) else repr(x)
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Surface:
    host: str
    domain: str = "web"                 # web | network | server | mobile
    scheme: str | None = None
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)          # frameworks/langs/cms
    endpoints: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)  # open ports/services
    headers: dict[str, str] = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def merge(self, other: Surface) -> Surface:
        if other.scheme and not self.scheme:
            self.scheme = other.scheme
        self.title = self.title or other.title
        self.server = self.server or other.server
        self.tech = _dedup([*self.tech, *other.tech])
        self.endpoints = _dedup([*self.endpoints, *other.endpoints])
        self.params = _dedup([*self.params, *other.params])
        self.services = _dedup([*self.services, *other.services])
        self.headers = {**other.headers, **self.headers}
        self.tls = self.tls or other.tls
        self.dns = {**other.dns, **self.dns}
        self.notes = _dedup([*self.notes, *other.notes])
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def summary(self) -> str:
        bits = [f"host={self.host}", f"domain={self.domain}"]
        if self.server:
            bits.append(f"server={self.server}")
        if self.tech:
            bits.append("tech=" + ",".join(self.tech[:6]))
        if self.services:
            bits.append("ports=" + ",".join(str(s.port) for s in self.services[:12]))
        if self.endpoints:
            bits.append(f"endpoints={len(self.endpoints)}")
        return "  ·  ".join(bits)


class TargetModel:
    """Holds every host's surface for a run and persists merges to the store."""

    def __init__(self, ctx: RunContext | None = None):
        self.ctx = ctx
        self._surfaces: dict[str, Surface] = {}

    def observe(self, surface: Surface) -> Surface:
        existing = self._surfaces.get(surface.host)
        if existing is None:
            self._surfaces[surface.host] = surface
            merged = surface
        else:
            merged = existing.merge(surface)
        if self.ctx is not None:
            self.ctx.store.upsert_target(
                self.ctx.run_id, merged.host,
                url=(f"{merged.scheme}://{merged.host}" if merged.scheme else None),
                domain=merged.domain, fingerprint=merged.to_dict(),
            )
        return merged

    def get(self, host: str) -> Surface | None:
        return self._surfaces.get(host)

    def all(self) -> list[Surface]:
        return list(self._surfaces.values())

    def summary(self) -> str:
        if not self._surfaces:
            return "no targets mapped yet"
        return "\n".join(s.summary() for s in self._surfaces.values())
