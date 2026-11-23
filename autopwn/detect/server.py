"""Server detectors: weak TLS and outdated software banners."""
from __future__ import annotations

import re

from .model import Candidate

_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+-]*)/(\d+\.[\d.]+)")


def detect_from_surface(surface) -> list[Candidate]:
    out: list[Candidate] = []
    host = surface.host
    tls = surface.tls or {}

    # weak / invalid TLS — the handshake + cert are the proof
    tls_notes = [n for n in tls.get("notes", []) if n]
    if tls_notes:
        out.append(Candidate("weak_tls", host=host, param=str(tls.get("port", 443)),
                             confidence=0.9, method="direct",
                             note="; ".join(tls_notes),
                             evidence_response=f"{tls.get('protocol')} · {tls.get('cipher')} · issuer={tls.get('issuer','')}",
                             steps=["TLS handshake", "certificate/protocol flags observed"]))

    # outdated software by version banner (advisory → suspected)
    if surface.server:
        m = _VERSION_RE.search(surface.server)
        if m:
            out.append(Candidate("outdated_software", host=host, confidence=0.3,
                                 method="manual",
                                 note=f"server banner: {surface.server}",
                                 evidence_response=surface.server,
                                 steps=["read Server banner", "map version to CVE feed (manual)"]))
    return out
