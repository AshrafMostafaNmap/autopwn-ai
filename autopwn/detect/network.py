"""Network detectors: cleartext services, and datastores that can be confirmed
unauthenticated with a read-only protocol hello.
"""
from __future__ import annotations

from .model import Candidate
from .signatures import RISKY_SERVICES

# port → (probe bytes, expected signature, service label) for safe confirmation
_PROTO_PROBE = {
    6379: (b"INFO\r\n", "redis_version", "redis"),
    11211: (b"version\r\n", "VERSION", "memcached"),
}


def detect_from_surface(surface) -> list[Candidate]:
    out: list[Candidate] = []
    host = surface.host
    for svc in surface.services:
        info = RISKY_SERVICES.get(svc.port)
        if not info:
            continue
        class_id, name = info
        if class_id == "cleartext_service":
            out.append(Candidate(class_id, host=host, param=str(svc.port), confidence=0.9,
                                 method="direct", note=f"cleartext {name} on :{svc.port}",
                                 evidence_response=svc.banner,
                                 steps=[f"{name} reachable on :{svc.port} (plaintext)"]))
        elif svc.port in _PROTO_PROBE:
            probe, expect, label = _PROTO_PROBE[svc.port]
            out.append(Candidate(class_id, host=host, param=str(svc.port), confidence=0.6,
                                 method="protocol",
                                 vdata={"port": svc.port, "probe": probe, "expect": expect, "service": label},
                                 note=f"{label} on :{svc.port} — verify unauthenticated",
                                 steps=[f"read-only {label} hello on :{svc.port}"]))
        else:
            out.append(Candidate(class_id, host=host, param=str(svc.port), confidence=0.4,
                                 method="manual",
                                 note=f"{name} exposed on :{svc.port} — authorized manual check needed",
                                 evidence_response=svc.banner,
                                 steps=[f"{name} port open; unauth access not auto-proven"]))
    return out
