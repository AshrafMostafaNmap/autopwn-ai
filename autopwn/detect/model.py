"""Candidate (a suspected issue plus how to verify it) and VerifyResult."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# verification methods the SafeVerifier knows how to run (all non-destructive)
VERIFY_METHODS = ("direct", "reflection", "boolean", "time", "protocol")


@dataclass
class Candidate:
    class_id: str                       # key into signatures.VULN_CLASSES
    host: str = ""
    url: str = ""
    param: str = ""
    confidence: float = 0.5             # detector's prior before verification
    method: str = "direct"              # how to verify
    vdata: dict[str, Any] = field(default_factory=dict)   # params the verifier needs
    note: str = ""
    evidence_request: str = ""
    evidence_response: str = ""
    steps: list[str] = field(default_factory=list)
    # per-finding overrides of the class defaults (template scanners report their own)
    title: str = ""
    cvss: float | None = None
    cwe: str = ""
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    key: str = ""                       # extra dedup discriminator (e.g. template id)

    def dedup_key(self) -> tuple:
        # one issue per (class, host, path, param) — collapses repeat detections
        from urllib.parse import urlparse
        path = urlparse(self.url).path if self.url else ""
        return (self.class_id, self.host, path, self.param, self.key)


@dataclass
class VerifyResult:
    verified: bool
    method: str
    note: str = ""
    request: str = ""
    response: str = ""
    steps: list[str] = field(default_factory=list)
