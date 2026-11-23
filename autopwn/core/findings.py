"""The Finding record shared by detection, storage and reports."""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Status(str, enum.Enum):
    SUSPECTED = "suspected"   # detected, not yet safely verified
    VERIFIED = "verified"     # confirmed via non-destructive proof (L1)


@dataclass
class Target:
    host: str
    url: str | None = None
    param: str | None = None


@dataclass
class SeverityInfo:
    cvss_score: float
    cvss_vector: str = ""
    rating: Severity = Severity.INFO

    def __post_init__(self):
        if isinstance(self.rating, str):
            self.rating = Severity(self.rating)
        # keep rating consistent with score if not explicitly meaningful
        if self.rating == Severity.INFO and self.cvss_score > 0:
            self.rating = Severity.from_cvss(self.cvss_score)


@dataclass
class Evidence:
    request: str = ""
    response: str = ""
    screenshot: str = ""
    steps: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    target: Target
    severity: SeverityInfo
    owasp: str = ""
    cwe: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    safe_poc: str = ""                 # non-destructive proof description
    detection_guidance: str = ""       # 🔵 how the blue team detects it
    remediation: str = ""              # 🔵 how to fix it
    confidence: float = 0.0
    status: Status = Status.SUSPECTED

    def __post_init__(self):
        if isinstance(self.status, str):
            self.status = Status(self.status)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"]["rating"] = self.severity.rating.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        sev = d.get("severity") or {}
        return cls(
            id=d["id"], title=d["title"], target=Target(**(d.get("target") or {"host": ""})),
            severity=SeverityInfo(cvss_score=sev.get("cvss_score", 0.0),
                                  cvss_vector=sev.get("cvss_vector", ""),
                                  rating=sev.get("rating", "info")),
            owasp=d.get("owasp", ""), cwe=d.get("cwe", ""),
            evidence=Evidence(**(d.get("evidence") or {})), safe_poc=d.get("safe_poc", ""),
            detection_guidance=d.get("detection_guidance", ""), remediation=d.get("remediation", ""),
            confidence=d.get("confidence", 0.0), status=d.get("status", "suspected"))

    @property
    def is_reportable(self) -> bool:
        """Only verified findings are reported — this is our FP filter."""
        return self.status == Status.VERIFIED
