"""Report data: verified findings, severity counts and priorities."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .. import __version__
from ..core.findings import Finding, Severity

# severity → priority label + sort rank
_PRIORITY = {
    Severity.CRITICAL: ("P1", 0),
    Severity.HIGH: ("P2", 1),
    Severity.MEDIUM: ("P3", 2),
    Severity.LOW: ("P4", 3),
    Severity.INFO: ("P5", 4),
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def priority_of(finding: Finding) -> str:
    return _PRIORITY.get(finding.severity.rating, ("P5", 4))[0]


@dataclass
class ReportMeta:
    title: str = "AutoPwn AI — Security Assessment"
    run_id: str = ""
    goal: str = ""
    targets: list[str] = field(default_factory=list)
    profile: str = "safe"
    tool: str = "AutoPwn AI"
    version: str = __version__
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


@dataclass
class ReportData:
    meta: ReportMeta
    findings: list[Finding]                       # VERIFIED, severity-sorted
    style: str = "technical"                      # technical | executive
    suspected_count: int = 0                      # for transparency in the summary

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in _SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity.rating.value] += 1
        return out

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def top_severity(self) -> str:
        for s in _SEVERITY_ORDER:
            if self.counts.get(s.value):
                return s.value
        return "none"

    @property
    def by_owasp(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            key = f.owasp or "Uncategorized"
            out[key] = out.get(key, 0) + 1
        return out

    def rows(self) -> list[dict]:
        """Flat, render-ready rows (one per finding) with derived fields."""
        rows = []
        for f in self.findings:
            d = f.to_dict()
            d["priority"] = priority_of(f)
            rows.append(d)
        return rows


def build_report_data(findings: list[Finding], meta: ReportMeta, *,
                      style: str = "technical", suspected_count: int = 0) -> ReportData:
    """Sort verified findings by CVSS (desc) and wrap with metadata."""
    verified = [f for f in findings if f.is_reportable]
    verified.sort(key=lambda f: f.severity.cvss_score, reverse=True)
    return ReportData(meta=meta, findings=verified, style=style,
                      suspected_count=suspected_count)
