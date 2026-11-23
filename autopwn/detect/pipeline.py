"""Findings pipeline: dedup, CVSS from the class table, suspected → verified.
Only verified findings are reportable.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..core.findings import Evidence, Finding, Severity, SeverityInfo, Status, Target
from .model import Candidate, VerifyResult
from .signatures import VULN_CLASSES


def _finding_id(candidate: Candidate) -> str:
    base = candidate.dedup_key()[:4]          # ids stay stable for findings without a key
    raw = "|".join(str(x) for x in base) + (f"|{candidate.key}" if candidate.key else "")
    return "AP-" + hashlib.sha1(raw.encode()).hexdigest()[:8].upper()


def make_finding(candidate: Candidate) -> Finding:
    """Build a SUSPECTED finding from a candidate, scored off the class table."""
    vc = VULN_CLASSES[candidate.class_id]
    score = candidate.cvss if candidate.cvss is not None else vc.cvss_score
    vector = vc.cvss_vector if candidate.cvss is None else ""
    return Finding(
        id=_finding_id(candidate),
        title=candidate.title or vc.title,
        target=Target(host=candidate.host, url=candidate.url or None,
                      param=candidate.param or None),
        severity=SeverityInfo(cvss_score=score, cvss_vector=vector,
                              rating=Severity.from_cvss(score)),
        owasp=vc.owasp, cwe=candidate.cwe or vc.cwe,
        evidence=Evidence(request=candidate.evidence_request,
                          response=candidate.evidence_response,
                          steps=list(candidate.steps)),
        safe_poc=candidate.note,
        detection_guidance=vc.detection_guidance,
        remediation=candidate.remediation or vc.remediation,
        confidence=candidate.confidence,
        status=Status.SUSPECTED,
    )


@dataclass
class _Item:
    finding: Finding
    candidate: Candidate


class FindingsPipeline:
    """Dedups candidates into findings and runs verification to promote them."""

    def __init__(self, ctx=None):
        self.ctx = ctx
        self._items: dict[tuple, _Item] = {}        # dedup_key -> item

    def add(self, candidate: Candidate) -> Finding:
        if candidate.class_id not in VULN_CLASSES:
            raise KeyError(f"unknown vuln class: {candidate.class_id}")
        key = candidate.dedup_key()
        existing = self._items.get(key)
        if existing is not None:
            # keep the higher-confidence evidence; don't duplicate
            if candidate.confidence > existing.candidate.confidence:
                existing.candidate = candidate
                existing.finding.confidence = candidate.confidence
            return existing.finding
        finding = make_finding(candidate)
        self._items[key] = _Item(finding, candidate)
        self._persist(finding)
        return finding

    def add_all(self, candidates: list[Candidate]) -> list[Finding]:
        return [self.add(c) for c in candidates]

    def verify_all(self, verifier) -> list[Finding]:
        """Run the safe verifier over every still-suspected item. Returns the
        findings newly promoted to VERIFIED."""
        promoted: list[Finding] = []
        for item in self._items.values():
            if item.finding.status is Status.VERIFIED:
                continue
            res: VerifyResult = verifier.verify(item.candidate)
            if self.ctx is not None:
                self.ctx.logger.info("verify", finding=item.finding.id,
                                     cls=item.candidate.class_id, method=res.method,
                                     verified=res.verified, note=res.note)
            if res.verified:
                self._promote(item, res)
                promoted.append(item.finding)
        return promoted

    def _promote(self, item: _Item, res: VerifyResult) -> None:
        f = item.finding
        f.status = Status.VERIFIED
        f.confidence = max(f.confidence, 0.95)
        if res.request:
            f.evidence.request = res.request
        if res.response:
            f.evidence.response = res.response
        if res.steps:
            f.evidence.steps = list(res.steps)
        f.safe_poc = res.note or f.safe_poc
        self._persist(f)

    def all(self) -> list[Finding]:
        return [i.finding for i in self._items.values()]

    def suspected(self) -> list[Finding]:
        return [f for f in self.all() if f.status is Status.SUSPECTED]

    def reportable(self) -> list[Finding]:
        """Only verified findings are reportable (the FP filter), severity-sorted."""
        verified = [f for f in self.all() if f.is_reportable]
        return sorted(verified, key=lambda f: f.severity.cvss_score, reverse=True)

    def restore(self, findings: list[Finding]) -> None:
        """Reload findings saved by an earlier part of this run. Verified ones need
        nothing more; suspected ones can only be re-verified by detecting them again."""
        by_title = {vc.title: vc.id for vc in VULN_CLASSES.values()}
        for f in findings:
            class_id = by_title.get(f.title)
            if class_id is None:
                continue
            cand = Candidate(class_id, host=f.target.host, url=f.target.url or "",
                             param=f.target.param or "", confidence=f.confidence,
                             method="manual", note=f.safe_poc)
            self._items[cand.dedup_key()] = _Item(f, cand)

    def _persist(self, finding: Finding) -> None:
        if self.ctx is not None:
            self.ctx.store.save_finding(self.ctx.run_id, finding)
