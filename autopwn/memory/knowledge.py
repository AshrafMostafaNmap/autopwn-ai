"""Knowledge base: technique lookup over the vulnerability-class table and the
playbooks.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import playbooks
from ..detect.signatures import DOMAIN_CLASSES, VULN_CLASSES, VulnClass


@dataclass
class Technique:
    class_id: str
    title: str
    cvss: float
    owasp: str
    cwe: str
    detection: str
    remediation: str

    @classmethod
    def from_vuln(cls, v: VulnClass) -> Technique:
        return cls(v.id, v.title, v.cvss_score, v.owasp, v.cwe,
                   v.detection_guidance, v.remediation)


class KnowledgeBase:
    def lookup(self, class_id: str) -> Technique | None:
        v = VULN_CLASSES.get(class_id)
        return Technique.from_vuln(v) if v else None

    def techniques_for(self, domain: str) -> list[Technique]:
        return [Technique.from_vuln(VULN_CLASSES[c]) for c in DOMAIN_CLASSES.get(domain, [])
                if c in VULN_CLASSES]

    def search(self, query: str) -> list[Technique]:
        q = (query or "").lower()
        out = []
        for v in VULN_CLASSES.values():
            hay = " ".join([v.id, v.title, v.owasp, v.cwe, v.detection_guidance, v.remediation]).lower()
            if q in hay:
                out.append(Technique.from_vuln(v))
        return out

    def playbook(self, domain: str) -> str:
        return playbooks.load(domain)

    def domains(self) -> list[str]:
        return sorted(DOMAIN_CLASSES)
