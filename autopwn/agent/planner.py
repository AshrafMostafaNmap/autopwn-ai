"""Methodology planner: forward-only phases recon → planning → detection →
verify → report, and the methodology chosen per domain.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Phase(enum.Enum):
    RECON = "recon"
    PLANNING = "planning"
    DETECTION = "detection"
    VERIFY = "verify"
    REPORT = "report"
    DONE = "done"

    @property
    def order(self) -> int:
        return _ORDER[self]


_ORDER = {p: i for i, p in enumerate(Phase)}
_NEXT = {p: list(Phase)[i + 1] for i, p in enumerate(Phase) if i + 1 < len(Phase)}

_PHASE_INTENT = {
    Phase.RECON:     "Map the target deeply: surface, tech/stack, services, endpoints, auth. Breadth first, no conclusions yet.",
    Phase.PLANNING:  "From recon, choose which vulnerability classes to pursue and in what order; pick the methodology/playbooks.",
    Phase.DETECTION: "Probe for the chosen classes. Produce *suspected* findings with evidence — do not claim them confirmed yet.",
    Phase.VERIFY:    "Confirm suspected findings non-destructively only (boolean/time/reflection/differential). This is the false-positive filter.",
    Phase.REPORT:    "Assemble verified findings into the defender-framed report (CVSS, detection guidance, remediation).",
    Phase.DONE:      "Engagement complete.",
}


class Methodology(enum.Enum):
    OWASP_WSTG = "OWASP WSTG"       # web
    PTES = "PTES"                   # overall / network / infra
    MOBILE = "OWASP MASVS/MASTG"    # android


def methodology_for(domain: str | None) -> Methodology:
    d = (domain or "").lower()
    if d in ("web", "website", "webapp"):
        return Methodology.OWASP_WSTG
    if d in ("mobile", "android"):
        return Methodology.MOBILE
    return Methodology.PTES          # network / server / unknown → PTES umbrella


@dataclass
class Planner:
    phase: Phase = Phase.RECON
    domain: str | None = None
    methodology: Methodology = field(default=Methodology.PTES)
    history: list[Phase] = field(default_factory=lambda: [Phase.RECON])

    def __post_init__(self) -> None:
        self.methodology = methodology_for(self.domain)

    @property
    def intent(self) -> str:
        return _PHASE_INTENT[self.phase]

    @property
    def is_done(self) -> bool:
        return self.phase is Phase.DONE

    def can_advance(self) -> bool:
        return self.phase in _NEXT

    def advance(self) -> Phase:
        """Move to the next phase. Raises if already DONE."""
        if self.phase not in _NEXT:
            raise ValueError("already at the final phase")
        self.phase = _NEXT[self.phase]
        self.history.append(self.phase)
        return self.phase

    def goto(self, target: Phase) -> Phase:
        """Advance directly to a later phase (forward-only). Skipping is allowed
        (e.g. recon → detection) but going backwards is rejected."""
        if target.order < self.phase.order:
            raise ValueError(f"cannot go back: {self.phase.value} → {target.value} (forward-only)")
        self.phase = target
        self.history.append(target)
        return target

    def status_line(self) -> str:
        done = " → ".join(p.value for p in self.history)
        return f"phase: {self.phase.value}  ·  methodology: {self.methodology.value}  ·  path: {done}"
