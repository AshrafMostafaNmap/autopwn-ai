"""Coverage-complete signal: every applicable class checked on every target and
no new verified finding for a few rounds (or the round budget is spent).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .signatures import DOMAIN_CLASSES


@dataclass
class CoverageTracker:
    plateau: int = 3                 # rounds without a new verified finding → plateau
    max_rounds: int = 50             # backstop
    checked: set[tuple] = field(default_factory=set)      # (domain, host, class_id)
    expected: set[tuple] = field(default_factory=set)
    rounds: int = 0
    verified_count: int = 0
    _stale_rounds: int = 0

    def expect_target(self, host: str, domain: str) -> None:
        for class_id in DOMAIN_CLASSES.get(domain, []):
            self.expected.add((domain, host, class_id))

    def mark_checked(self, host: str, domain: str, class_id: str) -> None:
        self.checked.add((domain, host, class_id))

    def mark_checked_many(self, host: str, domain: str, class_ids=None) -> None:
        for cid in (class_ids if class_ids is not None else DOMAIN_CLASSES.get(domain, [])):
            self.mark_checked(host, domain, cid)

    def record_round(self, newly_verified: int) -> None:
        self.rounds += 1
        self.verified_count += newly_verified
        if newly_verified > 0:
            self._stale_rounds = 0
        else:
            self._stale_rounds += 1

    @property
    def checklist_remaining(self) -> set[tuple]:
        return self.expected - self.checked

    @property
    def checklist_done(self) -> bool:
        return bool(self.expected) and not self.checklist_remaining

    @property
    def plateaued(self) -> bool:
        return self._stale_rounds >= self.plateau

    @property
    def budget_hit(self) -> bool:
        return self.rounds >= self.max_rounds

    def is_complete(self) -> bool:
        if self.budget_hit:
            return True
        return self.checklist_done and self.plateaued

    def status(self) -> dict:
        return {
            "rounds": self.rounds,
            "checklist": f"{len(self.checked & self.expected)}/{len(self.expected)}",
            "remaining": sorted(f"{d}:{h}:{c}" for d, h, c in self.checklist_remaining)[:20],
            "verified": self.verified_count,
            "stale_rounds": self._stale_rounds,
            "plateaued": self.plateaued,
            "complete": self.is_complete(),
        }
