"""Run the real detection → verification pipeline against a benchmark target."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from functools import lru_cache

from ..core.findings import Finding
from ..detect import FindingsPipeline, SafeVerifier
from ..detect import web as dweb
from ..detect.signatures import VULN_CLASSES


@lru_cache(maxsize=1)
def _title_to_class() -> dict[str, str]:
    """Reverse map a finding's title back to its VULN_CLASSES id (titles unique)."""
    return {vc.title: cid for cid, vc in VULN_CLASSES.items()}


def class_of(finding: Finding) -> str | None:
    return _title_to_class().get(finding.title)


@dataclass
class RunOutcome:
    target: str
    verified_classes: frozenset[str]
    verified_findings: list[Finding] = field(default_factory=list)
    suspected: int = 0
    duration_s: float = 0.0
    probes: int = 0
    error: str = ""

    @property
    def depth(self) -> int:
        """A simple depth proxy: distinct (class, location) verified findings."""
        return len({(class_of(f), f.target.url or f.target.host) for f in self.verified_findings})


def run_web_target(probe_urls: list[str], *, name: str = "web",
                   timeout: float = 15.0) -> RunOutcome:
    """Run detection + safe verification against a set of web probe URLs."""
    pipe = FindingsPipeline()
    verifier = SafeVerifier(timeout=timeout)
    started = time.time()
    try:
        for url in probe_urls:
            pipe.add_all(dweb.detect_all(url))
        pipe.verify_all(verifier)
    except Exception as e:                      # a benchmark never crashes the harness
        verifier.close()
        return RunOutcome(target=name, verified_classes=frozenset(),
                          duration_s=round(time.time() - started, 3),
                          probes=len(probe_urls), error=f"{type(e).__name__}: {e}")
    finally:
        verifier.close()

    verified = pipe.reportable()
    classes = frozenset(c for f in verified if (c := class_of(f)) is not None)
    return RunOutcome(
        target=name,
        verified_classes=classes,
        verified_findings=verified,
        suspected=len(pipe.suspected()),
        duration_s=round(time.time() - started, 3),
        probes=len(probe_urls),
    )
