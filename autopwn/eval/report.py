"""Benchmark regression report (JSON + Markdown)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .graders import CodeGrade
from .metrics import aggregate


@dataclass
class RegressionReport:
    grades: list[CodeGrade] = field(default_factory=list)
    tool_version: str = "0.1.0"
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))

    def add(self, grade: CodeGrade) -> None:
        self.grades.append(grade)

    def summary(self) -> dict:
        return aggregate([g.metrics for g in self.grades])

    def to_dict(self) -> dict:
        return {
            "schema": "autopwn.eval/1",
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "summary": self.summary(),
            "targets": [g.to_dict() for g in self.grades],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)

    def to_markdown(self) -> str:
        s = self.summary()
        L: list[str] = []
        L.append("# AutoPwn AI — Benchmark Regression Report")
        L.append("")
        L.append(f"_Generated {self.generated_at} · tool {self.tool_version}_")
        L.append("")
        L.append("## Summary")
        L.append("")
        L.append(f"- **Targets:** {s['targets']}")
        L.append(f"- **Detection rate (macro recall):** {s['macro_detection_rate']:.0%}")
        L.append(f"- **Precision (macro):** {s['macro_precision']:.0%}")
        L.append(f"- **F1 (macro):** {s['macro_f1']:.0%}")
        L.append(f"- **False positives (total):** {s['total_false_positives']}")
        L.append(f"- **False negatives (total):** {s['total_false_negatives']}")
        L.append("")
        L.append("## Per-target")
        L.append("")
        L.append("| Target | Detect rate | Precision | F1 | FP | FN | Verified |")
        L.append("|---|---|---|---|---|---|---|")
        for g in self.grades:
            m = g.metrics
            L.append(f"| {g.target} | {m.recall:.0%} | {m.precision:.0%} | {m.f1:.0%} | "
                     f"{len(m.fp)} | {len(m.fn)} | {g.verified} |")
            if m.fp:
                L.append(f"|  ↳ false positives | `{', '.join(sorted(m.fp))}` | | | | | |")
            if m.fn:
                L.append(f"|  ↳ missed (FN) | `{', '.join(sorted(m.fn))}` | | | | | |")
        L.append("")
        return "\n".join(L)
