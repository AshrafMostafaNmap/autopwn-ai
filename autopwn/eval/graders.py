"""Graders: code-based (vs ground truth), LLM-as-judge (pluggable provider) and a
weighted human-review rubric.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..llm.provider import Message
from .metrics import Metrics, evaluate
from .runner import RunOutcome


@dataclass
class CodeGrade:
    target: str
    metrics: Metrics
    verified: int
    suspected: int

    def to_dict(self) -> dict:
        return {"target": self.target, "verified": self.verified,
                "suspected": self.suspected, **self.metrics.to_dict()}


class CodeGrader:
    """Objective grading against a ground-truth class set."""

    def grade(self, outcome: RunOutcome, ground_truth: set[str] | frozenset[str]) -> CodeGrade:
        metrics = evaluate(outcome.verified_classes, ground_truth)
        return CodeGrade(target=outcome.target, metrics=metrics,
                         verified=len(outcome.verified_findings),
                         suspected=outcome.suspected)


JUDGE_CRITERIA = ("clarity", "depth", "actionability", "purple_framing")

_JUDGE_SYSTEM = (
    "You are a senior security-report reviewer. Score the report from 0-10 on: "
    "clarity, depth, actionability, and purple_framing (does it explain blue-team "
    "detection AND remediation for each finding?). Respond ONLY with JSON: "
    '{"scores": {"clarity": n, "depth": n, "actionability": n, "purple_framing": n}, '
    '"overall": n, "rationale": "..."}.'
)


@dataclass
class JudgeScore:
    overall: float
    scores: dict[str, float] = field(default_factory=dict)
    rationale: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {"overall": self.overall, "scores": self.scores,
                "rationale": self.rationale, "error": self.error}


def _extract_json(text: str) -> dict:
    """Parse a JSON object out of an LLM reply (tolerant of ```json fences)."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    m = re.search(r"\{.*\}", text, re.S)
    return json.loads(m.group(0)) if m else {}


class LLMJudge:
    """Grades report quality with any provider exposing `complete(messages)`."""

    def __init__(self, provider):
        self.provider = provider

    def grade(self, report_text: str) -> JudgeScore:
        messages = [Message.system(_JUDGE_SYSTEM),
                    Message.user("REPORT TO REVIEW:\n\n" + report_text)]
        try:
            resp = self.provider.complete(messages)
            data = _extract_json(getattr(resp, "content", "") or "")
        except Exception as e:
            return JudgeScore(overall=0.0, error=f"{type(e).__name__}: {e}")
        scores = {k: float(v) for k, v in (data.get("scores") or {}).items()}
        overall = data.get("overall")
        if overall is None and scores:
            overall = sum(scores.values()) / len(scores)
        return JudgeScore(overall=float(overall or 0.0), scores=scores,
                          rationale=str(data.get("rationale", "")))


@dataclass(frozen=True)
class RubricCriterion:
    key: str
    title: str
    weight: float
    description: str


DEFAULT_RUBRIC: tuple[RubricCriterion, ...] = (
    RubricCriterion("report_quality", "Report quality", 1.0,
                    "Clear, well-structured, accurate; evidence supports each finding."),
    RubricCriterion("depth", "Scan depth", 1.0,
                    "Breadth of surface covered and thoroughness of probing per class."),
    RubricCriterion("purple_framing", "Purple-team framing", 1.5,
                    "Every finding carries blue-team detection guidance AND remediation."),
    RubricCriterion("verification", "Verification rigor", 1.5,
                    "Findings are confirmed non-destructively; false positives filtered."),
)


@dataclass
class RubricResult:
    scores: dict[str, int]
    weighted_total: float            # 0-100
    max_per_criterion: int
    breakdown: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"scores": self.scores, "weighted_total": round(self.weighted_total, 2),
                "max_per_criterion": self.max_per_criterion, "breakdown": self.breakdown}


class HumanRubric:
    """Weighted human-review scoring over a fixed criteria set."""

    def __init__(self, criteria: tuple[RubricCriterion, ...] = DEFAULT_RUBRIC):
        self.criteria = criteria

    def criteria_keys(self) -> list[str]:
        return [c.key for c in self.criteria]

    def score(self, ratings: dict[str, int], *, max_per_criterion: int = 5) -> RubricResult:
        """`ratings` maps criterion key → 0..max_per_criterion. Missing keys = 0.
        Returns a weighted total normalized to 0-100."""
        total_weight = sum(c.weight for c in self.criteria)
        earned, breakdown = 0.0, {}
        for c in self.criteria:
            r = max(0, min(int(ratings.get(c.key, 0)), max_per_criterion))
            contribution = (r / max_per_criterion) * c.weight
            breakdown[c.key] = round(contribution / total_weight * 100, 2)
            earned += contribution
        weighted_total = earned / total_weight * 100
        clean = {c.key: max(0, min(int(ratings.get(c.key, 0)), max_per_criterion))
                 for c in self.criteria}
        return RubricResult(scores=clean, weighted_total=weighted_total,
                            max_per_criterion=max_per_criterion, breakdown=breakdown)
