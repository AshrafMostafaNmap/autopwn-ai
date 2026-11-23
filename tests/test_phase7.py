"""Phase-7 tests: evaluation harness, metrics, graders, regression report.

Everything runs offline against the in-process planted-vulnerability target, so
the benchmark exercises the real detection→safe-verification pipeline end-to-end
with deterministic ground truth. No network, no real LLM.
"""
from __future__ import annotations

import json

import pytest

from autopwn.core.findings import Finding, Severity, SeverityInfo, Target
from autopwn.eval import (
    EXTERNAL_TARGETS,
    CodeGrader,
    HumanRubric,
    JudgeScore,
    LLMJudge,
    PlantedTarget,
    RegressionReport,
    RunOutcome,
    aggregate,
    class_of,
    evaluate,
    external_by_name,
    run_local_benchmark,
    run_web_target,
)
from autopwn.llm.provider import LLMResponse


def test_local_benchmark_finds_all_planted_vulns():
    run = run_local_benchmark()
    outcome = run.outcomes[0]
    assert outcome.error == ""
    # every planted class is confirmed, with no false positives
    assert outcome.verified_classes == PlantedTarget.GROUND_TRUTH
    grade = run.report.grades[0]
    assert grade.metrics.recall == 1.0            # 100% detection
    assert grade.metrics.detection_rate == 1.0    # alias
    assert len(grade.metrics.fp) == 0             # the key metric
    assert len(grade.metrics.fn) == 0
    assert grade.metrics.f1 == 1.0


def test_planted_target_context_manager():
    with PlantedTarget() as pt:
        assert pt.base_url.startswith("http://127.0.0.1:")
        urls = pt.probe_urls()
        assert any(u.endswith("/item?id=1") for u in urls)
        assert any(u.endswith("/search?q=hi") for u in urls)


def test_runner_returns_outcome_on_unreachable():
    # nothing listening on :1 — the harness must not raise
    outcome = run_web_target(["http://127.0.0.1:1/x?id=1"], name="dead")
    assert isinstance(outcome, RunOutcome)
    assert outcome.probes == 1


def test_metrics_precision_recall_f1():
    m = evaluate(detected={"a", "b", "d"}, ground_truth={"a", "b", "c"})
    assert m.tp == frozenset({"a", "b"})
    assert m.fp == frozenset({"d"})               # detected but not real
    assert m.fn == frozenset({"c"})               # real but missed
    assert m.precision == pytest.approx(2 / 3)
    assert m.recall == pytest.approx(2 / 3)
    assert m.f1 == pytest.approx(2 / 3)

def test_metrics_perfect_and_empty():
    assert evaluate({"a"}, {"a"}).f1 == 1.0
    empty = evaluate(set(), set())
    assert empty.precision == 0.0 and empty.recall == 0.0 and empty.f1 == 0.0

def test_aggregate_totals():
    m1 = evaluate({"a", "b"}, {"a", "b"})          # perfect
    m2 = evaluate({"x", "z"}, {"x", "y"})          # 1 fp (z), 1 fn (y)
    agg = aggregate([m1, m2])
    assert agg["targets"] == 2
    assert agg["total_false_positives"] == 1
    assert agg["total_false_negatives"] == 1
    assert agg["macro_recall"] == pytest.approx((1.0 + 0.5) / 2)


def test_code_grader_identifies_fp_fn():
    outcome = RunOutcome(target="t", verified_classes=frozenset({"sqli", "xss_reflected", "open_redirect"}),
                         verified_findings=[], suspected=2)
    grade = CodeGrader().grade(outcome, {"sqli", "xss_reflected", "sensitive_file"})
    assert grade.metrics.fp == frozenset({"open_redirect"})
    assert grade.metrics.fn == frozenset({"sensitive_file"})
    assert grade.suspected == 2
    d = grade.to_dict()
    assert d["false_positives"] == 1 and d["false_negatives"] == 1


def test_class_of_maps_title_to_id():
    f = Finding(id="x", title="SQL Injection",
                target=Target(host="h"), severity=SeverityInfo(cvss_score=9.8, rating=Severity.CRITICAL))
    assert class_of(f) == "sqli"
    f2 = Finding(id="y", title="Totally Unknown Thing",
                 target=Target(host="h"), severity=SeverityInfo(cvss_score=1.0))
    assert class_of(f2) is None


class _StubProvider:
    def __init__(self, content): self._content = content
    def complete(self, messages, tools=None): return LLMResponse(content=self._content)

class _RaisingProvider:
    def complete(self, messages, tools=None): raise RuntimeError("no model")


def test_llm_judge_parses_scores():
    content = json.dumps({"scores": {"clarity": 8, "depth": 7, "actionability": 9, "purple_framing": 10},
                          "overall": 8.5, "rationale": "solid report"})
    score = LLMJudge(_StubProvider(content)).grade("the report text")
    assert isinstance(score, JudgeScore)
    assert score.overall == 8.5
    assert score.scores["purple_framing"] == 10.0
    assert "solid" in score.rationale

def test_llm_judge_handles_fenced_json():
    content = "```json\n" + json.dumps({"scores": {"clarity": 6}, "overall": 6}) + "\n```"
    score = LLMJudge(_StubProvider(content)).grade("report")
    assert score.overall == 6.0

def test_llm_judge_infers_overall_from_scores():
    content = json.dumps({"scores": {"clarity": 4, "depth": 6}})   # no overall
    score = LLMJudge(_StubProvider(content)).grade("report")
    assert score.overall == pytest.approx(5.0)

def test_llm_judge_handles_provider_error():
    score = LLMJudge(_RaisingProvider()).grade("report")
    assert score.overall == 0.0 and score.error


def test_human_rubric_full_and_zero():
    rubric = HumanRubric()
    keys = rubric.criteria_keys()
    full = rubric.score({k: 5 for k in keys})
    assert full.weighted_total == pytest.approx(100.0)
    zero = rubric.score({k: 0 for k in keys})
    assert zero.weighted_total == 0.0

def test_human_rubric_weighted():
    # report_quality(1.0)=5, depth(1.0)=0, purple_framing(1.5)=5, verification(1.5)=0
    # earned = 1.0 + 0 + 1.5 + 0 = 2.5 ; total weight = 5.0 → 50%
    rubric = HumanRubric()
    r = rubric.score({"report_quality": 5, "depth": 0, "purple_framing": 5, "verification": 0})
    assert r.weighted_total == pytest.approx(50.0)

def test_human_rubric_clamps_out_of_range():
    r = HumanRubric().score({k: 99 for k in HumanRubric().criteria_keys()})
    assert r.weighted_total == pytest.approx(100.0)   # clamped to max


def test_regression_report_json_and_markdown():
    run = run_local_benchmark(tool_version="0.1.0")
    report = run.report
    doc = json.loads(report.to_json())                # valid JSON
    assert doc["schema"] == "autopwn.eval/1"
    assert doc["summary"]["macro_detection_rate"] == 1.0
    assert doc["summary"]["total_false_positives"] == 0
    assert len(doc["targets"]) == 1
    md = report.to_markdown()
    assert "Benchmark Regression Report" in md
    assert "Detection rate" in md
    assert "100%" in md

def test_regression_report_shows_fp_fn_rows():
    from autopwn.eval import CodeGrade
    rep = RegressionReport()
    m = evaluate({"sqli", "open_redirect"}, {"sqli", "sensitive_file"})
    rep.add(CodeGrade(target="demo", metrics=m, verified=2, suspected=1))
    md = rep.to_markdown()
    assert "open_redirect" in md                      # FP listed
    assert "sensitive_file" in md                      # FN listed


def test_external_targets_catalogue():
    assert EXTERNAL_TARGETS, "external catalogue should load from benchmarks/"
    juice = external_by_name("OWASP Juice Shop")
    assert juice is not None
    assert juice.requires_instance is True
    assert "sqli" in juice.ground_truth
    # mobile + network targets are catalogued too
    names = {t.name for t in EXTERNAL_TARGETS}
    assert "Metasploitable2" in names and "DIVA (Damn Insecure and Vulnerable App)" in names
