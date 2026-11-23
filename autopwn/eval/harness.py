"""Benchmark entry points used by `autopwnai eval`."""
from __future__ import annotations

from dataclasses import dataclass

from .graders import CodeGrader
from .report import RegressionReport
from .runner import RunOutcome, run_web_target
from .targets import BenchmarkTarget, PlantedTarget, external_by_name


@dataclass
class BenchmarkRun:
    report: RegressionReport
    outcomes: list[RunOutcome]


def run_local_benchmark(*, tool_version: str = "0.1.0") -> BenchmarkRun:
    """Run the in-process planted target end-to-end. Fully offline."""
    grader = CodeGrader()
    report = RegressionReport(tool_version=tool_version)
    outcomes: list[RunOutcome] = []
    with PlantedTarget() as pt:
        t = pt.target()
        outcome = run_web_target(pt.probe_urls(), name=t.name)
        report.add(grader.grade(outcome, t.ground_truth))
        outcomes.append(outcome)
    return BenchmarkRun(report=report, outcomes=outcomes)


def run_external_target(target: BenchmarkTarget | str, *,
                        tool_version: str = "0.1.0") -> BenchmarkRun:
    """Run a catalogued external web target (requires a reachable instance)."""
    if isinstance(target, str):
        resolved = external_by_name(target)
        if resolved is None:
            raise ValueError(f"unknown external target: {target}")
        target = resolved
    if target.domain != "web":
        raise NotImplementedError(
            f"external '{target.name}' is a {target.domain} target — run it via the "
            f"recon/detect tools against its host/APK; offline harness covers web.")
    grader = CodeGrader()
    report = RegressionReport(tool_version=tool_version)
    outcome = run_web_target(target.probe_urls(), name=target.name)
    report.add(grader.grade(outcome, target.ground_truth))
    return BenchmarkRun(report=report, outcomes=[outcome])
