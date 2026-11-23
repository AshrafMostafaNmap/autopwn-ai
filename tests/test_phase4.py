"""Phase-4 tests: reporting (JSON / Markdown / HTML / PDF, two styles).

DoD: every finding field (incl. the two purple fields) renders; JSON is valid;
the style switch works; only verified findings appear.
"""
from __future__ import annotations

import json

import pytest

from autopwn.core.findings import Evidence, Finding, Severity, SeverityInfo, Status, Target
from autopwn.report import ReportBuilder, ReportMeta, build_report_data, priority_of, renderers


def _verified(fid="AP-1", cls="SQL Injection", score=9.8, status=Status.VERIFIED):
    return Finding(
        id=fid, title=cls, target=Target(host="app.lab", url="http://app.lab/item", param="id"),
        severity=SeverityInfo(cvss_score=score, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                              rating=Severity.from_cvss(score)),
        owasp="A03:2021-Injection", cwe="CWE-89",
        evidence=Evidence(request="GET /item?id=1'", response="SQL syntax error near ''",
                          steps=["append quote", "boolean differential confirmed"]),
        safe_poc="boolean differential confirmed (true~1.00, false~0.40)",
        detection_guidance="Alert on DB errors and tautologies in parameters.",
        remediation="Use parameterized queries; least-privilege DB accounts.",
        confidence=0.95, status=status,
    )


def _meta():
    return ReportMeta(run_id="20260101-000000-abcdef", goal="assess app.lab",
                      targets=["app.lab"], profile="safe")


# ── data model ────────────────────────────────────────────────────────────────
def test_only_verified_included_and_sorted():
    findings = [_verified("AP-1", "SQL Injection", 9.8),
                _verified("AP-2", "Reflected XSS", 6.1),
                _verified("AP-3", "Suspected thing", 7.5, status=Status.SUSPECTED)]
    data = build_report_data(findings, _meta(), suspected_count=1)
    assert data.total == 2                               # suspected excluded
    assert data.findings[0].severity.cvss_score == 9.8   # sorted desc
    assert data.counts["critical"] == 1 and data.counts["medium"] == 1
    assert data.top_severity == "critical"

def test_priority_mapping():
    assert priority_of(_verified(score=9.8)) == "P1"
    assert priority_of(_verified(score=6.1)) == "P3"


# ── JSON ──────────────────────────────────────────────────────────────────────
def test_json_valid_and_complete():
    data = build_report_data([_verified()], _meta(), suspected_count=2)
    doc = json.loads(renderers.to_json(data))            # must parse
    assert doc["schema"] == "autopwn.report/1"
    assert doc["summary"]["total"] == 1
    assert doc["summary"]["suspected_not_reported"] == 2
    f = doc["findings"][0]
    # every key field present, including the two purple fields
    for key in ("id", "title", "severity", "owasp", "cwe", "evidence",
                "safe_poc", "detection_guidance", "remediation", "status", "priority"):
        assert key in f, f"missing {key}"
    assert f["detection_guidance"] and f["remediation"]
    assert f["severity"]["cvss_score"] == 9.8


# ── Markdown ──────────────────────────────────────────────────────────────────
def test_markdown_renders_purple_fields():
    md = renderers.to_markdown(build_report_data([_verified()], _meta()))
    assert "# AutoPwn AI" in md
    assert "SQL Injection" in md
    assert "CWE-89" in md
    assert "Detection (blue team)" in md and "Remediation" in md
    assert "CVSS 9.8" in md


# ── HTML + style switch ───────────────────────────────────────────────────────
def test_html_technical_has_evidence():
    html = renderers.to_html(build_report_data([_verified()], _meta(), style="technical"))
    assert "<html" in html.lower()
    assert "SQL syntax error" in html                    # evidence present
    assert "🔵" in html and "Remediation" in html

def test_html_executive_hides_raw_evidence():
    html = renderers.to_html(build_report_data([_verified()], _meta(), style="executive"))
    assert "SQL syntax error" not in html                # raw evidence dropped
    assert "Remediation" in html                         # fix still shown
    assert "Confirmed non-destructively" in html

def test_html_escapes_content():
    f = _verified()
    f.title = "<script>alert(1)</script>"
    html = renderers.to_html(build_report_data([f], _meta()))
    assert "<script>alert(1)</script>" not in html       # autoescaped
    assert "&lt;script&gt;" in html


# ── builder writes files ──────────────────────────────────────────────────────
def test_builder_writes_selected_formats(tmp_path):
    builder = ReportBuilder(tmp_path / "reports")
    res = builder.build([_verified()], _meta(), formats=["json", "md", "html"], style="technical")
    assert all(res[f]["ok"] for f in ("json", "md", "html"))
    for f in ("json", "md", "html"):
        from pathlib import Path
        assert Path(res[f]["path"]).is_file()

@pytest.mark.skipif(not renderers.pdf_available(), reason="weasyprint not available")
def test_builder_pdf(tmp_path):
    builder = ReportBuilder(tmp_path / "reports")
    res = builder.build([_verified()], _meta(), formats=["pdf"])
    assert res["pdf"]["ok"]
    from pathlib import Path
    pdf = Path(res["pdf"]["path"]).read_bytes()
    assert pdf[:4] == b"%PDF"                             # real PDF


# ── agent tool ────────────────────────────────────────────────────────────────
def test_generate_report_tool(tmp_path):
    from autopwn.agent.tools import ToolRegistry
    from autopwn.detect import FindingsPipeline
    from autopwn.llm.provider import ToolCall
    from autopwn.report import register_report_tools

    pipe = FindingsPipeline()
    # inject a verified finding directly
    from autopwn.detect.model import Candidate
    f = pipe.add(Candidate("sqli", host="app.lab", url="http://app.lab/x", param="id"))
    f.status = Status.VERIFIED

    reg = ToolRegistry()
    register_report_tools(reg, ctx=None, pipeline=pipe)
    # ctx=None → writes under ./reports; redirect cwd to tmp
    import os
    cwd = os.getcwd(); os.chdir(tmp_path)
    try:
        res = reg.dispatch(ToolCall("c", "generate_report", {"formats": ["json", "md"], "style": "executive"}))
    finally:
        os.chdir(cwd)
    assert res.ok
    assert res.data["findings"] == 1
    assert {w["format"] for w in res.data["written"]} == {"json", "md"}
