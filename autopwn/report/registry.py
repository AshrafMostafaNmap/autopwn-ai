"""The report tool for the agent."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent.tools import ToolRegistry, ToolResult
from .builder import ReportBuilder
from .model import ReportMeta


def register_report_tools(registry: ToolRegistry, *, ctx=None, pipeline) -> None:

    def _meta() -> ReportMeta:
        if ctx is not None:
            return ReportMeta(run_id=ctx.run_id, goal=ctx.goal, targets=list(ctx.targets),
                              profile=ctx.config.run.profile)
        return ReportMeta()

    def generate_report(args: dict[str, Any], _ctx) -> ToolResult:
        formats = args.get("formats") or ["json", "md", "html", "pdf"]
        if isinstance(formats, str):
            formats = [f.strip() for f in formats.replace(",", " ").split() if f.strip()]
        style = args.get("style", "technical")
        verified = pipeline.reportable()
        if not verified:
            return ToolResult.fail("no verified findings to report — verify findings first",
                                   suspected=len(pipeline.suspected()))

        out_dir = (ctx.run_dir / "reports") if ctx is not None else Path("reports")
        builder = ReportBuilder(out_dir)
        results = builder.build(verified, _meta(), formats=formats, style=style,
                                suspected_count=len(pipeline.suspected()))

        written, errors = [], []
        for fmt, r in results.items():
            if r.get("ok"):
                p = r["path"]
                rel = str(Path(p).relative_to(ctx.run_dir)) if ctx is not None else p
                written.append({"format": fmt, "path": rel, "bytes": r.get("bytes", 0)})
                if ctx is not None:
                    ctx.store.add_artifact(ctx.run_id, kind="report", path=rel, meta={"format": fmt, "style": style})
            else:
                errors.append({"format": fmt, "error": r["error"], "skipped": r.get("skipped", False)})

        summary = f"report ({style}): {len(verified)} verified finding(s) → " + \
                  ", ".join(w["format"] for w in written)
        if errors:
            summary += "  · skipped: " + ", ".join(e["format"] for e in errors)
        return ToolResult(content=summary, data={"written": written, "errors": errors,
                                                 "style": style, "findings": len(verified)})

    registry.add(
        "generate_report",
        "Generate the assessment report from VERIFIED findings in the chosen "
        "formats (json, md, html, pdf, sarif) and style (technical or executive). Every "
        "finding renders CVSS, evidence, detection guidance, and remediation.",
        generate_report, phase="report",
        parameters={
            "type": "object",
            "properties": {
                "formats": {"type": "array", "items": {"type": "string",
                            "enum": ["json", "md", "html", "pdf", "sarif"]}},
                "style": {"type": "string", "enum": ["technical", "executive"]},
            },
        },
    )
