"""Write reports to disk in the requested formats."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core.findings import Finding
from . import renderers
from .model import ReportMeta, build_report_data

_EXT = {"json": "json", "markdown": "md", "md": "md", "html": "html", "pdf": "pdf", "sarif": "sarif"}


@dataclass
class ReportBuilder:
    out_dir: Path

    def __post_init__(self):
        self.out_dir = Path(self.out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def build(
        self,
        findings: list[Finding],
        meta: ReportMeta,
        *,
        formats: list[str] | tuple[str, ...] = ("json", "md", "html", "pdf"),
        style: str = "technical",
        suspected_count: int = 0,
        basename: str | None = None,
    ) -> dict[str, dict]:
        data = build_report_data(findings, meta, style=style, suspected_count=suspected_count)
        base = basename or f"report-{meta.run_id or 'autopwn'}-{style}"
        results: dict[str, dict] = {}

        for fmt in formats:
            fmt = fmt.lower()
            ext = _EXT.get(fmt)
            if ext is None:
                results[fmt] = {"ok": False, "error": f"unknown format '{fmt}'"}
                continue
            path = self.out_dir / f"{base}.{ext}"
            try:
                if fmt == "json":
                    path.write_text(renderers.to_json(data), encoding="utf-8")
                elif fmt in ("md", "markdown"):
                    path.write_text(renderers.to_markdown(data), encoding="utf-8")
                elif fmt == "html":
                    path.write_text(renderers.to_html(data), encoding="utf-8")
                elif fmt == "pdf":
                    path.write_bytes(renderers.to_pdf(data))
                elif fmt == "sarif":
                    path.write_text(renderers.to_sarif(data), encoding="utf-8")
                results[fmt] = {"ok": True, "path": str(path), "bytes": path.stat().st_size}
            except renderers.PDFUnavailable as e:
                results[fmt] = {"ok": False, "error": str(e), "skipped": True}
            except Exception as e:
                results[fmt] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        return results
