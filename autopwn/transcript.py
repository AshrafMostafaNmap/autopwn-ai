"""The chat as the operator saw it: an append-only log in the run folder and the
exporters that turn it into a clean Markdown or HTML document.

The model's context is compacted as a session grows; this log is not, so an
export always holds every question and answer. Tool arguments arrive through the
redacting event logger, so secrets appear only as «secret:…» placeholders.
"""
from __future__ import annotations

import html
import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

TRANSCRIPT_FILE = "transcript.jsonl"
FORMATS = {"txt": "Text", "md": "Markdown", "html": "HTML"}

_EVENT_KINDS = {"tool.call", "tool.result", "tool.declined", "agent.message", "agent.error"}


class Transcript:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def add(self, kind: str, **fields) -> None:
        rec = {"ts": round(time.time(), 3), "kind": kind, **fields}
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def on_event(self, rec: dict) -> None:
        """Logger sink: keep the events that belong in the chat."""
        kind = rec.get("kind", "")
        if kind not in _EVENT_KINDS:
            return
        if kind == "tool.call":
            self.add("tool", tool=rec.get("tool"), args=rec.get("args") or {})
        elif kind == "tool.result":
            self.add("tool_done", tool=rec.get("tool"), ok=bool(rec.get("ok", True)), ms=rec.get("ms"))
        elif kind == "tool.declined":
            self.add("declined", tool=rec.get("tool"), reason=rec.get("reason", ""))
        elif kind == "agent.message" and rec.get("text"):
            self.add("narration", text=rec["text"])
        elif kind == "agent.error":
            self.add("error", text=rec.get("error", ""))

    def entries(self) -> list[dict]:
        return read_entries(self.path)


def read_entries(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def entries_from_messages(messages) -> list[dict]:
    """Best effort for sessions saved before the transcript existed."""
    out: list[dict] = []
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else m.role
        content = m.get("content") if isinstance(m, dict) else m.content
        calls = (m.get("tool_calls") if isinstance(m, dict) else m.tool_calls) or []
        if role == "user" and content:
            out.append({"kind": "user", "text": content})
        elif role == "assistant":
            if content and calls:
                out.append({"kind": "narration", "text": content})
            elif content:
                out.append({"kind": "answer", "text": content})
            for c in calls:
                name = c.get("name") if isinstance(c, dict) else c.name
                args = c.get("arguments") if isinstance(c, dict) else c.arguments
                out.append({"kind": "tool", "tool": name, "args": args or {}})
                out.append({"kind": "tool_done", "tool": name, "ok": True})
    return out


# ── structure ────────────────────────────────────────────────────────────────
@dataclass
class ToolUse:
    name: str
    args: dict
    state: str = "ok"               # ok | error | declined | running
    ms: float | None = None
    note: str = ""


@dataclass
class Turn:
    question: str
    asked: float | None = None
    answered: float | None = None
    steps: list[tuple[str, object]] = field(default_factory=list)   # ("narration", str) | ("tool", ToolUse)
    answer: str = ""
    error: str = ""
    findings: list[dict] = field(default_factory=list)
    tokens: int = 0
    cost: float = 0.0

    @property
    def tools(self) -> list[ToolUse]:
        return [s for k, s in self.steps if k == "tool"]


def build_turns(entries: list[dict]) -> list[Turn]:
    turns: list[Turn] = []
    open_tools: list[ToolUse] = []
    for e in entries:
        kind = e.get("kind")
        if kind == "user":
            turns.append(Turn(question=e.get("text", ""), asked=e.get("ts")))
            open_tools = []
            continue
        if not turns:
            turns.append(Turn(question=""))
        t = turns[-1]
        if kind == "narration":
            t.steps.append(("narration", e.get("text", "")))
        elif kind == "tool":
            use = ToolUse(e.get("tool") or "tool", e.get("args") or {}, state="running")
            t.steps.append(("tool", use))
            open_tools.append(use)
        elif kind == "tool_done":
            use = next((u for u in open_tools if u.name == e.get("tool")), None)
            if use is not None:
                use.state = "ok" if e.get("ok", True) else "error"
                use.ms = e.get("ms")
                open_tools.remove(use)
        elif kind == "declined":
            t.steps.append(("tool", ToolUse(e.get("tool") or "tool", {}, "declined", note=e.get("reason", ""))))
        elif kind == "finding":
            t.findings.append(e)
        elif kind == "error":
            t.error = e.get("text", "")
        elif kind == "answer":
            t.answer = e.get("text", "")
            t.answered = e.get("ts")
            t.tokens = e.get("tokens") or 0
            t.cost = e.get("cost") or 0.0
            if e.get("error") and not t.error:
                t.error = e["error"]
    return turns


# ── rendering ────────────────────────────────────────────────────────────────
@dataclass
class ExportMeta:
    title: str = ""
    model: str = ""
    targets: list[str] = field(default_factory=list)
    authorized: bool = False
    run_id: str = ""


def _when(ts: float | None, fmt: str = "%H:%M") -> str:
    return datetime.fromtimestamp(ts).strftime(fmt) if ts else ""


def _args_inline(args: dict, limit: int = 90) -> str:
    parts = []
    for k, v in (args or {}).items():
        val = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
        parts.append(f"{k}={val}")
    text = " ".join(parts)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _duration(ms: float | None) -> str:
    if ms is None:
        return ""
    if ms < 1:
        return "<1ms"
    return f"{ms / 1000:.1f}s" if ms >= 1000 else f"{ms:.0f}ms"


def _demote_headings(text: str, by: int = 3) -> str:
    """Answers sit under '### AutoPwn AI'; their own headings go below it."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            hashes = len(line) - len(line.lstrip("#"))
            if line[hashes:hashes + 1] == " ":
                line = "#" * min(6, hashes + by) + line[hashes:]
        out.append(line)
    return "\n".join(out)


_MARK = {"ok": "✓", "error": "✗", "declined": "⊘", "running": "…"}


def _span(turns: list[Turn]) -> tuple[float | None, float | None]:
    stamps = [x for t in turns for x in (t.asked, t.answered) if x]
    return (min(stamps), max(stamps)) if stamps else (None, None)


def _summary_rows(meta: ExportMeta, turns: list[Turn]) -> list[tuple[str, str]]:
    start, end = _span(turns)
    rows = []
    if start:
        day = _when(start, "%Y-%m-%d %H:%M")
        rows.append(("Date", f"{day} → {_when(end)}" if end and _when(end) != _when(start) else day))
    if meta.model:
        rows.append(("Model", meta.model))
    if meta.targets:
        rows.append(("Scope", ", ".join(meta.targets) + (" (authorized)" if meta.authorized else "")))
    tools = sum(len(t.tools) for t in turns)
    findings = sum(len(t.findings) for t in turns)
    stats = f"{len(turns)} question{'s' if len(turns) != 1 else ''} · {tools} tool call{'s' if tools != 1 else ''}"
    if findings:
        stats += f" · {findings} verified finding{'s' if findings != 1 else ''}"
    rows.append(("Session", stats))
    cost = sum(t.cost for t in turns)
    if cost:
        rows.append(("Cost", f"${cost:.4f}"))
    return rows


def render_markdown(turns: list[Turn], meta: ExportMeta, *, tools: bool = True) -> str:
    out = [f"# {meta.title or 'AutoPwn AI session'}", ""]
    out += ["| | |", "|---|---|"]
    out += [f"| **{k}** | {v.replace('|', '\\|')} |" for k, v in _summary_rows(meta, turns)]
    out.append("")
    for i, t in enumerate(turns, 1):
        out += ["---", "", f"## {i}. You" + (f" · {_when(t.asked)}" if t.asked else ""), ""]
        out += [t.question.strip() or "_(no question)_", ""]
        out += ["### AutoPwn AI" + (f" · {_when(t.answered)}" if t.answered else ""), ""]
        if tools and t.steps:
            for kind, step in t.steps:
                if kind == "narration":
                    out.append(f"> {' '.join(str(step).split())}")
                else:
                    line = f"> {_MARK[step.state]} `{step.name}`"
                    if step.args:
                        line += f" {_args_inline(step.args)}"
                    if step.ms is not None:
                        line += f" · {_duration(step.ms)}"
                    if step.note:
                        line += f" · {step.note}"
                    out.append(line)
                out.append(">")
            out.pop()
            out.append("")
        for f in t.findings:
            out.append(f"**◆ Verified — {f.get('severity', '').upper()}: {f.get('title', '')}** "
                       f"({f.get('target', '')}{', ' + f['method'] if f.get('method') else ''})")
            out.append("")
        if t.answer:
            out += [_demote_headings(t.answer.strip()), ""]
        if t.error:
            out += [f"> **Error:** {t.error}", ""]
        if not t.answer and not t.error:
            out += ["_(no answer — the turn was interrupted)_", ""]
    out += ["---", "", f"_Exported from AutoPwn AI · {_when(time.time(), '%Y-%m-%d %H:%M')}_", ""]
    return "\n".join(out)


_RULE = "─" * 60


def _table_to_text(rows: list[str]) -> list[str]:
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    cells = [r for r in cells if not all(re.fullmatch(r":?-{2,}:?", c) for c in r if c)]
    if not cells:
        return []
    cols = max(len(r) for r in cells)
    cells = [r + [""] * (cols - len(r)) for r in cells]
    widths = [max(len(r[i]) for r in cells) for i in range(cols)]
    out = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in cells]
    if len(out) > 1:
        out.insert(1, "  ".join("-" * w for w in widths))
    return out


def markdown_to_text(text: str) -> str:
    """Readable plain text from the model's Markdown: no **, #, ` or | noise."""
    out: list[str] = []
    lines = (text or "").splitlines()
    i, fenced = 0, False
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            i += 1
            continue
        if fenced:
            out.append("    " + line)
            i += 1
            continue
        if line.lstrip().startswith("|"):
            block = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                block.append(lines[i])
                i += 1
            out += [_inline_text(r) for r in _table_to_text(block)]
            continue
        if m := re.match(r"^(#{1,6})\s+(.*)$", line):
            title = _inline_text(m.group(2)).strip()
            out.append(title)
            if len(m.group(1)) <= 2:
                out.append("-" * max(3, len(title)))
        elif m := re.match(r"^(\s*)[-*+]\s+(.*)$", line):
            out.append(f"{m.group(1)}• {_inline_text(m.group(2))}")
        elif re.fullmatch(r"\s*([-*_])(\s*\1){2,}\s*", line):
            out.append(_RULE)
        elif m := re.match(r"^>\s?(.*)$", line):
            out.append(f"  | {_inline_text(m.group(1))}")
        else:
            out.append(_inline_text(line))
        i += 1
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def _inline_text(s: str) -> str:
    s = re.sub(r"!?\[([^\]]*)\]\(([^)\s]+)[^)]*\)", lambda m: m.group(1) if m.group(1) == m.group(2)
               else f"{m.group(1)} ({m.group(2)})", s)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    s = re.sub(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1", r"\2", s)
    s = re.sub(r"(?<![\w*])\*(?=\S)([^*]+?)(?<=\S)\*(?![\w*])", r"\1", s)
    s = re.sub(r"~~(.+?)~~", r"\1", s)
    return s


def render_text(turns: list[Turn], meta: ExportMeta, *, tools: bool = True) -> str:
    title = meta.title or "AutoPwn AI session"
    out = [title, "=" * min(60, max(10, len(title))), ""]
    rows = _summary_rows(meta, turns)
    pad = max(len(k) for k, _ in rows) + 2
    out += [f"{k + ':':<{pad}}{v}" for k, v in rows]
    for i, t in enumerate(turns, 1):
        out += ["", _RULE, "", f"[{i}] YOU" + (f"  ·  {_when(t.asked)}" if t.asked else ""), ""]
        out += [t.question.strip() or "(no question)", ""]
        out += [f"[{i}] AUTOPWN AI" + (f"  ·  {_when(t.answered)}" if t.answered else ""), ""]
        if tools and t.steps:
            for kind, step in t.steps:
                if kind == "narration":
                    out.append(f"  … {' '.join(str(step).split())}")
                else:
                    extra = "  ".join(x for x in (_args_inline(step.args), _duration(step.ms), step.note) if x)
                    out.append(f"  {_MARK[step.state]} {step.name}" + (f"  {extra}" if extra else ""))
            out.append("")
        for f in t.findings:
            where = f.get("target", "") + (f", {f['method']}" if f.get("method") else "")
            out += [f"  ◆ VERIFIED {f.get('severity', '').upper()}: {f.get('title', '')} ({where})", ""]
        if t.answer:
            out += [markdown_to_text(t.answer), ""]
        if t.error:
            out += [f"Error: {t.error}", ""]
        if not t.answer and not t.error:
            out += ["(no answer — the turn was interrupted)", ""]
    out += [_RULE, f"Exported from AutoPwn AI · {_when(time.time(), '%Y-%m-%d %H:%M')}", ""]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out))


def chat_text(entries: list[dict], meta: ExportMeta, *, tools: bool = False) -> str:
    return render_text(build_turns(entries), meta, tools=tools)


def _md_to_html(text: str) -> str:
    from markdown_it import MarkdownIt
    md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table").enable("strikethrough")
    return md.render(text or "")


_CSS = """
:root{--bg:#0B0D0C;--panel:#131715;--line:#2A312D;--fg:#E6EAE7;--muted:#8A938D;--green:#4ADE80;
--red:#FF6B7A;--orange:#FFA552;--blue:#7AB8FF;color-scheme:dark}
@media (prefers-color-scheme: light){:root{--bg:#FAFBFA;--panel:#F0F3F1;--line:#D5DBD7;--fg:#141816;
--muted:#5C665F;--green:#16A34A;--red:#DC2626;--orange:#C2410C;--blue:#2563EB;color-scheme:light}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"Segoe UI",
"Noto Sans Arabic",sans-serif}
main{max-width:860px;margin:0 auto;padding:40px 20px 64px}
h1{font-size:24px;margin:0 0 16px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;padding:14px 16px;background:var(--panel);
border:1px solid var(--line);border-radius:10px;font-size:13px;margin-bottom:32px}
.meta dt{color:var(--muted)}.meta dd{margin:0}
.turn{margin:0 0 36px}
.who{font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);
display:flex;gap:8px;align-items:baseline;margin-bottom:6px}
.who time{font-weight:400;text-transform:none;letter-spacing:0}
.q{background:var(--panel);border-left:3px solid var(--green);border-radius:6px;padding:10px 14px;
white-space:pre-wrap;margin-bottom:20px}
.steps{border-left:1px solid var(--line);margin:0 0 14px 4px;padding:2px 0 2px 14px;font-size:13px;
color:var(--muted)}
.steps p{margin:4px 0}
.tool{font-family:ui-monospace,"JetBrains Mono",Menlo,monospace;font-size:12.5px;margin:3px 0;
overflow-wrap:anywhere}
.tool .n{color:var(--fg)}.tool .d{opacity:.8}
.ok{color:var(--green)}.error{color:var(--red)}.declined{color:var(--orange)}.running{color:var(--muted)}
.finding{border:1px solid var(--green);border-radius:8px;padding:8px 12px;margin:0 0 14px;font-size:14px}
.finding b{color:var(--green)}
.a{overflow-wrap:anywhere}
.a h1,.a h2,.a h3{font-size:17px;margin:18px 0 8px}
.a code{font-family:ui-monospace,Menlo,monospace;font-size:13px;background:var(--panel);padding:1px 5px;
border-radius:4px}
.a code,.tool,.q code{unicode-bidi:isolate;direction:ltr}
.a pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;
direction:ltr;text-align:left}
.a pre code{background:none;padding:0}
.a table{border-collapse:collapse;display:block;overflow-x:auto}
.a th,.a td{border:1px solid var(--line);padding:4px 10px}
.a blockquote{margin:0;padding-left:12px;border-left:3px solid var(--line);color:var(--muted)}
.a a{color:var(--blue)}
.err{color:var(--red);font-size:14px}
.none{color:var(--muted);font-style:italic}
footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px;margin-top:40px}
@media print{body{background:#fff;color:#000}.q,.meta{background:#f3f3f3}main{padding:0}}
"""


def render_html(turns: list[Turn], meta: ExportMeta, *, tools: bool = True) -> str:
    e = html.escape
    title = meta.title or "AutoPwn AI session"
    body = [f'<h1 dir="auto">{e(title)}</h1>', '<dl class="meta">']
    body += [f"<dt>{e(k)}</dt><dd dir=\"auto\">{e(v)}</dd>" for k, v in _summary_rows(meta, turns)]
    body.append("</dl>")
    for i, t in enumerate(turns, 1):
        body.append(f'<section class="turn" id="q{i}">')
        body.append(f'<div class="who">{i}. You<time>{e(_when(t.asked))}</time></div>')
        body.append(f'<div class="q" dir="auto">{e(t.question.strip()) or "<span class=none>(no question)</span>"}</div>')
        body.append(f'<div class="who">AutoPwn AI<time>{e(_when(t.answered))}</time></div>')
        if tools and t.steps:
            body.append('<div class="steps">')
            for kind, step in t.steps:
                if kind == "narration":
                    body.append(f'<p dir="auto">{e(str(step).strip())}</p>')
                else:
                    extra = " ".join(x for x in (_args_inline(step.args), _duration(step.ms), step.note) if x)
                    body.append(f'<div class="tool"><span class="{step.state}">{_MARK[step.state]}</span> '
                                f'<span class="n">{e(step.name)}</span> <span class="d">{e(extra)}</span></div>')
            body.append("</div>")
        for f in t.findings:
            where = f.get("target", "") + (f" · {f['method']}" if f.get("method") else "")
            body.append(f'<div class="finding"><b>◆ Verified · {e(f.get("severity", "").upper())}</b> '
                        f'{e(f.get("title", ""))} <span class="d">({e(where)})</span></div>')
        if t.answer:
            body.append(f'<div class="a" dir="auto">{_md_to_html(t.answer)}</div>')
        if t.error:
            body.append(f'<p class="err" dir="auto">Error: {e(t.error)}</p>')
        if not t.answer and not t.error:
            body.append('<p class="none">(no answer — the turn was interrupted)</p>')
        body.append("</section>")
    body.append(f"<footer>Exported from AutoPwn AI · {e(_when(time.time(), '%Y-%m-%d %H:%M'))}</footer>")
    return ("<!doctype html>\n<html><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{e(title)}</title><style>{_CSS}</style></head>"
            f"<body><main>{''.join(body)}</main></body></html>\n")


_RENDERERS = {"txt": render_text, "md": render_markdown, "html": render_html}


def export(entries: list[dict], meta: ExportMeta, out_dir: Path, fmt: str = "txt", *,
           tools: bool = True, path: Path | None = None) -> Path:
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r} (use {', '.join(FORMATS)})")
    turns = build_turns(entries)
    text = _RENDERERS[fmt](turns, meta, tools=tools)
    if path is None:
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"chat-{datetime.now():%Y%m%d-%H%M%S}" + ("" if tools else "-clean")
        path = out_dir / f"{stem}.{fmt}"
        n = 2
        while path.exists():
            path = out_dir / f"{stem}-{n}.{fmt}"
            n += 1
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
