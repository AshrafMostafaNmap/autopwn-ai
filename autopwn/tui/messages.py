"""Conversation widgets."""
from __future__ import annotations

from rich.markdown import Markdown
from rich.text import Text
from textual.widgets import Static

from ..ui.theme import BLUE, FAINT, GRAY, GREEN, ORANGE, RED, WHITE

SEV_COLOR = {"critical": RED, "high": ORANGE, "medium": "#E0C64F", "low": BLUE, "info": GRAY}
SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class UserMessage(Static):
    def __init__(self, text: str) -> None:
        super().__init__(Text(text, style=WHITE), classes="msg user")


def render_to_text(console, renderable, width: int) -> Text:
    """Render a Rich renderable to styled Text at a fixed width."""
    lines = console.render_lines(renderable, console.options.update(width=width, max_width=width), pad=False)
    out = Text(end="")
    for n, line in enumerate(lines):
        row = Text(end="")
        for seg in line:
            if not seg.control:
                row.append(seg.text, seg.style)
        row.rstrip()
        if n:
            out.append("\n")
        out.append_text(row)
    return out


class _MarkdownMessage(Static):
    """Markdown pre-rendered to styled Text at the widget's width and re-flowed
    on resize, so it can be selected and copied like any other line."""

    def __init__(self, classes: str) -> None:
        self._width = 0
        super().__init__(self._renderable(), classes=classes)

    def _renderable(self):
        raise NotImplementedError

    def on_resize(self) -> None:
        self._reflow()

    def _reflow(self) -> None:
        width = self.content_size.width
        if width <= 0 or width == self._width:
            return
        self._width = width
        self.update(render_to_text(self.app.console, self._renderable(), width))


class AssistantMessage(_MarkdownMessage):
    def __init__(self, text: str, footer: str = "") -> None:
        self.text, self.footer = text, footer
        super().__init__("msg assistant")

    def _renderable(self):
        from rich.console import Group
        parts = [Markdown(self.text or "_(no answer)_")]
        if self.footer:
            parts.append(Text(self.footer, style=FAINT))
        return Group(*parts)


class Narration(_MarkdownMessage):
    """What the model says while it works (alongside tool calls)."""

    def __init__(self, text: str) -> None:
        self.text = text
        super().__init__("msg narration")

    def _renderable(self):
        return Markdown(self.text)


class ToolLine(Static):
    def __init__(self, name: str, detail: str = "") -> None:
        self.tool, self.detail, self.state, self.note = name, detail, "running", ""
        self._frame = 0
        super().__init__(self._render_line(), classes="msg tool")

    def tick(self) -> None:
        if self.state == "running":
            self._frame = (self._frame + 1) % len(SPIN)
            self.update(self._render_line())

    def finish(self, state: str, note: str = "") -> None:
        self.state, self.note = state, note
        self.update(self._render_line())

    def _render_line(self) -> Text:
        glyph, color = {"running": (SPIN[self._frame], BLUE), "ok": ("✓", GREEN),
                        "error": ("✗", RED), "declined": ("⊘", ORANGE),
                        "skipped": ("·", GRAY)}[self.state]
        t = Text()
        t.append(f"{glyph} ", style=color)
        t.append(self.tool, style=f"bold {WHITE}" if self.state == "running" else WHITE)
        if self.detail:
            t.append(f"  {self.detail}", style=GRAY)
        if self.note:
            t.append(f"  · {self.note}", style=color if self.state != "ok" else FAINT)
        return t


class Notice(Static):
    STYLES = {"system": ("·", GRAY), "success": ("✓", GREEN), "error": ("✗", RED),
              "warning": ("!", ORANGE)}

    def __init__(self, text: str, kind: str = "system") -> None:
        glyph, color = self.STYLES[kind]
        line = Text()
        line.append(f"{glyph} ", style=color)
        line.append(text, style=color if kind != "system" else GRAY)
        super().__init__(line, classes=f"msg notice {kind}")


class FindingLine(Static):
    def __init__(self, severity: str, title: str, where: str, method: str = "") -> None:
        color = SEV_COLOR.get(severity, GRAY)
        t = Text()
        t.append("◆ verified ", style=f"bold {GREEN}")
        t.append(f"{severity} ", style=f"bold {color}")
        t.append(title, style=f"bold {WHITE}")
        t.append(f"  {where}", style=GRAY)
        if method:
            t.append(f"  ({method})", style=FAINT)
        super().__init__(t, classes="msg finding")


class Working(Static):
    """Spinner shown at the end of the conversation while the agent works."""

    def __init__(self) -> None:
        self._frame, self.seconds = 0, 0.0
        super().__init__("", classes="msg working")

    def tick(self, seconds: float) -> None:
        self._frame = (self._frame + 1) % len(SPIN)
        self.seconds = seconds
        t = Text()
        t.append(f"{SPIN[self._frame]} ", style=GREEN)
        t.append(f"working  {seconds:.0f}s", style=GRAY)
        t.append("   esc interrupt", style=FAINT)
        self.update(t)
