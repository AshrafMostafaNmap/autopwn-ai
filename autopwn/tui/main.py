"""The main screen: home view, conversation, prompt with `/` completion, status bar."""
from __future__ import annotations

import time
from collections import deque

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from ..ui.banner import VERSION, logo_mark
from ..ui.theme import BLUE, FAINT, GRAY, GREEN, ORANGE, RED, WHITE
from . import commands
from .messages import AssistantMessage, FindingLine, Narration, Notice, ToolLine, UserMessage, Working

HOME_HINTS = ("new", "model", "provider", "scope", "mcp", "copy", "export", "help")
FADE = 0.18
SCROLL = 0.15


def _short(args) -> str:
    if not isinstance(args, dict) or not args:
        return ""
    text = "  ".join(f"{k}={v}" for k, v in args.items())
    return text if len(text) <= 80 else text[:79] + "…"


def _compact_num(n: int) -> str:
    return f"{n / 1000:.1f}K" if n >= 1000 else str(n)


class MainScreen(Screen):
    BINDINGS = [
        Binding("tab", "tab", "mode", priority=True),
        Binding("escape", "escape", "interrupt", show=False),
        Binding("up", "arrow(-1)", show=False, priority=True),
        Binding("down", "arrow(1)", show=False, priority=True),
        Binding("pageup", "page(-1)", show=False),
        Binding("pagedown", "page(1)", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.history: list[tuple[str, str]] = []           # (role, text): export + tests
        self._pending: dict[str, deque] = {}
        self._working: Working | None = None
        self._turn_started = 0.0
        self._ticker = None
        self._completed = False

    def compose(self) -> ComposeResult:
        with Vertical(id="home"):
            yield Center(Static(logo_mark(), id="home-logo"))
            yield Center(Static(Text(VERSION, style=FAINT), id="home-version"))
            yield Center(Static(self._hints(), id="home-hints"))
        with Horizontal(id="topbar"):
            yield Label("", id="top-title")
            yield Label("", id="top-meta")
        yield VerticalScroll(id="messages")
        yield OptionList(id="complete")
        with Horizontal(id="prompt-row"):
            yield Label("›", id="prompt-glyph")
            yield Input(placeholder="ask autopwn — e.g. map juice.lab and check it for injection",
                        id="prompt")
        yield Static("", id="status")

    def _hints(self) -> Text:
        t = Text()
        for name in HOME_HINTS:
            c = commands.BY_NAME[name]
            t.append(f"/{c.name:<11}", style=f"bold {WHITE}")
            t.append(f"{c.help:<42}", style=GRAY)
            t.append(f"ctrl+x {c.key}\n" if c.key else "\n", style=FAINT)
        return t

    def on_mount(self) -> None:
        self.messages.anchor()
        self.query_one("#complete", OptionList).display = False
        self._show_home(True)
        self.prompt.focus()
        self.refresh_status()

    @property
    def prompt(self) -> Input:
        return self.query_one("#prompt", Input)

    @property
    def messages(self) -> VerticalScroll:
        return self.query_one("#messages", VerticalScroll)

    def _show_home(self, home: bool) -> None:
        self.query_one("#home").display = home
        self.query_one("#topbar").display = not home
        self.messages.display = not home

    def _add(self, widget, role: str, text: str) -> None:
        """Mount a message with a short fade-in. The conversation stays anchored to
        the bottom while the operator is there; scrolling up to read releases it."""
        self.history.append((role, text))
        self._show_home(False)
        widget.styles.opacity = 0.0
        if self._working is not None and self._working.parent is not None:
            self.messages.mount(widget, before=self._working)
        else:
            self.messages.mount(widget)
        widget.styles.animate("opacity", 1.0, duration=FADE, easing="out_cubic")

    def user(self, text: str) -> None:
        self._add(UserMessage(text), "user", text)

    def agent(self, text: str, footer: str = "") -> None:
        self._add(AssistantMessage(text, footer), "agent", text)

    def narration(self, text: str) -> None:
        self._add(Narration(text), "narration", text)

    def notice(self, text: str, kind: str = "system") -> None:
        role = {"success": "system", "warning": "system"}.get(kind, kind)
        self._add(Notice(text, kind), role, text)

    def tool_started(self, name: str, args) -> ToolLine:
        line = ToolLine(name, _short(args))
        self._pending.setdefault(name, deque()).append(line)
        self._add(line, "tool", f"{name} {_short(args)}".strip())
        return line

    def tool_finished(self, name: str, ok: bool, ms: float | None) -> None:
        queue = self._pending.get(name)
        if queue:
            line = queue.popleft()
            line.finish("ok" if ok else "error", f"{ms:.0f}ms" if ok and ms is not None else
                        ("" if ok else "failed"))

    def clear(self) -> None:
        self.messages.remove_children()
        self.history.clear()
        self._pending.clear()
        self._working = None
        self._show_home(True)
        self.refresh_status()

    def replay(self, messages) -> None:
        """Render a resumed conversation."""
        for m in messages:
            if m.role == "user" and m.content:
                self.user(m.content)
            elif m.role == "assistant":
                if m.content and m.tool_calls:
                    self.narration(m.content)
                elif m.content:
                    self.agent(m.content)
                for c in m.tool_calls:
                    self.tool_started(c.name, c.arguments).finish("ok")
                    self._pending[c.name].clear()

    def start_turn(self, text: str) -> None:
        self.messages.anchor()
        self.messages.scroll_end(animate=True, duration=SCROLL, easing="out_cubic")
        self.user(text)
        self._turn_started = time.monotonic()
        self._working = Working()
        self.messages.mount(self._working)
        self._ticker = self.set_interval(0.1, self._tick)
        self._run_turn(text)
        self.refresh_status()

    @work(thread=True, exclusive=True, group="turn", exit_on_error=False)
    def _run_turn(self, text: str) -> None:
        try:
            result = self.app.session.chat(text)
        except Exception as e:
            result = None
            self.app.call_from_thread(self.notice, f"{type(e).__name__}: {e}", "error")
        self.app.call_from_thread(self._turn_done, result)

    def _turn_done(self, result) -> None:
        if self._ticker is not None:
            self._ticker.stop()
            self._ticker = None
        if self._working is not None:
            self._working.remove()
            self._working = None
        for queue in self._pending.values():
            for line in queue:
                line.finish("skipped")
            queue.clear()
        if result is not None:
            secs = time.monotonic() - self._turn_started
            footer = (f"{self.app.session.model} · {secs:.1f}s · {_compact_num(result.tokens)} tokens"
                      f"   /copy {self.app.session.answer_count()}")
            if result.reason == "error":
                self.notice(result.error or "the turn failed", "error")
                if "API key" in (result.error or ""):
                    self.app.provider_ok = False
            elif result.reason == "cancelled":
                self.notice("interrupted", "warning")
            elif result.final:
                self.agent(result.final, footer)
                self.app.provider_ok = True
            elif result.reason.startswith("max_"):
                self.notice(f"stopped: {result.reason.replace('_', ' ')} for this turn — ask to continue",
                            "warning")
        self.refresh_status()
        self.prompt.focus()

    def _tick(self) -> None:
        if self._working is not None:
            self._working.tick(time.monotonic() - self._turn_started)
        for queue in self._pending.values():
            for line in queue:
                line.tick()

    def on_engine(self, rec: dict) -> None:
        kind = rec.get("kind", "")
        if kind == "tool.call":
            self.tool_started(rec.get("tool", "tool"), rec.get("args"))
        elif kind == "tool.result":
            self.tool_finished(rec.get("tool", ""), bool(rec.get("ok", True)), rec.get("ms"))
        elif kind == "tool.declined":
            line = ToolLine(rec.get("tool", "tool"))
            self._add(line, "system", f"{rec.get('tool')} declined")
            line.finish("declined", rec.get("reason", "declined"))
        elif kind == "agent.message" and rec.get("text"):
            self.narration(rec["text"])
        elif kind == "verify" and rec.get("verified"):
            f = next((x for x in self.app.session.findings() if x.id == rec.get("finding")), None)
            if f is not None:
                self._add(FindingLine(f.severity.rating.value, f.title, f.target.url or f.target.host,
                                      rec.get("method", "")),
                          "system", f"verified {f.title}")
        elif kind == "agent.error":
            self.notice(rec.get("error", "provider error"), "error")
        if kind in ("llm.result", "tool.result", "verify"):
            self.refresh_status()

    def refresh_status(self) -> None:
        s = self.app.session
        if s is None:
            return
        st = s.context_stats()
        t = Text()
        hitl = s.mode == "hitl"
        t.append(" HITL " if hitl else " AUTO ", style=f"bold #0B0D0C on {ORANGE if hitl else GREEN}")
        t.append("  ")
        t.append("● " if self.app.provider_ok else "○ ", style=GREEN if self.app.provider_ok else RED)
        t.append(s.model, style=WHITE)
        t.append(f"   {st['phase']}", style=BLUE)
        scope = ", ".join(s.targets[:2]) + ("…" if len(s.targets) > 2 else "")
        t.append(f"   {scope or 'no scope'}", style=GRAY if scope else FAINT)
        if scope:
            t.append(" ✓" if s.authorized else " !", style=GREEN if s.authorized else ORANGE)
        right = Text()
        if st["turns"] or st["messages"]:
            right.append(f"{_compact_num(st['tokens_est'])} ", style=GRAY)
            right.append(f"{st['percent']:.0f}%", style=ORANGE if st["percent"] >= 70 else GRAY)
        if st["session_cost"]:
            right.append(f"  ${st['session_cost']:.3f}", style=GRAY)
        if st["verified"]:
            right.append(f"  ◆ {st['verified']}", style=GREEN)
        right.append("   tab mode  ctrl+p commands", style=FAINT)
        pad = max(1, self.size.width - t.cell_len - right.cell_len - 2)
        t.append(" " * pad)
        t.append_text(right)
        self.query_one("#status", Static).update(t)
        self.query_one("#top-title", Label).update(Text(f"# {s.title or 'new session'}", style=f"bold {WHITE}"))
        meta = f"{s.turns} turn{'s' if s.turns != 1 else ''}"
        if st["compactions"]:
            meta += f" · {st['compactions']} compaction{'s' if st['compactions'] != 1 else ''}"
        self.query_one("#top-meta", Label).update(Text(meta, style=FAINT))

    def on_resize(self) -> None:
        self.refresh_status()

    @property
    def completing(self) -> bool:
        return bool(self.query_one("#complete", OptionList).display)

    @on(Input.Changed, "#prompt")
    def _changed(self, event: Input.Changed) -> None:
        value = event.value
        ol = self.query_one("#complete", OptionList)
        if self._completed:
            self._completed = False
            ol.display = False
            return
        if value.startswith("/"):
            found = commands.suggestions(value)
            ol.clear_options()
            for text, help_ in found:
                line = Text()
                line.append(f"/{text:<18}", style=f"bold {WHITE}")
                line.append(help_, style=GRAY)
                ol.add_option(Option(line, id=text))
            ol.display = bool(found)
            if found:
                ol.highlighted = 0
        else:
            ol.display = False

    def _complete(self) -> bool:
        ol = self.query_one("#complete", OptionList)
        if not self.completing or ol.highlighted is None:
            return False
        name = ol.get_option_at_index(ol.highlighted).id
        self._completed = True
        self.prompt.value = f"/{name}"
        self.prompt.cursor_position = len(self.prompt.value)
        ol.display = False
        return True

    @on(Input.Submitted, "#prompt")
    def _submit(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if self.completing and text.startswith("/"):
            ol = self.query_one("#complete", OptionList)
            pick = ol.get_option_at_index(ol.highlighted).id if ol.highlighted is not None else None
            if commands.parse(text) is None or (pick and pick.startswith(text[1:].lower())):
                self._complete()
                text = self.prompt.value.strip()
        self.query_one("#complete", OptionList).display = False
        if not text:
            return
        event.input.value = ""
        if text.startswith("/"):
            parsed = commands.parse(text)
            if parsed is None:
                self.notice(f"unknown command {text.split()[0]} — /help lists them", "error")
            else:
                self.app.run_command(*parsed)
            return
        if self.app.session.busy:
            self.app.notify("the agent is working — esc interrupts", severity="warning")
            return
        self.start_turn(text)

    @on(OptionList.OptionSelected, "#complete")
    def _picked(self, _event) -> None:
        self._complete()
        self.prompt.focus()

    def action_tab(self) -> None:
        if not self._complete():
            self.app.action_toggle_mode()

    def action_arrow(self, delta: int) -> None:
        if self.completing:
            ol = self.query_one("#complete", OptionList)
            if ol.option_count:
                ol.highlighted = max(0, min(ol.option_count - 1, (ol.highlighted or 0) + delta))
        else:
            self.messages.scroll_relative(y=delta * 3, duration=SCROLL, easing="out_cubic")

    def action_page(self, delta: int) -> None:
        self.messages.scroll_relative(y=delta * max(5, self.messages.size.height - 2),
                                      duration=SCROLL * 1.6, easing="out_cubic")

    def action_escape(self) -> None:
        if self.completing:
            self.query_one("#complete", OptionList).display = False
        elif self.app.session and self.app.session.busy:
            self.app.session.cancel()
            self.notice("interrupting after the current step…", "warning")
