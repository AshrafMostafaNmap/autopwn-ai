"""The `autopwnai` terminal app.

Holds one EngineSession. Engine events arrive through logger sinks and
`post_message` (thread-safe); approvals block the agent thread on a dialog.
Every control is reachable three ways: `/command`, Ctrl+P, and Ctrl+X <key>.
"""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable

from rich.text import Text
from rich.theme import Theme
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.widgets import Input, Static

from ..ui.theme import BLUE, FAINT, GRAY, GREEN, WHITE
from . import commands
from .dialogs import (
    ApprovalDialog,
    ContextDialog,
    FindingsDialog,
    HelpDialog,
    MCPDialog,
    MemoryDialog,
    PickerDialog,
    PickItem,
    ProviderDialog,
    ReportDialog,
    ScopeDialog,
    ToolsDialog,
    command_items,
    model_items,
    provider_items,
    session_items,
)
from .main import MainScreen

ROLES = ("Pentester", "Scope Approver", "Admin", "Viewer")     # Viewer cannot approve tools

MARKDOWN_THEME = Theme({
    "markdown.h1": f"bold {GREEN}", "markdown.h1.border": GREEN,
    "markdown.h2": f"bold {WHITE}", "markdown.h3": f"bold {WHITE}",
    "markdown.h4": f"bold {GRAY}", "markdown.h5": GRAY, "markdown.h6": GRAY,
    "markdown.code": BLUE, "markdown.code_block": WHITE, "markdown.link": f"underline {BLUE}",
    "markdown.link_url": BLUE, "markdown.item.bullet": GREEN, "markdown.item.number": GREEN,
    "markdown.block_quote": GRAY, "markdown.hr": FAINT, "markdown.strong": f"bold {WHITE}",
    "markdown.em": f"italic {WHITE}", "markdown.table.header": f"bold {GREEN}",
})


class EngineEvent(Message):
    def __init__(self, record: dict) -> None:
        super().__init__()
        self.record = record


class LeaderDialog(ModalScreen[str]):
    """Ctrl+X: shows the shortcut keys and returns the next key pressed."""

    def compose(self) -> ComposeResult:
        t = Text()
        keyed = [c for c in commands.COMMANDS if c.key]
        for i, c in enumerate(keyed):
            t.append(f"{c.key} ", style=f"bold {GREEN}")
            t.append(f"{c.name:<12}", style=WHITE)
            if i % 7 == 6 and i != len(keyed) - 1:
                t.append("\n")
        with Vertical(classes="leader"):
            yield Static(Text("ctrl+x", style=f"bold {GRAY}"))
            yield Static(t)

    def on_key(self, event) -> None:
        event.stop()
        self.dismiss(event.key)


class FatalScreen(Screen):
    BINDINGS = [Binding("q", "app.exit", "quit"), Binding("escape", "app.exit", "quit")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        yield Static(Text(f"AutoPwn AI could not start\n\n{self.message}\n\npress q to quit", style=WHITE),
                     id="fatal")


class AutoPwnApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "AutoPwn AI"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+c", "copy_or_quit", "copy / quit", priority=True),
        Binding("ctrl+p", "command_menu", "commands", priority=True),
        Binding("ctrl+x", "leader", "shortcuts", priority=True),
        Binding("f1", "help", show=False),
        Binding("f3", "cycle_role", show=False),
    ]

    def __init__(self, session_factory: Callable | None = None, *, setup: bool = False, **kw) -> None:
        super().__init__(**kw)
        self._force_setup = setup
        self._factory = session_factory or _default_factory()
        self.session = None
        self.main: MainScreen | None = None
        self.provider_ok = False
        self.role = ROLES[0]
        self._exiting = False
        self._quit_armed = 0.0

    # ── startup ───────────────────────────────────────────────────────────────
    def on_mount(self) -> None:
        self.console.push_theme(MARKDOWN_THEME)
        try:
            self.session = self._factory()
        except Exception as e:
            self.push_screen(FatalScreen(f"{type(e).__name__}: {e}"))
            return
        self._wire()
        self.main = MainScreen()
        self.push_screen(self.main)
        if self._force_setup or not self.session.settings.setup_done:
            self.action_setup(first_run=not self.session.settings.setup_done)
        else:
            self._startup()

    def action_setup(self, first_run: bool = False) -> None:
        from .setup import SetupScreen

        def done(notes) -> None:
            for n in notes or []:
                self.main.notice(n, "warning")
            if notes is not None:
                self.main.notice("setup saved — /setup runs it again", "success")
            if first_run or self._force_setup:
                self._force_setup = False
                self._startup(after_setup=True)
            else:
                self.provider_ok = self.session.ready().ok
                self.main.refresh_status()
        self.push_screen(SetupScreen(rerun=not first_run), done)

    def _wire(self) -> None:
        self.session.subscribe(lambda rec: self.post_message(EngineEvent(rec)))
        self.session.set_approver(self._approve_from_thread)

    @work(thread=True, group="startup", exit_on_error=False)
    def _startup(self, after_setup: bool = False) -> None:
        state = self.session.ready()
        mcp = self.session.connect_enabled_mcp() if self.session.mcp_configs() else {}
        self.call_from_thread(self._startup_done, state, mcp, after_setup)

    def _startup_done(self, state, mcp: dict, after_setup: bool = False) -> None:
        self.provider_ok = state.ok
        m = self.main
        if m is None:
            return
        if self.session.auto_selected:
            m.notice(f"using {self.session.auto_selected} — the default model's provider isn't connected")
        if not state.ok:
            m.notice(state.message, "error")
            if not after_setup:
                self.action_open_provider(message="Connect a provider to start.")
        for w in state.warnings:
            m.notice(w, "warning")
        for name, res in mcp.items():
            m.notice(f"MCP {name}: {res}", "success" if res.startswith("ok") else "error")
        m.refresh_status()

    # ── engine → UI ───────────────────────────────────────────────────────────
    def on_engine_event(self, message: EngineEvent) -> None:
        if self.main is not None and self.main.is_mounted:
            self.main.on_engine(message.record)

    def refresh_status(self) -> None:
        if self.main is not None and self.main.is_mounted:
            self.main.refresh_status()

    # ── approvals (agent thread) ──────────────────────────────────────────────
    def _approve_from_thread(self, call, tool) -> bool:
        if self.role == "Viewer" or self._exiting:
            return False
        decided, box = threading.Event(), {"ok": False}

        def show() -> None:
            def done(result) -> None:
                box["ok"] = bool(result)
                decided.set()
            self.push_screen(ApprovalDialog(tool.name, tool.source, dict(call.arguments or {})), done)

        try:
            self.call_from_thread(show)
        except RuntimeError:
            return False
        while not decided.wait(0.2):
            if self._exiting or self.session.agent.cancelled:
                return False
        return box["ok"]

    # ── commands ──────────────────────────────────────────────────────────────
    def run_command(self, cmd: commands.Command, arg: str = "") -> None:
        if cmd.name == "model" and arg:
            self.apply_model(arg)
        elif cmd.name == "mode" and arg:
            self.set_mode("hitl" if arg.lower().startswith(("h", "manual", "on")) else "autonomous")
        elif cmd.name == "export" and arg:
            words = arg.lower().split()
            fmt = next((w for w in words if w in ("txt", "md", "html")), "txt")
            self.export_chat(fmt, tools="clean" not in words)
        elif cmd.name == "copy" and arg:
            if arg.strip().isdigit():
                self.copy_answer(int(arg))
            else:
                self.action_copy(everything=arg.lower().startswith(("all", "chat")))
        else:
            getattr(self, f"action_{cmd.action}")()

    def action_command_menu(self) -> None:
        def chosen(name):
            if name and (parsed := commands.parse(f"/{name}")):
                self.run_command(*parsed)
        self.push_screen(PickerDialog("Commands", command_items(), placeholder="search commands"), chosen)

    def action_leader(self) -> None:
        def pressed(key):
            cmd = commands.BY_KEY.get(key or "")
            if cmd:
                self.run_command(cmd)
        self.push_screen(LeaderDialog(), pressed)

    # ── model / provider ──────────────────────────────────────────────────────
    def action_open_model(self, provider: str | None = None) -> None:
        def chosen(model_id):
            if model_id:
                self.apply_model(model_id)
        first = provider or self.session.provider_id
        self.push_screen(PickerDialog("Models", loader=lambda: model_items(self.session, first=first),
                                      placeholder="search models — e.g. free, sonnet, gpt",
                                      empty="no connected provider has models — /provider",
                                      allow_custom=True), chosen)

    def apply_model(self, model_id: str) -> None:
        self.main.notice(f"switching to {model_id}…")
        self._set_model(model_id)

    @work(thread=True, group="model", exit_on_error=False)
    def _set_model(self, model_id: str) -> None:
        state = self.session.set_model(model_id)
        self.call_from_thread(self._model_set, model_id, state)

    def _model_set(self, model_id: str, state) -> None:
        self.provider_ok = state.ok
        if state.ok:
            self.main.notice(f"model {model_id}", "success")
            for w in state.warnings:
                self.main.notice(w, "warning")
        else:
            self.main.notice(state.message, "error")
            if "API key" in state.message:
                self.action_open_provider(self.session.provider_id, f"{model_id} needs this provider connected.")
        self.main.refresh_status()

    def action_open_provider(self, provider: str | None = None, message: str = "") -> None:
        def saved(result):
            if not result:
                return
            what, pid = result
            if what == "saved":
                self.main.notice(f"{pid} connected — key stored encrypted on this machine", "success")
                if pid == self.session.provider_id:
                    self.provider_ok = self.session.ready().ok
                    self.main.refresh_status()
                else:
                    self.action_open_model(pid)
            else:
                self.main.notice(f"{pid} key removed")
                self.provider_ok = self.session.ready().ok
                self.main.refresh_status()

        if provider:
            self.push_screen(ProviderDialog(provider, message), saved)
            return

        def chosen(pid):
            if pid:
                self.push_screen(ProviderDialog(pid, message), saved)
        self.push_screen(PickerDialog("Providers", provider_items(self.session),
                                      placeholder="search providers",
                                      footer=message or "enter to add or change a key"), chosen)

    # ── other dialogs ─────────────────────────────────────────────────────────
    def action_open_mcp(self) -> None:
        self.push_screen(MCPDialog(), lambda _r: self.refresh_status())

    def action_open_tools(self) -> None:
        self.push_screen(ToolsDialog())

    def action_open_context(self) -> None:
        self.push_screen(ContextDialog(), lambda _r: self.refresh_status())

    def action_open_findings(self) -> None:
        self.push_screen(FindingsDialog())

    def action_open_report(self) -> None:
        self.push_screen(ReportDialog())

    def action_open_memory(self) -> None:
        self.push_screen(MemoryDialog())

    def action_help(self) -> None:
        self.push_screen(HelpDialog())

    def action_open_scope(self) -> None:
        def saved(result):
            if result:
                s = self.session
                self.main.notice(f"scope: {', '.join(s.targets) or 'none'} · "
                                 f"{'authorized' if s.authorized else 'NOT authorized'} · "
                                 f"{s.planner.methodology.value}", "success" if s.authorized else "warning")
            self.refresh_status()
        self.push_screen(ScopeDialog(), saved)

    def action_open_sessions(self) -> None:
        def chosen(path):
            if path:
                self._switch_session(resume=path)
        self.push_screen(PickerDialog("Sessions", session_items(self.session),
                                      placeholder="search sessions",
                                      empty="no earlier sessions yet"), chosen)

    # ── session controls ──────────────────────────────────────────────────────
    def action_toggle_mode(self) -> None:
        self.set_mode("autonomous" if self.session.mode == "hitl" else "hitl")

    def set_mode(self, mode: str) -> None:
        self.session.set_mode(mode)
        self.main.notice("human-in-the-loop — you approve every tool call" if mode == "hitl"
                         else "autonomous — the agent runs tools itself; gated tools still ask")
        self.main.refresh_status()

    def action_cycle_role(self) -> None:
        self.role = ROLES[(ROLES.index(self.role) + 1) % len(ROLES)]
        self.main.notice(f"operator role {self.role}" + (" — cannot approve tools" if self.role == "Viewer" else ""))

    def action_compact(self) -> None:
        if self.session.busy:
            self.notify("wait for the current turn", severity="warning")
            return
        did = self.session.compact()
        self.main.notice("older turns summarized into working memory" if did else "nothing to compact yet",
                         "success" if did else "system")
        self.main.refresh_status()

    def action_export(self) -> None:
        def chosen(choice):
            if choice:
                fmt, _, mode = choice.partition(":")
                self.export_chat(fmt, tools=mode != "clean")
        items = [
            PickItem("txt:clean", "Text", "your questions and the answers, plain and clean", ".txt"),
            PickItem("txt:full", "Text — with tool activity", "also the tools the agent ran", ".txt"),
            PickItem("md:full", "Markdown", "questions, answers and tool activity", ".md"),
            PickItem("md:clean", "Markdown — conversation only", "just your questions and the answers", ".md"),
            PickItem("html:full", "HTML", "styled page for the browser or print to PDF", ".html"),
            PickItem("html:clean", "HTML — conversation only", "styled, without tool activity", ".html"),
        ]
        self.push_screen(PickerDialog("Export chat", items, placeholder="format"), chosen)

    def export_chat(self, fmt: str = "txt", *, tools: bool = True) -> None:
        if not self.session.turns and not self.session.chat_entries():
            self.main.notice("nothing to export yet — send a message first")
            return
        try:
            path = self.session.export_chat(fmt, tools=tools)
        except Exception as e:
            self.main.notice(f"export failed: {e}", "error")
            return
        self.main.notice(f"chat exported → {path.resolve()}", "success")

    def action_new_session(self) -> None:
        self._switch_session()

    def _switch_session(self, resume: str | None = None) -> None:
        if self.session.busy:
            self.notify("wait for the current turn (esc interrupts)", severity="warning")
            return
        deltas = self.session.close()
        try:
            self.session = self._factory(resume=resume) if resume else self._factory()
        except Exception as e:
            self.push_screen(FatalScreen(f"{type(e).__name__}: {e}"))
            return
        self._wire()
        self.main.clear()
        if resume:
            self.main.replay(self.session.agent.conversation.messages)
            self.main.notice(f"resumed — {self.session.turns} turns, working memory restored", "success")
        else:
            for host, summary in deltas.items():
                self.main.notice(f"previous session saved · {host}: {summary}")
        self._startup()

    # ── shutdown ──────────────────────────────────────────────────────────────
    def _close_session(self) -> None:
        if self._exiting or self.session is None:
            return
        self._exiting = True
        if self.session.busy:
            self.session.cancel()
            self.session.wait_idle(timeout=5.0)
        try:
            self.session.close()
        except Exception:
            pass

    # ── clipboard ─────────────────────────────────────────────────────────────
    def copy_to_clipboard(self, text: str) -> None:
        """OSC 52 for terminals that support it, plus the desktop clipboard tool
        (wl-copy / xclip / xsel / pbcopy) for those that do not."""
        super().copy_to_clipboard(text)
        if not self.is_headless:
            threading.Thread(target=_system_copy, args=(text,), daemon=True).start()

    def selected_text(self) -> str:
        text = self.screen.get_selected_text() or ""
        focused = self.focused
        if not text and isinstance(focused, Input) and focused.selected_text:
            text = focused.selected_text
        return text

    def action_copy_or_quit(self) -> None:
        """ctrl+c: copy the selection; otherwise clear the prompt; otherwise
        quit on a second press."""
        if text := self.selected_text():
            self.copy_to_clipboard(text)
            self.screen.clear_selection()
            self.notify(f"copied {len(text):,} characters", timeout=2)
            return
        prompt = self.main.prompt if self.main is not None and self.screen is self.main else None
        if prompt is not None and prompt.value:
            prompt.value = ""
            return
        if time.monotonic() - self._quit_armed < 2.0:
            self.action_save_quit()
            return
        self._quit_armed = time.monotonic()
        self.notify("press ctrl+c again to quit  ·  select text with the mouse, then ctrl+c to copy", timeout=2)

    def action_copy(self, everything: bool = False) -> None:
        if everything:
            from ..transcript import chat_text
            text = chat_text(self.session.chat_entries(), self.session.chat_meta())
            what = "whole chat"
        else:
            text = self.session.last_answer
            what = "last answer"
        if not text:
            self.main.notice("nothing to copy yet")
            return
        self.copy_to_clipboard(text)
        self.main.notice(f"{what} copied to the clipboard ({len(text):,} characters)", "success")

    def copy_answer(self, number: int) -> None:
        from ..transcript import build_turns
        turns = build_turns(self.session.chat_entries())
        if not 1 <= number <= len(turns) or not turns[number - 1].answer:
            self.main.notice(f"no answer #{number} — answers are numbered 1 to {len(turns)}", "error")
            return
        text = turns[number - 1].answer
        self.copy_to_clipboard(text)
        self.main.notice(f"answer #{number} copied to the clipboard ({len(text):,} characters)", "success")

    def action_save_quit(self) -> None:
        self._close_session()
        self.exit()

    async def action_quit(self) -> None:
        self.action_save_quit()

    def on_unmount(self) -> None:
        self._close_session()


def _system_copy(text: str) -> None:
    import shutil
    import subprocess
    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"],
                ["pbcopy"]):
        if cmd[0] == "wl-copy" and not os.environ.get("WAYLAND_DISPLAY"):
            continue
        if cmd[0] in ("xclip", "xsel") and not os.environ.get("DISPLAY"):
            continue
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=3, check=False)
                return
            except (OSError, subprocess.SubprocessError):
                continue


def _default_factory(config_path: str | None = None) -> Callable:
    from ..engine import EngineSession

    def factory(resume: str | None = None):
        return EngineSession.create(config_path=config_path, resume=resume)
    return factory


def run_app(config_path: str | None = None, *, setup: bool = False) -> None:
    AutoPwnApp(session_factory=_default_factory(config_path), setup=setup).run()


__all__ = ["AutoPwnApp", "EngineEvent", "ROLES", "run_app"]
