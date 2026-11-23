"""First-run setup: consent, providers and keys, default model, preferences.

Shown automatically until it is completed once; `autopwnai setup` or `/setup`
opens it again. Every step can be changed later from the app.
"""
from __future__ import annotations

from datetime import UTC, datetime

from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    ContentSwitcher,
    Input,
    Label,
    OptionList,
    RadioButton,
    RadioSet,
    SelectionList,
    Static,
)
from textual.widgets.option_list import Option
from textual.widgets.selection_list import Selection

from ..llm.catalog import PROVIDERS, list_models
from ..llm.keycheck import check_key
from ..mcp.presets import PRESETS
from ..onboarding import TERMS, TERMS_VERSION, Scan, scan
from ..ui.banner import logo_mark
from ..ui.theme import FAINT, GRAY, GREEN, ORANGE, RED, WHITE

STEPS = ("welcome", "providers", "keys", "model", "prefs", "done")
TITLES = {"welcome": "Welcome", "providers": "Providers", "keys": "Keys", "model": "Model",
          "prefs": "Preferences", "done": "Ready"}
SUGGESTED_MCP = ("fetch", "thinking", "time", "knowledge-graph")
MODELS_PER_PROVIDER = 6


class SetupScreen(Screen):
    BINDINGS = [Binding("escape", "back", "back", show=False)]

    def __init__(self, *, rerun: bool = False) -> None:
        super().__init__()
        self.rerun = rerun
        self.step = 0
        self.scan_result: Scan | None = None
        self.key_queue: list[str] = []
        self.key_index = 0
        self.connected: list[str] = []
        self.model: str | None = None
        self._busy = False

    @property
    def session(self):
        return self.app.session

    def compose(self) -> ComposeResult:
        with Vertical(id="setup"):
            yield Static("", id="setup-steps")
            with ContentSwitcher(initial="welcome", id="setup-body"):
                with VerticalScroll(id="welcome", can_focus=False):
                    yield Center(Static(logo_mark(), id="setup-logo"))
                    yield Static(Text("Let's get you set up — about a minute. Everything here can be "
                                      "changed later from the app.", style=GRAY), classes="setup-lead")
                    yield Static(Text(TERMS, style=WHITE), id="setup-terms")
                    yield Checkbox("I will only test systems I own or am authorized to test", id="terms")
                    yield Label("Your name (recorded in the audit log)", classes="field")
                    yield Input(placeholder="operator", id="operator")
                with VerticalScroll(id="providers", can_focus=False):
                    yield Static(Text("Which providers do you have access to? Pick every one you want to "
                                      "use — ones already available on this machine are ticked.", style=GRAY),
                                 classes="setup-lead")
                    yield SelectionList[str](id="prov-list")
                with Vertical(id="keys"):
                    yield Static("", id="key-title")
                    yield Static("", id="key-help")
                    yield Input(placeholder="API key — stored encrypted on this machine", password=True,
                                id="key-input")
                    yield Input(placeholder="endpoint / API base URL", id="key-base")
                    with Horizontal(classes="dialog-buttons"):
                        yield Button("Verify & save", id="key-save", variant="success")
                        yield Button("Skip", id="key-skip")
                    yield Static("", id="key-status")
                with Vertical(id="model"):
                    yield Static(Text("Pick the default model. Only tool-capable models are listed; "
                                      "/model switches any time.", style=GRAY), classes="setup-lead")
                    yield OptionList(id="model-list")
                with VerticalScroll(id="prefs", can_focus=False):
                    yield Label("How should the agent work?", classes="field")
                    with RadioSet(id="mode"):
                        yield RadioButton("Ask before each tool runs (human-in-the-loop) — recommended to start",
                                          value=True)
                        yield RadioButton("Autonomous — run tools without asking")
                    yield Label("MCP servers to add (optional)", classes="field")
                    yield SelectionList[str](id="mcp-pick")
                    yield Label("Scanners on this machine", classes="field")
                    yield Static("", id="tools-table")
                    yield Checkbox("Download the missing scanners in the background after setup "
                                   "(official releases, checksum-verified, no root)", value=True, id="get-scanners")
                with VerticalScroll(id="done", can_focus=False):
                    yield Static("", id="summary")
            with Horizontal(id="setup-nav"):
                yield Button("Back", id="nav-back")
                yield Static("", id="nav-msg")
                yield Button("Next", id="nav-next", variant="success")

    def on_mount(self) -> None:
        s = self.session.settings
        self.query_one("#operator", Input).value = s.operator or ""
        if s.terms_accepted.startswith(f"{TERMS_VERSION}@"):
            self.query_one("#terms", Checkbox).value = True
        self.query_one("#mode", RadioSet).query(RadioButton)[0 if s.mode == "hitl" or not s.setup_done else 1] \
            .value = True
        self._show()
        self._load_scan()
        self.query_one("#terms", Checkbox).focus()

    @property
    def current(self) -> str:
        return STEPS[self.step]

    def _show(self) -> None:
        self.query_one("#setup-body", ContentSwitcher).current = self.current
        bar = Text()
        for i, name in enumerate(STEPS):
            if name == "keys" and not self.key_queue:
                continue
            done, here = i < self.step, i == self.step
            bar.append("● " if done or here else "○ ", style=GREEN if done or here else FAINT)
            bar.append(TITLES[name], style=f"bold {WHITE}" if here else (GRAY if done else FAINT))
            if name != "done":
                bar.append("  ─  ", style=FAINT)
        self.query_one("#setup-steps", Static).update(bar)
        self.query_one("#nav-back", Button).disabled = self.step == 0
        self.query_one("#nav-next", Button).label = "Start" if self.current == "done" else "Next"
        self.query_one("#nav-next", Button).display = self.current != "keys"
        self._msg("")
        if self.current == "keys":
            self._show_key()
        elif self.current == "model":
            self._load_models()
        elif self.current == "done":
            self._show_summary()

    def _msg(self, text: str, color: str = ORANGE) -> None:
        if not text:
            text, color = "tab move · space select · enter continue · esc back", FAINT
        self.query_one("#nav-msg", Static).update(Text(text, style=color))

    def _goto(self, step: int) -> None:
        if STEPS[step] == "keys" and not self.key_queue:
            step += 1 if step > self.step else -1
        self.step = max(0, min(step, len(STEPS) - 1))
        self._show()

    @on(Button.Pressed, "#nav-back")
    def action_back(self) -> None:
        if self._busy or self.step == 0:
            return
        if self.current == "keys" and self.key_index > 0:
            self.key_index -= 1
            self._show_key()
            return
        self._goto(self.step - 1)

    @on(Input.Submitted, "#operator")
    @on(Button.Pressed, "#nav-next")
    def _next(self) -> None:
        if self._busy:
            return
        handler = getattr(self, f"_leave_{self.current}", None)
        if handler is not None and handler() is False:
            return
        if self.current == "done":
            self._finish()
            return
        self._goto(self.step + 1)

    def _leave_welcome(self) -> bool:
        if not self.query_one("#terms", Checkbox).value:
            self._msg("please confirm you will only test authorized systems")
            return False
        return True

    @work(thread=True, group="setup-scan", exit_on_error=False)
    def _load_scan(self) -> None:
        sc = scan(set(self.session.creds.providers()), dict(self.session.settings.api_bases))
        self.app.call_from_thread(self._scan_done, sc)

    def _scan_done(self, sc: Scan) -> None:
        self.scan_result = sc
        sl = self.query_one("#prov-list", SelectionList)
        sl.clear_options()
        for p in sc.providers:
            label = Text()
            label.append(f"{p.label:<22}", style=WHITE)
            if p.found:
                label.append(f"● {p.found}", style=GREEN)
            elif p.note:
                label.append(p.note, style=FAINT)
            sl.add_option(Selection(label, p.id, bool(p.found)))
        self._fill_prefs(sc)

    def _leave_providers(self) -> bool:
        if self.scan_result is None:
            self._msg("still checking this machine…")
            return False
        chosen = list(self.query_one("#prov-list", SelectionList).selected)
        found = {p.id for p in self.scan_result.providers if p.found}
        self.connected = [pid for pid in chosen if pid in found]
        self.key_queue = [pid for pid in chosen if pid not in found]
        self.key_index = 0
        return True

    def _show_key(self) -> None:
        if self.key_index >= len(self.key_queue):
            self._goto(self.step + 1)
            return
        pid = self.key_queue[self.key_index]
        info = PROVIDERS[pid]
        title = Text()
        title.append(f"{info.label}", style=f"bold {WHITE}")
        title.append(f"   {self.key_index + 1} of {len(self.key_queue)}", style=FAINT)
        self.query_one("#key-title", Static).update(title)
        hint = info.note or ""
        if info.env_var and info.requires_key:
            hint = (hint + "  ·  " if hint else "") + f"or set ${info.env_var} in your shell"
        self.query_one("#key-help", Static).update(Text(hint, style=GRAY))
        key = self.query_one("#key-input", Input)
        key.value = ""
        key.display = info.requires_key or pid == "openai_compatible"
        key.placeholder = ("API key (optional)" if not info.requires_key
                           else "API key — stored encrypted on this machine")
        base = self.query_one("#key-base", Input)
        base.value = self.session.settings.api_bases.get(pid) or info.api_base or ""
        base.display = info.needs_api_base or bool(info.api_base)
        self.query_one("#key-status", Static).update("")
        (key if key.display else base).focus()

    @on(Input.Submitted, "#key-input")
    @on(Input.Submitted, "#key-base")
    @on(Button.Pressed, "#key-save")
    def _verify(self) -> None:
        if self._busy or self.current != "keys":
            return
        pid = self.key_queue[self.key_index]
        key = self.query_one("#key-input", Input).value.strip() or None
        base = self.query_one("#key-base", Input).value.strip() or None
        self._busy = True
        self.query_one("#key-status", Static).update(Text("checking…", style=GRAY))
        self._check(pid, key, base)

    @work(thread=True, group="setup-key", exit_on_error=False)
    def _check(self, pid: str, key: str | None, base: str | None) -> None:
        result = check_key(pid, key, base)
        if result.ok:
            self.session.connect_provider(pid, key, api_base=base)
        self.app.call_from_thread(self._checked, pid, result)

    def _checked(self, pid: str, result) -> None:
        self._busy = False
        color = GREEN if result.verified else (ORANGE if result.ok else RED)
        self.query_one("#key-status", Static).update(Text(("✓ " if result.ok else "✗ ") + result.message,
                                                          style=color))
        if result.ok:
            if pid not in self.connected:
                self.connected.append(pid)
            self.set_timer(0.8 if result.verified else 1.6, self._advance_key)

    @on(Button.Pressed, "#key-skip")
    def _skip_key(self) -> None:
        if not self._busy:
            self._advance_key()

    def _advance_key(self) -> None:
        if self.current != "keys":
            return
        self.key_index += 1
        self._show_key()

    @work(thread=True, group="setup-models", exit_on_error=False)
    def _load_models(self) -> None:
        rows: list[tuple[str, str, str]] = []
        for pid in self.connected:
            entries = [m for m in list_models(pid) if m.tools is not False]
            for m in entries[:MODELS_PER_PROVIDER]:
                ctx = f"{m.context // 1000}K" if m.context else ""
                tag = "free" if m.free else ("recommended" if m.featured else "")
                rows.append((m.id, ctx, tag))
        self.app.call_from_thread(self._models_loaded, rows)

    def _models_loaded(self, rows: list[tuple[str, str, str]]) -> None:
        ol = self.query_one("#model-list", OptionList)
        ol.clear_options()
        if not rows:
            ol.add_option(Option(Text("No provider connected yet — connect one later with /provider.",
                                      style=ORANGE), id="", disabled=True))
            self.model = None
            return
        width = max(len(r[0]) for r in rows) + 2
        for mid, ctx, tag in rows:
            line = Text()
            line.append(f"{mid:<{width}}", style=WHITE)
            line.append(f"{ctx:>6}  ", style=GRAY)
            line.append(tag, style=GREEN if tag else FAINT)
            ol.add_option(Option(line, id=mid))
        ids = [r[0] for r in rows]
        current = self.model or self.session.model
        ol.highlighted = ids.index(current) if current in ids else 0
        ol.focus()

    def _leave_model(self) -> bool:
        ol = self.query_one("#model-list", OptionList)
        if ol.highlighted is not None and ol.option_count:
            self.model = ol.get_option_at_index(ol.highlighted).id or None
        return True

    @on(OptionList.OptionSelected, "#model-list")
    def _model_picked(self) -> None:
        self._next()

    def _fill_prefs(self, sc: Scan) -> None:
        added = {c.name for c in self.session.mcp_configs()}
        sl = self.query_one("#mcp-pick", SelectionList)
        sl.clear_options()
        for name in SUGGESTED_MCP:
            preset = PRESETS[name]
            if not sc.launchers.get(preset.requires, True):
                continue
            label = Text()
            label.append(f"{preset.title:<22}", style=WHITE)
            label.append(preset.description, style=GRAY)
            sl.add_option(Selection(label, name, name in added or name in ("fetch", "thinking")))
        table = Table.grid(padding=(0, 2))
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True, overflow="ellipsis", max_width=44)
        for t in sc.tools:
            mark = Text("✓", style=GREEN) if t.path else Text("·", style=FAINT)
            how = Text(t.install, style=GRAY) if t.install else Text("installed", style=FAINT)
            table.add_row(mark, Text(t.name, style=WHITE), Text(t.purpose, style=GRAY), how)
        self.query_one("#get-scanners", Checkbox).display = bool(self._missing_scanners())
        if sc.system:
            table.add_row(Text("·", style=FAINT), Text("system", style=WHITE), Text(sc.system, style=GRAY), Text(""))
        note = Text("\nOptional — the agent uses what is installed. Full install commands: autopwnai doctor",
                    style=FAINT)
        from rich.console import Group
        self.query_one("#tools-table", Static).update(Group(table, note))

    def _choices(self) -> dict:
        return {"operator": self.query_one("#operator", Input).value.strip(),
                "mode": "hitl" if self.query_one("#mode", RadioSet).pressed_index == 0 else "autonomous",
                "mcp": list(self.query_one("#mcp-pick", SelectionList).selected),
                "model": self.model,
                "scanners": self._missing_scanners() if self.query_one("#get-scanners", Checkbox).value else []}

    def _missing_scanners(self) -> list[str]:
        from ..recon.installer import SCANNERS, resolve
        return [s.name for s in SCANNERS.values() if s.downloadable and not resolve(s.name)]

    def _show_summary(self) -> None:
        c = self._choices()
        t = Text()
        rows = [("Operator", c["operator"] or "—"),
                ("Providers", ", ".join(PROVIDERS[p].label for p in self.connected) or "none yet — use /provider"),
                ("Model", c["model"] or self.session.model),
                ("Mode", "human-in-the-loop" if c["mode"] == "hitl" else "autonomous"),
                ("MCP servers", ", ".join(c["mcp"]) or "none"),
                ("Scanners", f"download {', '.join(c['scanners'])}" if c["scanners"] else "nothing to download")]
        for k, v in rows:
            t.append(f"  {k:<14}", style=GRAY)
            t.append(f"{v}\n", style=WHITE)
        t.append("\nKeys are stored encrypted on this machine and never sent to the model.\n\n", style=FAINT)
        t.append("Press Start. Type a goal in plain language — e.g. ", style=GRAY)
        t.append("map lab.local and check it for injection", style=GREEN)
        t.append(" — or / for commands.", style=GRAY)
        self.query_one("#summary", Static).update(t)
        self.query_one("#nav-next", Button).focus()

    def _finish(self) -> None:
        self._busy = True
        self._msg("saving…", GRAY)
        self._apply(self._choices())

    @work(thread=True, group="setup-apply", exit_on_error=False)
    def _apply(self, c: dict) -> None:
        s = self.session
        notes: list[str] = []
        s.settings.operator = c["operator"]
        s.settings.terms_accepted = f"{TERMS_VERSION}@{datetime.now(UTC).isoformat(timespec='seconds')}"
        s.set_mode(c["mode"])
        existing = {cfg.name for cfg in s.mcp_configs()}
        for name in c["mcp"]:
            if name not in existing:
                try:
                    s.add_mcp_preset(name)
                except Exception as e:
                    notes.append(f"MCP {name}: {e}")
        if c["model"] and c["model"] != s.model:
            state = s.set_model(c["model"])
            if not state.ok:
                notes.append(state.message)
        s.settings.setup_done = True
        s.settings.save()
        s.audit.record("setup", operator=c["operator"] or "operator", mode=c["mode"],
                       providers=self.connected, mcp=c["mcp"], terms=TERMS_VERSION)
        self.app.call_from_thread(self.dismiss, {"notes": notes, "scanners": c["scanners"]})
