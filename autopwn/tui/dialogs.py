"""Dialogs. Every list dialog shares one searchable picker; forms are compact."""
from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from dataclasses import dataclass

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, OptionList, RadioButton, RadioSet, Select, Static
from textual.widgets.option_list import Option

from ..ui.theme import FAINT, GRAY, GREEN, ORANGE, RED, WHITE
from . import commands
from .messages import SEV_COLOR


@dataclass
class PickItem:
    id: str
    label: str
    detail: str = ""
    tag: str = ""
    group: str = ""
    disabled: bool = False


def fuzzy_score(query: str, text: str) -> int:
    """0 = no match. Prefers contiguous and early matches."""
    q, t = query.casefold(), text.casefold()
    if not q:
        return 1
    if q in t:
        return 1000 - t.index(q)
    pos, score = 0, 0
    for ch in q:
        found = t.find(ch, pos)
        if found < 0:
            return 0
        score += 10 - min(9, found - pos)
        pos = found + 1
    return score


class Dialog(ModalScreen):
    BINDINGS = [Binding("escape", "close", "close")]
    TITLE = ""
    WIDTH = "medium"

    def header(self) -> Horizontal:
        return Horizontal(Label(self.TITLE, classes="dialog-title"),
                          Label("esc", classes="dialog-esc"), classes="dialog-header")

    def action_close(self) -> None:
        self.dismiss(None)

    @property
    def session(self):
        return self.app.session


class PickerDialog(Dialog):
    BINDINGS = [Binding("escape", "close", "close"),
                Binding("down", "move(1)", show=False, priority=True),
                Binding("up", "move(-1)", show=False, priority=True),
                Binding("pagedown", "move(10)", show=False, priority=True),
                Binding("pageup", "move(-10)", show=False, priority=True)]

    def __init__(self, title: str, items: list[PickItem] | None = None, *,
                 placeholder: str = "search", loader: Callable[[], list[PickItem]] | None = None,
                 empty: str = "nothing here", footer: str = "", allow_custom: bool = False) -> None:
        super().__init__()
        self.TITLE = title
        self.items = items or []
        self.placeholder, self.loader, self.empty = placeholder, loader, empty
        self.footer, self.allow_custom = footer, allow_custom

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield self.header()
            yield Input(placeholder=self.placeholder, id="pick-search")
            yield OptionList(id="pick-list")
            yield Static(Text(self.footer or "↑↓ move · enter select · esc close", style=FAINT),
                         id="pick-footer")

    def on_mount(self) -> None:
        self.query_one("#pick-search", Input).focus()
        if self.loader:
            self._show_items([PickItem("", "loading…", disabled=True)])
            self._load()
        else:
            self._show_items(self.items)

    @work(thread=True, exclusive=True, group="picker")
    def _load(self) -> None:
        items = self.loader()
        self.app.call_from_thread(self._loaded, items)

    def _loaded(self, items: list[PickItem]) -> None:
        self.items = items
        self._filter(self.query_one("#pick-search", Input).value)

    @on(Input.Changed, "#pick-search")
    def _changed(self, event: Input.Changed) -> None:
        self._filter(event.value)

    def _filter(self, query: str) -> None:
        if not query.strip():
            self._show_items(self.items)
            return
        scored = [(fuzzy_score(query, f"{i.label} {i.detail} {i.group}"), i) for i in self.items
                  if not i.disabled]
        self._show_items([i for s, i in sorted(scored, key=lambda x: -x[0]) if s > 0], grouped=False)

    def _show_items(self, items: list[PickItem], grouped: bool = True) -> None:
        ol = self.query_one("#pick-list", OptionList)
        ol.clear_options()
        real = [i for i in items if not i.disabled or i.id]
        label_w = min(max((len(i.label) for i in real), default=0), 34)
        detail_w = min(max((len(i.detail) for i in real), default=0), 46)
        group = None
        for item in items:
            if grouped and item.group and item.group != group:
                group = item.group
                ol.add_option(Option(Text(group, style=f"bold {GREEN}"), disabled=True))
            ol.add_option(Option(self._line(item, label_w, detail_w), id=item.id or None,
                                 disabled=item.disabled))
        if ol.option_count == 0:
            ol.add_option(Option(Text(self.empty, style=GRAY), disabled=True))
        first = next((i for i in range(ol.option_count) if not ol.get_option_at_index(i).disabled), None)
        ol.highlighted = first

    def _line(self, item: PickItem, label_w: int = 0, detail_w: int = 0) -> Text:
        t = Text()
        t.append(f"{item.label:<{label_w}}", style=WHITE if not item.disabled else GRAY)
        if item.detail or detail_w:
            t.append(f"  {item.detail:<{detail_w}}", style=GRAY)
        if item.tag:
            t.append(f"  {item.tag}", style=GREEN)
        return t

    def action_move(self, delta: int) -> None:
        ol = self.query_one("#pick-list", OptionList)
        enabled = [i for i in range(ol.option_count) if not ol.get_option_at_index(i).disabled]
        if not enabled:
            return
        pos = enabled.index(ol.highlighted) if ol.highlighted in enabled else -1
        ol.highlighted = enabled[max(0, min(len(enabled) - 1, pos + delta))]

    @on(Input.Submitted, "#pick-search")
    def _submit(self, event: Input.Submitted) -> None:
        ol = self.query_one("#pick-list", OptionList)
        if ol.highlighted is not None:
            opt = ol.get_option_at_index(ol.highlighted)
            if opt.id and not opt.disabled:
                self.dismiss(opt.id)
                return
        if self.allow_custom and event.value.strip():
            self.dismiss(event.value.strip())

    @on(OptionList.OptionSelected, "#pick-list")
    def _selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.dismiss(event.option.id)


def command_items() -> list[PickItem]:
    items = []
    for c in commands.COMMANDS:
        items.append(PickItem(c.name, f"/{c.name}", c.help, f"ctrl+x {c.key}" if c.key else ""))
        items += [PickItem(v.text, f"/{v.text}", v.help) for v in commands.VARIANTS
                  if v.text.split()[0] == c.name]
    return items


def model_items(session, first: str | None = None) -> list[PickItem]:
    """Models of every provider that can run right now; `first` (else the active
    provider) is listed first."""
    from ..llm.catalog import PROVIDERS, list_models
    rows = {r["id"]: r for r in session.provider_status()}
    lead = first or session.provider_id
    order = [lead] + [p for p in PROVIDERS if p != lead]
    items: list[PickItem] = []
    for pid in order:
        row = rows.get(pid)
        if not row or not row["connected"]:
            continue
        models = list_models(pid, api_base=row["api_base"])
        if PROVIDERS[pid].api_base and not any(m.tools is None for m in models):
            continue                    # local runtime that isn't running
        for m in models[:300]:
            ctx = f"{m.context // 1000}k" if m.context else ""
            tag = " ".join(t for t in ("free" if m.free else "", "● active" if m.id == session.model else "") if t)
            items.append(PickItem(m.id, m.name, ctx, tag, group=PROVIDERS[pid].label))
    return items


def session_items(session) -> list[PickItem]:
    from datetime import datetime
    items = []
    for s in session.sessions():
        when = datetime.fromtimestamp(s["updated"]).strftime("%b %d %H:%M")
        scope = ", ".join(s["targets"][:2])
        detail = f"{when} · {s['turns']} turns" + (f" · {scope}" if scope else "")
        tag = f"{s['verified']} verified" if s["verified"] else ""
        items.append(PickItem(s["path"], s["title"], detail, tag))
    return items


class ProviderDialog(Dialog):
    TITLE = "Connect provider"

    def __init__(self, provider_id: str, message: str = "") -> None:
        super().__init__()
        self.pid, self.message = provider_id, message

    def compose(self) -> ComposeResult:
        row = next(r for r in self.session.provider_status() if r["id"] == self.pid)
        with Vertical(classes="dialog"):
            yield self.header()
            info = Text()
            info.append(f"{row['label']}\n", style=f"bold {WHITE}")
            info.append(("● connected" if row["connected"] else "○ not connected") + f"  {row['source']}",
                        style=GREEN if row["connected"] else ORANGE)
            if row["key"] != "—":
                info.append(f"  {row['key']}", style=GRAY)
            if row["note"]:
                info.append(f"\n{row['note']}", style=GRAY)
            yield Static(info, id="prov-info")
            yield Input(placeholder="API key — stored encrypted on this machine", password=True, id="prov-key")
            base = Input(value=row["api_base"] or "", placeholder="endpoint / API base (optional)", id="prov-base")
            base.display = bool(row["needs_api_base"] or row["api_base"])
            yield base
            with Horizontal(classes="dialog-buttons"):
                yield Button("Save", id="prov-save", variant="success")
                yield Button("Remove key", id="prov-remove", variant="error")
            yield Static(Text(self.message, style=ORANGE), id="prov-status")

    def on_mount(self) -> None:
        self.query_one("#prov-key", Input).focus()

    @on(Input.Submitted, "#prov-key")
    @on(Button.Pressed, "#prov-save")
    def _save(self) -> None:
        key = self.query_one("#prov-key", Input).value.strip()
        base = self.query_one("#prov-base", Input).value.strip() or None
        if not key and not base:
            self._status("paste a key (or an endpoint) first", ORANGE)
            return
        state = self.session.connect_provider(self.pid, key or None, api_base=base)
        self.query_one("#prov-key", Input).value = ""
        if not state.ok:
            self._status(f"✗ {state.message}", RED)
            return
        self.dismiss(("saved", self.pid))

    @on(Button.Pressed, "#prov-remove")
    def _remove(self) -> None:
        self.session.disconnect_provider(self.pid)
        self.dismiss(("removed", self.pid))

    def _status(self, text: str, color: str) -> None:
        self.query_one("#prov-status", Static).update(Text(text, style=color))


def provider_items(session) -> list[PickItem]:
    return [PickItem(r["id"], r["label"],
                     "connected" if r["connected"] else "", "● active" if r["active"] else "")
            for r in session.provider_status()]


class MCPDialog(Dialog):
    TITLE = "MCP servers"
    BINDINGS = [Binding("escape", "close", "close"), Binding("enter", "toggle", "connect/disconnect"),
                Binding("a", "add", "add"), Binding("p", "presets", "presets"),
                Binding("d", "delete", "delete")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield self.header()
            yield OptionList(id="mcp-list")
            yield Static(Text("enter connect/disconnect · p presets · a add custom · d delete", style=FAINT))
            yield Static("", id="mcp-status")

    def on_mount(self) -> None:
        self._reload()
        self.query_one("#mcp-list", OptionList).focus()

    def _reload(self, select: str | None = None) -> None:
        ol = self.query_one("#mcp-list", OptionList)
        ol.clear_options()
        rows = self.session.mcp_status()
        for r in rows:
            t = Text()
            mark, color = ("●", GREEN) if r["connected"] else (("✗", RED) if r["error"] else ("○", GRAY))
            t.append(f"{mark} ", style=color)
            t.append(r["name"], style=f"bold {WHITE}")
            t.append(f"  {r['tools']} tools" if r["connected"] else "  off", style=GRAY)
            t.append("  trusted" if r["trusted"] else "  asks first", style=FAINT)
            t.append(f"\n    {r['command'][:80]}", style=FAINT)
            if r["error"]:
                t.append(f"\n    {r['error'][:100]}", style=RED)
            ol.add_option(Option(t, id=r["name"]))
        if not rows:
            ol.add_option(Option(Text("no servers yet — press p for presets or a to add one", style=GRAY),
                                 disabled=True))
        names = [r["name"] for r in rows]
        ol.highlighted = names.index(select) if select in names else (0 if rows else None)

    def _current(self) -> str | None:
        ol = self.query_one("#mcp-list", OptionList)
        if ol.highlighted is None:
            return None
        return ol.get_option_at_index(ol.highlighted).id

    def _status(self, text: str, color: str = GRAY) -> None:
        self.query_one("#mcp-status", Static).update(Text(text, style=color))

    def action_toggle(self) -> None:
        name = self._current()
        if not name:
            return
        row = next(r for r in self.session.mcp_status() if r["name"] == name)
        if row["connected"]:
            self.session.disconnect_mcp(name)
            self._after(name, f"{name} disconnected", GRAY)
        else:
            self._status(f"connecting {name}…")
            self._connect(name)

    @work(thread=True, group="mcp")
    def _connect(self, name: str) -> None:
        try:
            tools = self.session.connect_mcp(name)
            msg, color = f"{name}: {len(tools)} tools available to the agent", GREEN
        except Exception as e:
            msg, color = f"{name}: {e}", RED
        self.app.call_from_thread(self._after, name, msg, color)

    def _after(self, name: str, msg: str, color: str) -> None:
        self._reload(select=name)
        self._status(msg, color)
        self.app.refresh_status()

    def action_add(self) -> None:
        def done(entry):
            if entry:
                self.session.add_mcp_server(**entry)
                self._reload(select=entry["name"])
                self._status(f"added {entry['name']} — enter to connect", GREEN)
        self.app.push_screen(AddMCPDialog(), done)

    def action_presets(self) -> None:
        items = [PickItem(p["name"], p["title"], p["description"],
                          "added" if p["added"] else ("" if p["available"] else f"needs {p['requires']}"),
                          disabled=not p["available"])
                 for p in self.session.mcp_presets()]

        def chosen(name):
            if not name:
                return
            try:
                self.session.add_mcp_preset(name)
            except Exception as e:
                self._status(str(e), RED)
                return
            self._reload(select=name)
            self._status(f"connecting {name}…")
            self._connect(name)
        self.app.push_screen(PickerDialog("MCP presets", items, placeholder="search presets"), chosen)

    def action_delete(self) -> None:
        name = self._current()
        if name:
            self.session.remove_mcp_server(name)
            self._reload()
            self._status(f"{name} removed")
            self.app.refresh_status()


class AddMCPDialog(Dialog):
    TITLE = "Add MCP server"

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield self.header()
            yield Input(placeholder="name", id="m-name")
            with RadioSet(id="m-transport"):
                yield RadioButton("stdio (local command)", value=True)
                yield RadioButton("http (streamable)")
                yield RadioButton("sse")
            yield Input(placeholder="command + arguments, e.g. npx -y @modelcontextprotocol/server-filesystem /tmp",
                        id="m-cmd")
            yield Input(placeholder="url, e.g. http://127.0.0.1:8000/mcp", id="m-url")
            yield Input(placeholder="env or headers: KEY=value, KEY2=value", id="m-env")
            yield Checkbox("trusted — run its tools without asking", id="m-trusted")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Add", id="m-add", variant="success")
            yield Static("", id="m-status")

    def on_mount(self) -> None:
        self.query_one("#m-name", Input).focus()

    @on(Button.Pressed, "#m-add")
    def _add(self) -> None:
        name = self.query_one("#m-name", Input).value.strip()
        transport = ("stdio", "http", "sse")[self.query_one("#m-transport", RadioSet).pressed_index or 0]
        pairs = {}
        for pair in self.query_one("#m-env", Input).value.split(","):
            if "=" in pair and pair.split("=", 1)[0].strip():
                k, v = pair.split("=", 1)
                pairs[k.strip()] = v.strip()
        entry = {"name": name, "transport": transport,
                 "trusted": self.query_one("#m-trusted", Checkbox).value}
        try:
            if transport == "stdio":
                parts = shlex.split(self.query_one("#m-cmd", Input).value)
                if not parts:
                    raise ValueError("enter the command")
                entry.update(command=parts[0], args=parts[1:], env=pairs)
            else:
                url = self.query_one("#m-url", Input).value.strip()
                if not url:
                    raise ValueError("enter the url")
                entry.update(url=url, headers=pairs)
            if not name:
                raise ValueError("enter a name")
        except ValueError as e:
            self.query_one("#m-status", Static).update(Text(str(e), style=RED))
            return
        self.dismiss(entry)


class ScopeDialog(Dialog):
    TITLE = "Scope & authorization"

    def compose(self) -> ComposeResult:
        s = self.session
        with Vertical(classes="dialog"):
            yield self.header()
            yield Label("in scope — hosts or URLs, comma-separated", classes="field")
            yield Input(", ".join(s.targets), id="sc-in")
            yield Label("out of scope — never touched", classes="field")
            yield Input(", ".join(s.config.scope.out_of_scope), id="sc-out")
            yield Label("domain", classes="field")
            yield Select([(d, d) for d in ("web", "network", "server", "mobile")],
                         value=s.planner.domain or "web", allow_blank=False, id="sc-domain")
            yield Checkbox("I am authorized to assess the in-scope targets", value=s.authorized, id="sc-auth")
            yield Static(Text("Recorded in the run's tamper-evident audit log.", style=FAINT))
            with Horizontal(classes="dialog-buttons"):
                yield Button("Save", id="sc-save", variant="success")

    def on_mount(self) -> None:
        self.query_one("#sc-in", Input).focus()

    @on(Input.Submitted)
    @on(Button.Pressed, "#sc-save")
    def _save(self) -> None:
        def split(value: str) -> list[str]:
            return [x for x in (p.strip() for p in value.split(",")) if x]
        self.session.set_scope(targets=split(self.query_one("#sc-in", Input).value),
                               out_of_scope=split(self.query_one("#sc-out", Input).value),
                               authorized=self.query_one("#sc-auth", Checkbox).value,
                               domain=str(self.query_one("#sc-domain", Select).value))
        self.dismiss(True)


class ReportDialog(Dialog):
    TITLE = "Report"

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield self.header()
            yield Static(Text("Built from verified findings only.", style=GRAY))
            with Horizontal(classes="checks"):
                yield Checkbox("PDF", value=True, id="r-pdf")
                yield Checkbox("HTML", value=True, id="r-html")
                yield Checkbox("JSON", value=True, id="r-json")
                yield Checkbox("Markdown", value=True, id="r-md")
                yield Checkbox("SARIF", value=False, id="r-sarif")
            with RadioSet(id="r-style"):
                yield RadioButton("technical — full evidence", value=True)
                yield RadioButton("executive — business summary")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Generate", id="r-go", variant="success")
            yield Static("", id="r-out")

    @on(Button.Pressed, "#r-go")
    def _go(self) -> None:
        formats = [f for f, wid in (("pdf", "#r-pdf"), ("html", "#r-html"), ("json", "#r-json"),
                                    ("md", "#r-md"), ("sarif", "#r-sarif")) if self.query_one(wid, Checkbox).value]
        if not formats:
            self._out(Text("pick at least one format", style=ORANGE))
            return
        style = "executive" if self.query_one("#r-style", RadioSet).pressed_index == 1 else "technical"
        self._out(Text("generating…", style=GRAY))
        self._build(formats, style)

    @work(thread=True, group="report")
    def _build(self, formats: list[str], style: str) -> None:
        self.app.call_from_thread(self._show, self.session.generate_report(formats, style))

    def _show(self, results: dict) -> None:
        if "_error" in results:
            self._out(Text(results["_error"], style=ORANGE))
            return
        t = Text()
        for fmt, r in results.items():
            if r.get("ok"):
                t.append(f"✓ {fmt:<5}", style=GREEN)
                t.append(f"{r['path']}\n", style=WHITE)
            else:
                t.append(f"✗ {fmt:<5}", style=RED)
                t.append(f"{r.get('error', '')[:110]}\n", style=GRAY)
        self._out(t)

    def _out(self, renderable) -> None:
        self.query_one("#r-out", Static).update(renderable)


class DetailListDialog(Dialog):
    """A list on top, the highlighted item's detail below."""
    WIDTH = "wide"

    def rows(self) -> list[tuple[str, Text]]:
        raise NotImplementedError

    def detail(self, key: str):
        raise NotImplementedError

    empty = "nothing here yet"

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide tall"):
            yield self.header()
            yield OptionList(id="dl-list")
            with VerticalScroll(id="dl-detail-box"):
                yield Static("", id="dl-detail")

    def on_mount(self) -> None:
        ol = self.query_one("#dl-list", OptionList)
        rows = self.rows()
        for key, line in rows:
            ol.add_option(Option(line, id=key))
        if not rows:
            self.query_one("#dl-detail", Static).update(Text(self.empty, style=GRAY))
        else:
            ol.highlighted = 0
        ol.focus()

    @on(OptionList.OptionHighlighted, "#dl-list")
    def _highlight(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id:
            self.query_one("#dl-detail", Static).update(self.detail(event.option.id))


class FindingsDialog(DetailListDialog):
    TITLE = "Findings"
    empty = "No findings yet. Only safely verified findings reach the report."

    def rows(self):
        self._by_id = {}
        out = []
        for f in sorted(self.session.findings(),
                        key=lambda f: (f.status.value != "verified", -f.severity.cvss_score)):
            self._by_id[f.id] = f
            sev = f.severity.rating.value
            t = Text()
            t.append("✓ " if f.status.value == "verified" else "? ",
                     style=GREEN if f.status.value == "verified" else ORANGE)
            t.append(f"{sev:<9}", style=f"bold {SEV_COLOR.get(sev, GRAY)}")
            t.append(f"{f.severity.cvss_score:<5}", style=GRAY)
            t.append(f.title, style=WHITE)
            t.append(f"  {(f.target.url or f.target.host)[:60]}", style=FAINT)
            out.append((f.id, t))
        return out

    def detail(self, key):
        f = self._by_id[key]
        d = Text()
        d.append(f"{f.title}\n", style=f"bold {WHITE}")
        d.append(f"{f.owasp}  {f.cwe}  ·  {f.severity.cvss_vector}\n\n", style=GRAY)
        for label, value in (("safe proof", f.safe_poc), ("request", f.evidence.request),
                             ("response", (f.evidence.response or "")[:400])):
            if value:
                d.append(f"{label:<12}", style=GREEN)
                d.append(f"{value}\n", style=WHITE if label == "safe proof" else GRAY)
        d.append("\ndetect      ", style="bold #6CB6FF")
        d.append(f"{f.detection_guidance}\n", style=WHITE)
        d.append("fix         ", style="bold #6CB6FF")
        d.append(f"{f.remediation}\n", style=WHITE)
        return d


class MemoryDialog(DetailListDialog):
    TITLE = "Long-term memory"
    empty = "Nothing remembered yet. Each session's findings and summary are saved per target when it ends."

    def rows(self):
        self._data = {d["target"]: d for d in self.session.memory_overview()}
        out = []
        for target, d in self._data.items():
            t = Text()
            t.append(target, style=f"bold {WHITE}")
            open_n = sum(1 for h in d["history"] if h["status"] == "open")
            t.append(f"  {len(d['facts'])} facts · {open_n} open · {len(d['episodes'])} sessions", style=GRAY)
            out.append((target, t))
        return out

    def detail(self, key):
        from datetime import datetime
        d = self._data[key]
        t = Text()
        if d["facts"]:
            t.append("facts\n", style=GREEN)
            for k, v in d["facts"].items():
                t.append(f"  {k}: ", style=GRAY)
                t.append(f"{json.dumps(v, default=str)[:160]}\n", style=WHITE)
        if d["history"]:
            t.append("findings\n", style=GREEN)
            for h in d["history"]:
                t.append(f"  {'open ' if h['status'] == 'open' else 'fixed'}  ",
                         style=ORANGE if h["status"] == "open" else GREEN)
                t.append(f"{h['severity']:<9}{h['title']}\n", style=WHITE)
        if d["episodes"]:
            t.append("sessions\n", style=GREEN)
            for ep in d["episodes"]:
                t.append(f"  {datetime.fromtimestamp(ep['at']):%b %d}  ", style=GRAY)
                t.append(f"{ep['summary'][:300]}\n", style=WHITE)
        return t


class ToolsDialog(DetailListDialog):
    TITLE = "Tools"

    def rows(self):
        self._info = {i["name"]: i for i in self.session.tools_info()}
        out = []
        for i in sorted(self._info.values(), key=lambda i: (i["source"] != "native", i["source"], i["name"])):
            t = Text()
            t.append(i["name"], style=WHITE)
            t.append(f"  {i['source']}", style=GRAY)
            t.append(f"  {i['phase']}", style=FAINT)
            if i["approval"]:
                t.append("  asks first", style=ORANGE)
            out.append((i["name"], t))
        return out

    def detail(self, key):
        return Text(self._info[key]["description"], style=WHITE)


class ContextDialog(Dialog):
    TITLE = "Context & memory"

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield self.header()
            yield Static("", id="ctx-body")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Compact now", id="ctx-compact")

    def on_mount(self) -> None:
        self._draw()

    def _draw(self) -> None:
        st = self.session.context_stats()
        width = 44
        used = min(width, round(st["percent"] / 100 * width))
        bar = Text()
        bar.append("█" * used, style=GREEN if st["percent"] < 70 else ORANGE)
        bar.append("░" * (width - used), style=FAINT)
        bar.append(f"  {st['percent']}% of {st['context_window']:,}", style=GRAY)
        t = Table.grid(padding=(0, 2))
        t.add_column(style=GRAY)
        t.add_column(style=WHITE)
        for k, v in (("model", st["model"]),
                     ("system prompt", f"{st['system_tokens']:,} tokens"),
                     ("conversation", f"{st['history_tokens']:,} tokens · {st['messages']} messages"),
                     ("compacts after", f"{st['compact_at']:,} tokens of conversation"),
                     ("working summary", f"{st['compactions']} compaction(s), {st['folded_messages']} messages folded"
                      if st["compactions"] else "not needed yet"),
                     ("session spend", f"{st['session_tokens']:,} tokens"
                      + (f" · ${st['session_cost']:.4f}" if st["session_cost"] else "")),
                     ("phase", " → ".join(st["phase_path"])),
                     ("long-term memory", "injected for in-scope targets" if st["targets"] else "no targets"),
                     ("secrets kept local", st["secrets_vaulted"]),
                     ("run folder", st["run_dir"])):
            t.add_row(k, str(v))
        self.query_one("#ctx-body", Static).update(Group(bar, Text(""), t))

    @on(Button.Pressed, "#ctx-compact")
    def _compact(self) -> None:
        self.app.action_compact()
        self._draw()


class HelpDialog(Dialog):
    TITLE = "Help"

    def compose(self) -> ComposeResult:
        t = Text()
        t.append("Type to talk to the agent. Commands start with /.\n\n", style=GRAY)
        for c in commands.COMMANDS:
            t.append(f"  /{c.name:<10}", style=f"bold {GREEN}")
            t.append(f"{('ctrl+x ' + c.key) if c.key else '':<10}", style=GRAY)
            t.append(f"{c.help}\n", style=WHITE)
            for v in commands.VARIANTS:
                if v.text.split()[0] == c.name:
                    t.append(f"    /{v.text:<18}", style=GREEN)
                    t.append(f"{v.help}\n", style=GRAY)
        t.append("    /copy N", style=GREEN)
        t.append(" " * 13 + "copy answer number N (shown under each answer)\n", style=GRAY)
        t.append("\n", style=GRAY)
        for k, what in (("tab", "switch autonomous / human-in-the-loop"), ("ctrl+p", "command menu"),
                        ("esc", "interrupt the agent"), ("pgup pgdn", "scroll"),
                        ("mouse drag", "select text in the chat"),
                        ("ctrl+c", "copy the selection · clear the prompt · twice to quit")):
            t.append(f"  {k:<20}", style=f"bold {WHITE}")
            t.append(f"{what}\n", style=GRAY)
        with Vertical(classes="dialog"):
            yield self.header()
            with VerticalScroll(id="help-scroll"):
                yield Static(t)


class ApprovalDialog(ModalScreen[bool]):
    BINDINGS = [Binding("a", "approve", "approve"), Binding("y", "approve", show=False),
                Binding("d", "deny", "decline"), Binding("n", "deny", show=False),
                Binding("escape", "deny", "decline")]

    def __init__(self, tool: str, source: str, args: dict) -> None:
        super().__init__()
        self.tool, self.source, self.args = tool, source, args

    def compose(self) -> ComposeResult:
        body = Text()
        body.append(self.tool, style=f"bold {WHITE}")
        body.append(f"   {self.source}\n\n", style=GRAY)
        body.append(json.dumps(self.args, indent=2, default=str)[:1200], style=WHITE)
        with Vertical(classes="dialog approval"):
            yield Horizontal(Label("Run this tool?", classes="dialog-title"), classes="dialog-header")
            yield Static(body)
            with Horizontal(classes="dialog-buttons"):
                yield Button("Approve  a", id="ap-yes", variant="success")
                yield Button("Decline  d", id="ap-no", variant="error")

    @on(Button.Pressed, "#ap-yes")
    def action_approve(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#ap-no")
    def action_deny(self) -> None:
        self.dismiss(False)
