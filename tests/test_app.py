"""The `autopwnai` terminal app, driven like an operator would drive it, on top of
a real EngineSession with a scripted LLM."""
from __future__ import annotations

import json

import pytest
from conftest import ScriptedLLM, call, say
from textual.widgets import Checkbox, Input, OptionList, Select

from autopwn.core.findings import Status
from autopwn.detect.model import Candidate
from autopwn.govern import AuditLog
from autopwn.llm.provider import LLMError, MissingAPIKey
from autopwn.settings import Settings
from autopwn.tui import commands
from autopwn.tui.app import AutoPwnApp, LeaderDialog
from autopwn.tui.dialogs import (
    AddMCPDialog,
    ApprovalDialog,
    ContextDialog,
    FindingsDialog,
    HelpDialog,
    MCPDialog,
    MemoryDialog,
    PickerDialog,
    ProviderDialog,
    ReportDialog,
    ScopeDialog,
    ToolsDialog,
    fuzzy_score,
)
from autopwn.tui.main import MainScreen
from autopwn.tui.messages import FindingLine, ToolLine

SIZE = (140, 42)


async def wait_for(pilot, cond, timeout: float = 8.0) -> bool:
    for _ in range(int(timeout / 0.05)):
        if cond():
            return True
        await pilot.pause(0.05)
    return cond()


async def ready(pilot, app) -> None:
    await wait_for(pilot, lambda: app.main is not None and app.main.is_mounted and app.provider_ok)


async def send(pilot, app, text: str) -> None:
    app.main.prompt.value = text
    await pilot.press("enter")


async def opened(pilot, app, cls) -> object:
    assert await wait_for(pilot, lambda: isinstance(app.screen, cls) and app.screen.is_mounted
                          and bool(app.screen.query(".dialog, .leader")))
    await pilot.pause(0.05)
    return app.screen


def roles(app) -> list[str]:
    return [r for r, _ in app.main.history]


def plain(widget) -> str:
    """Text of a Static, whatever renderable it holds."""
    from rich.console import Console
    content = widget.content
    if isinstance(content, str):
        return content
    console = Console(width=160, record=True, color_system=None)
    console.print(content)
    return console.export_text()


def said(app, role: str | None = None) -> str:
    return "\n".join(t for r, t in app.main.history if role is None or r == role)


async def turn_done(pilot, app, timeout: float = 10.0) -> bool:
    return await wait_for(pilot, lambda: not app.session.busy and app.main._working is None, timeout)


@pytest.fixture
def app_with(make_session):
    def build(llm=None, **kw):
        llm = llm or ScriptedLLM()
        return AutoPwnApp(session_factory=lambda resume=None: make_session(llm, resume=resume, **kw))
    return build


# ── startup & home ────────────────────────────────────────────────────────────
async def test_starts_on_home(app_with):
    app = app_with(targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        assert isinstance(app.screen, MainScreen)
        assert app.main.query_one("#home").display and not app.main.messages.display
        assert app.main.prompt.has_focus


async def test_unready_provider_opens_the_provider_picker(app_with):
    app = app_with(ScriptedLLM(ready_error=MissingAPIKey("no API key for anthropic")))
    async with app.run_test(size=SIZE) as pilot:
        screen = await opened(pilot, app, PickerDialog)
        assert screen.TITLE == "Providers"
        assert "no API key" in said(app, "error") and app.provider_ok is False


async def test_fatal_screen_when_the_session_cannot_start():
    def broken():
        raise RuntimeError("cannot read config")
    app = AutoPwnApp(session_factory=broken)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.2)
        assert app.screen.__class__.__name__ == "FatalScreen"


# ── conversation ──────────────────────────────────────────────────────────────
async def test_turn_shows_narration_tools_and_answer(app_with):
    llm = ScriptedLLM([call("recall_target", content="checking memory first", host="app.lab"),
                       say("**first assessment** of `app.lab`")])
    app = app_with(llm, targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "what do you know about app.lab?")
        assert await turn_done(pilot, app)
        assert roles(app)[:4] == ["user", "narration", "tool", "agent"]
        line = app.main.query(ToolLine).first()
        assert line.tool == "recall_target" and line.state == "ok"
        assert "first assessment" in said(app, "agent")
        assert not app.main.query_one("#home").display and app.main.messages.display
        assert app.session.title == "what do you know about app.lab?"


async def test_failed_tool_is_marked(app_with):
    app = app_with(ScriptedLLM([call("web_recon"), say("done")]))           # missing url → fails
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "recon")
        assert await turn_done(pilot, app)
        assert app.main.query(ToolLine).first().state == "error"


async def test_provider_error_is_shown_not_raised(app_with):
    app = app_with(ScriptedLLM([LLMError("rate limited by the provider")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "hi")
        assert await wait_for(pilot, lambda: "rate limited" in said(app, "error"))
        assert isinstance(app.screen, MainScreen)


async def test_escape_interrupts(app_with):
    llm = ScriptedLLM([call("recall_target", cid=f"c{i}", host="x") for i in range(40)], delay=0.15)
    app = app_with(llm)
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "go deep")
        assert await wait_for(pilot, lambda: app.session.busy)
        await pilot.press("escape")
        assert await wait_for(pilot, lambda: "interrupted" in said(app), timeout=12)
        assert not app.session.busy


async def test_message_while_busy_is_refused(app_with):
    llm = ScriptedLLM([call("recall_target", cid=f"c{i}", host="x") for i in range(10)], delay=0.15)
    app = app_with(llm)
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "first")
        await wait_for(pilot, lambda: app.session.busy)
        await send(pilot, app, "second")
        assert roles(app).count("user") == 1
        await pilot.press("escape")
        await turn_done(pilot, app, timeout=12)


async def test_verified_finding_is_announced(app_with):
    app = app_with(targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        f = app.session.pipeline.add(Candidate("sqli", host="app.lab", url="http://app.lab/x", param="id"))
        f.status = Status.VERIFIED
        app.main.on_engine({"kind": "verify", "verified": True, "finding": f.id, "method": "boolean"})
        await pilot.pause(0.1)
        assert len(app.main.query(FindingLine)) == 1
        assert "◆ 1" in plain(app.main.query_one("#status"))


# ── commands, completion, menu, leader ────────────────────────────────────────
@pytest.mark.parametrize("cmd,cls", [
    ("/tools", ToolsDialog), ("/context", ContextDialog), ("/scope", ScopeDialog),
    ("/findings", FindingsDialog), ("/report", ReportDialog), ("/memory", MemoryDialog),
    ("/mcp", MCPDialog), ("/help", HelpDialog), ("/model", PickerDialog), ("/provider", PickerDialog),
    ("/sessions", PickerDialog), ("/connect", PickerDialog),
])
async def test_commands_open_their_dialogs(app_with, cmd, cls):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, cmd)
        await opened(pilot, app, cls)
        await pilot.press("escape")
        assert await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))


async def test_unknown_command(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/frobnicate")
        assert "unknown command /frobnicate" in said(app, "error")


async def test_slash_completion(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        app.main.prompt.value = "/ses"
        await pilot.pause(0.1)
        complete = app.main.query_one("#complete", OptionList)
        assert complete.display and complete.get_option_at_index(0).id == "sessions"
        await pilot.press("tab")
        assert app.main.prompt.value == "/sessions" and not complete.display
        app.main.prompt.value = "/mo"
        await pilot.pause(0.1)
        await pilot.press("enter")                       # enter on a suggestion runs it (like OpenCode)
        picker = await opened(pilot, app, PickerDialog)
        assert picker.TITLE == "Models" and app.main.prompt.value == ""


async def test_tab_toggles_mode(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await pilot.press("tab")
        assert app.session.mode == "hitl" and "HITL" in plain(app.main.query_one("#status"))
        await pilot.press("tab")
        assert app.session.mode == "autonomous"


async def test_mode_command_with_argument(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/mode hitl")
        assert app.session.mode == "hitl"


async def test_command_menu_runs_a_command(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await pilot.press("ctrl+p")
        menu = await opened(pilot, app, PickerDialog)
        assert menu.query_one("#pick-list", OptionList).option_count == len(commands.COMMANDS) + len(commands.VARIANTS)
        menu.query_one("#pick-search", Input).value = "tools"
        await pilot.pause(0.1)
        await pilot.press("enter")
        await opened(pilot, app, ToolsDialog)


async def test_leader_shortcuts(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await pilot.press("ctrl+x")
        await opened(pilot, app, LeaderDialog)
        await pilot.press("f")
        await opened(pilot, app, FindingsDialog)


def test_command_table():
    cmd, arg = commands.parse("/model openai/gpt-4.1")
    assert cmd.name == "model" and arg == "openai/gpt-4.1"
    assert commands.parse("/exit")[0].name == "quit" and commands.parse("hi") is None
    assert [c.name for c in commands.matches("/m")][:3] == ["model", "mcp", "mode"]
    assert len({c.key for c in commands.COMMANDS if c.key}) == len([c for c in commands.COMMANDS if c.key])


def test_fuzzy_score():
    assert fuzzy_score("son", "claude-sonnet-4-5") > fuzzy_score("son", "s-o-n")
    assert fuzzy_score("xyz", "claude") == 0 and fuzzy_score("", "a") == 1


# ── model & provider ──────────────────────────────────────────────────────────
async def test_model_picker_lists_connected_providers_and_switches(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        app.session.creds.set("openai", "sk-openai-test-123456")
        await send(pilot, app, "/model")
        picker = await opened(pilot, app, PickerDialog)
        ol = picker.query_one("#pick-list", OptionList)
        assert await wait_for(pilot, lambda: ol.option_count > 5)
        ids = [ol.get_option_at_index(i).id for i in range(ol.option_count)]
        assert any(i and i.startswith("openai/") for i in ids)
        picker.query_one("#pick-search", Input).value = "gpt-4.1-mini"
        await pilot.pause(0.2)
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: app.session.model.startswith("openai/gpt-4.1-mini"))


async def test_model_command_with_argument(app_with, tmp_path):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/model ollama/llama3.1")
        assert await wait_for(pilot, lambda: "model ollama/llama3.1" in said(app))
        assert Settings.load(tmp_path / "settings.json").model == "ollama/llama3.1"


async def test_provider_flow_stores_key_then_offers_models(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/provider")
        picker = await opened(pilot, app, PickerDialog)
        picker.query_one("#pick-search", Input).value = "openai"
        await pilot.pause(0.1)
        await pilot.press("enter")
        dialog = await opened(pilot, app, ProviderDialog)
        assert dialog.pid == "openai"
        dialog.query_one("#prov-key", Input).value = "sk-openai-test-abcdef1234"
        await pilot.press("enter")
        picker = await opened(pilot, app, PickerDialog)
        assert picker.TITLE == "Models"
        assert app.session.creds.get("openai") == "sk-openai-test-abcdef1234"


# ── scope / approvals ─────────────────────────────────────────────────────────
async def test_scope_dialog(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/scope")
        d = await opened(pilot, app, ScopeDialog)
        d.query_one("#sc-in", Input).value = "juice.lab, api.juice.lab"
        d.query_one("#sc-out", Input).value = "prod.juice.lab"
        d.query_one("#sc-domain", Select).value = "network"
        d.query_one("#sc-auth", Checkbox).value = True
        d.query_one("#sc-save").press()
        assert await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        s = app.session
        assert s.targets == ["juice.lab", "api.juice.lab"] and s.authorized
        assert s.config.scope.out_of_scope == ["prod.juice.lab"] and s.planner.domain == "network"


@pytest.mark.parametrize("key,declined", [("a", False), ("d", True)])
async def test_hitl_approval(app_with, key, declined):
    app = app_with(ScriptedLLM([call("recall_target", host="x"), say("done")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        app.session.set_mode("hitl")
        await send(pilot, app, "recall")
        dialog = await opened(pilot, app, ApprovalDialog)
        assert dialog.tool == "recall_target"
        await pilot.press(key)
        assert await turn_done(pilot, app)
        tool_msg = next(m.content for m in app.session.agent.conversation.messages if m.role == "tool")
        assert ('"declined": true' in tool_msg) is declined


async def test_viewer_cannot_approve(app_with):
    app = app_with(ScriptedLLM([call("recall_target", host="x"), say("done")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        for _ in range(3):
            await pilot.press("f3")
        assert app.role == "Viewer"
        app.session.set_mode("hitl")
        await send(pilot, app, "recall")
        assert await turn_done(pilot, app)
        assert not any(isinstance(s, ApprovalDialog) for s in app.screen_stack)
        assert "declined" in said(app)


# ── MCP ───────────────────────────────────────────────────────────────────────
async def test_mcp_add_custom_server(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/mcp")
        await opened(pilot, app, MCPDialog)
        await pilot.press("a")
        d = await opened(pilot, app, AddMCPDialog)
        d.query_one("#m-name", Input).value = "fs"
        d.query_one("#m-cmd", Input).value = 'npx -y "@modelcontextprotocol/server-filesystem" /tmp'
        d.query_one("#m-env", Input).value = "A=1, B=two"
        d.query_one("#m-add").press()
        await opened(pilot, app, MCPDialog)
        entry = app.session.settings.mcp_servers[0]
        assert entry["command"] == "npx"
        assert entry["args"] == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        assert entry["env"] == {"A": "1", "B": "two"} and entry["transport"] == "stdio"


async def test_mcp_add_http_server(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/mcp")
        await opened(pilot, app, MCPDialog)
        await pilot.press("a")
        d = await opened(pilot, app, AddMCPDialog)
        d.query_one("#m-name", Input).value = "remote"
        d.query("#m-transport RadioButton")[1].value = True
        d.query_one("#m-url", Input).value = "http://127.0.0.1:9/mcp"
        d.query_one("#m-env", Input).value = "Authorization=Bearer x"
        await pilot.pause(0.05)
        d.query_one("#m-add").press()
        await opened(pilot, app, MCPDialog)
        entry = app.session.settings.mcp_servers[0]
        assert entry["transport"] == "http" and entry["headers"] == {"Authorization": "Bearer x"}


async def test_mcp_presets_list(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/mcp")
        await opened(pilot, app, MCPDialog)
        await pilot.press("p")
        picker = await opened(pilot, app, PickerDialog)
        ol = picker.query_one("#pick-list", OptionList)
        ids = [ol.get_option_at_index(i).id for i in range(ol.option_count)]
        assert {"fetch", "filesystem", "browser", "git"} <= set(ids)


# ── findings / report / memory / context / tools ──────────────────────────────
def _verified(session):
    f = session.pipeline.add(Candidate("sqli", host="app.lab", url="http://app.lab/item?id=1",
                                       param="id", note="boolean differential confirmed"))
    f.status = Status.VERIFIED
    return f


async def test_findings_dialog_detail(app_with):
    app = app_with(targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        _verified(app.session)
        await send(pilot, app, "/findings")
        d = await opened(pilot, app, FindingsDialog)
        detail = d.query_one("#dl-detail")
        assert await wait_for(pilot, lambda: "parameterized" in plain(detail))


async def test_report_dialog(app_with):
    app = app_with(targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        _verified(app.session)
        await send(pilot, app, "/report")
        d = await opened(pilot, app, ReportDialog)
        d.query_one("#r-pdf", Checkbox).value = False
        d.query_one("#r-go").press()
        out = d.query_one("#r-out")
        assert await wait_for(pilot, lambda: "✓ json" in plain(out), timeout=12)


async def test_memory_dialog(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        app.session.memory.remember("app.lab", "stack", {"server": "nginx"})
        app.session.memory.add_episode("app.lab", "mapped the login form")
        await send(pilot, app, "/memory")
        d = await opened(pilot, app, MemoryDialog)
        detail = d.query_one("#dl-detail")
        assert await wait_for(pilot, lambda: "nginx" in plain(detail)
                              and "mapped the login form" in plain(detail))


async def test_context_dialog_and_compact(app_with):
    app = app_with(ScriptedLLM([say(f"answer {i}") for i in range(10)]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        for i in range(3):
            await send(pilot, app, f"message {i}")
            await turn_done(pilot, app)
        await send(pilot, app, "/compact")
        assert app.session.agent.conversation.compactions == 1
        await send(pilot, app, "/context")
        d = await opened(pilot, app, ContextDialog)
        assert "1 compaction" in plain(d.query_one("#ctx-body"))


async def test_tools_dialog_lists_native_tools(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "/tools")
        d = await opened(pilot, app, ToolsDialog)
        assert d.query_one("#dl-list", OptionList).option_count == len(app.session.registry)


# ── sessions ──────────────────────────────────────────────────────────────────
async def test_export(app_with):
    app = app_with(ScriptedLLM([say("hello operator")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "hello")
        await turn_done(pilot, app)
        await send(pilot, app, "/export")
        picker = await opened(pilot, app, PickerDialog)
        assert picker.TITLE == "Export chat"
        await pilot.press("enter")
        exports = app.session.ctx.run_dir / "exports"
        assert await wait_for(pilot, lambda: list(exports.glob("chat-*.txt")))
        text = next(exports.glob("chat-*.txt")).read_text()
        assert "[1] YOU" in text and "hello operator" in text and "**" not in text
        await send(pilot, app, "/export md")
        assert await wait_for(pilot, lambda: list(exports.glob("chat-*.md")))
        await send(pilot, app, "/export html clean")
        assert await wait_for(pilot, lambda: list((app.session.ctx.run_dir / "exports").glob("chat-*.html")))
        assert "chat exported" in said(app)


async def test_new_session_and_resume(app_with):
    app = app_with(ScriptedLLM([say("first answer"), say("again")]), targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "map app.lab")
        await turn_done(pilot, app)
        first = app.session
        await send(pilot, app, "/new")
        assert app.session is not first and first._closed
        assert not [r for r in roles(app) if r in ("user", "agent")]
        assert "previous session saved" in said(app)
        await send(pilot, app, "/sessions")
        picker = await opened(pilot, app, PickerDialog)
        assert picker.query_one("#pick-list", OptionList).option_count == 1
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: app.session.title == "map app.lab")
        assert "map app.lab" in said(app, "user") and "first answer" in said(app, "agent")
        await send(pilot, app, "continue")
        assert await turn_done(pilot, app)
        assert app.session.turns == 2


async def test_quit_saves(app_with):
    app = app_with(ScriptedLLM([say("ok")]), targets=["app.lab"])
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "hi")
        await turn_done(pilot, app)
        session = app.session
        await pilot.press("ctrl+c")
        assert not session._closed                       # first press only arms quit
        await pilot.press("ctrl+c")
    assert session._closed
    assert AuditLog.verify(session.ctx.run_dir / "audit.jsonl")
    actions = [json.loads(line)["action"] for line in
               (session.ctx.run_dir / "audit.jsonl").read_text().splitlines()]
    assert actions[0] == "authorization" and actions[-1] == "session.finish"
    assert (session.ctx.run_dir / "session.json").is_file()


# ── copy ──────────────────────────────────────────────────────────────────────
async def test_copy_last_answer_and_whole_chat(app_with):
    app = app_with(ScriptedLLM([say("**the** answer")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "a question")
        await turn_done(pilot, app)
        await send(pilot, app, "/copy")
        assert app.clipboard == "**the** answer"
        await send(pilot, app, "/copy all")
        assert "a question" in app.clipboard and "the answer" in app.clipboard and "**" not in app.clipboard


async def test_answers_are_selectable_text(app_with):
    from textual.selection import Selection

    from autopwn.tui.messages import AssistantMessage
    app = app_with(ScriptedLLM([say("## Title\n\n- one **bold** point")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "q")
        await turn_done(pilot, app)
        msg = app.main.query(AssistantMessage).last()
        assert await wait_for(pilot, lambda: msg._width > 0)
        text, _ = msg.get_selection(Selection(None, None))
        assert "Title" in text and "one bold point" in text and "**" not in text
        app.screen.selections = {msg: Selection(None, None)}
        await pilot.press("ctrl+c")
        assert "one bold point" in app.clipboard and not app.session._closed


async def test_ctrl_c_clears_the_prompt_before_quitting(app_with):
    app = app_with()
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        app.main.prompt.value = "draft"
        await pilot.press("ctrl+c")
        assert app.main.prompt.value == "" and not app.session._closed


async def test_copy_and_export_variants_in_autocomplete(app_with):
    app = app_with(ScriptedLLM([say("first"), say("second")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "one")
        await turn_done(pilot, app)
        await send(pilot, app, "two")
        await turn_done(pilot, app)
        ol = app.main.query_one("#complete", OptionList)

        app.main.prompt.value = "/cop"
        await pilot.pause(0.1)
        ids = [ol.get_option_at_index(i).id for i in range(ol.option_count)]
        assert ids[:2] == ["copy", "copy all"]

        app.main.prompt.value = "/export "
        await pilot.pause(0.1)
        ids = [ol.get_option_at_index(i).id for i in range(ol.option_count)]
        assert {"export txt", "export md", "export html"} <= set(ids)

        app.main.prompt.value = "/export h"
        await pilot.pause(0.1)
        await pilot.press("enter")
        exports = app.session.ctx.run_dir / "exports"
        assert await wait_for(pilot, lambda: list(exports.glob("chat-*.html")))

        await send(pilot, app, "/copy 1")
        assert app.clipboard == "first"
        await send(pilot, app, "/copy 9")
        assert "no answer #9" in said(app)


async def test_command_menu_runs_variants(app_with):
    app = app_with(ScriptedLLM([say("the answer")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        await send(pilot, app, "q")
        await turn_done(pilot, app)
        await pilot.press("ctrl+p")
        menu = await opened(pilot, app, PickerDialog)
        menu.query_one(Input).value = "copy all"
        await pilot.pause(0.2)
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: "the answer" in (app.clipboard or ""))
        assert "q" in app.clipboard


async def test_answer_footer_shows_its_copy_command(app_with):
    from autopwn.tui.messages import AssistantMessage
    app = app_with(ScriptedLLM([say("a"), say("b")]))
    async with app.run_test(size=SIZE) as pilot:
        await ready(pilot, app)
        for q in ("x", "y"):
            await send(pilot, app, q)
            await turn_done(pilot, app)
        footers = [m.footer for m in app.main.query(AssistantMessage)]
        assert footers[0].endswith("/copy 1") and footers[1].endswith("/copy 2")
