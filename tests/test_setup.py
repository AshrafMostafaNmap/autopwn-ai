"""First-run setup: the wizard, the machine scan and key verification."""
from __future__ import annotations

import httpx
from conftest import ScriptedLLM
from textual.widgets import Checkbox, Input, OptionList, SelectionList

import autopwn.tui.setup as setup_mod
from autopwn.llm.keycheck import check_key
from autopwn.onboarding import ProviderScan, Scan, ToolScan, scan
from autopwn.settings import Settings
from autopwn.tui.app import AutoPwnApp
from autopwn.tui.main import MainScreen
from autopwn.tui.setup import SetupScreen

SIZE = (120, 40)


async def _wait(pilot, cond, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if cond():
            return True
        await pilot.pause(0.05)
    return cond()


async def _click(pilot, selector):
    await pilot.pause(0.3)                 # two quick clicks would read as a double-click
    await pilot.click(selector)
    await pilot.pause(0.05)


def _fake_scan(stored=None, api_bases=None):
    return Scan(providers=[ProviderScan("openai", "OpenAI"), ProviderScan("anthropic", "Anthropic"),
                           ProviderScan("ollama", "Ollama (local)", found="running at http://localhost:11434",
                                        needs_key=False)],
                tools=[ToolScan("nmap", "ports", "/usr/bin/nmap"), ToolScan("nuclei", "templates", None, "go install")],
                launchers={"uvx": True, "npx": False})


def _app(make_session, tmp_path, monkeypatch, checks):
    monkeypatch.setattr(setup_mod, "scan", _fake_scan)

    def fake_check(pid, key, base=None):
        from autopwn.llm.keycheck import KeyCheck
        checks.append((pid, key))
        return KeyCheck(key == "sk-good", key == "sk-good", "OpenAI key works" if key == "sk-good" else "rejected")
    monkeypatch.setattr(setup_mod, "check_key", fake_check)
    return AutoPwnApp(session_factory=lambda resume=None: make_session(ScriptedLLM(), first_run=True))


async def test_first_run_walks_through_setup(make_session, tmp_path, monkeypatch):
    checks: list = []
    app = _app(make_session, tmp_path, monkeypatch, checks)
    async with app.run_test(size=SIZE) as pilot:
        assert await _wait(pilot, lambda: isinstance(app.screen, SetupScreen))
        wiz = app.screen

        await _click(pilot, "#nav-next")                         # terms not accepted yet
        assert wiz.current == "welcome"
        wiz.query_one("#terms", Checkbox).value = True
        wiz.query_one("#operator", Input).value = "blue team"
        await _click(pilot, "#nav-next")
        assert wiz.current == "providers"

        sl = wiz.query_one("#prov-list", SelectionList)
        assert await _wait(pilot, lambda: sl.option_count == 3)
        assert "ollama" in sl.selected                         # already usable → ticked
        sl.select("openai")
        await _click(pilot, "#nav-next")
        assert wiz.current == "keys" and wiz.key_queue == ["openai"]

        wiz.query_one("#key-input", Input).value = "sk-bad"
        await _click(pilot, "#key-save")
        assert await _wait(pilot, lambda: not wiz._busy)
        assert wiz.current == "keys" and "openai" not in wiz.connected
        wiz.query_one("#key-input", Input).value = "sk-good"
        await _click(pilot, "#key-save")
        assert await _wait(pilot, lambda: wiz.current == "model")
        assert app.session.creds.get("openai") == "sk-good"

        ol = wiz.query_one("#model-list", OptionList)
        assert await _wait(pilot, lambda: ol.option_count > 1)
        ids = [ol.get_option_at_index(i).id for i in range(ol.option_count)]
        assert "openai/gpt-5.5" in ids
        ol.highlighted = ids.index("openai/gpt-5.5")
        await _click(pilot, "#nav-next")
        assert wiz.current == "prefs"
        assert "fetch" in wiz.query_one("#mcp-pick", SelectionList).selected
        assert "browser" not in [wiz.query_one("#mcp-pick", SelectionList).get_option_at_index(i).value
                                 for i in range(wiz.query_one("#mcp-pick", SelectionList).option_count)]
        await _click(pilot, "#nav-next")
        assert wiz.current == "done"
        await _click(pilot, "#nav-next")
        assert await _wait(pilot, lambda: isinstance(app.screen, MainScreen))

        s = app.session.settings
        assert s.setup_done and s.operator == "blue team" and s.mode == "hitl"
        assert s.terms_accepted.startswith("1@")
        assert app.session.model == "openai/gpt-5.5"
        assert {c["name"] for c in s.mcp_servers} >= {"fetch"}
        assert checks == [("openai", "sk-bad"), ("openai", "sk-good")]
        assert Settings.load(s._path).setup_done


async def test_setup_not_shown_again_and_reopens_with_command(make_session, monkeypatch):
    monkeypatch.setattr(setup_mod, "scan", _fake_scan)
    app = AutoPwnApp(session_factory=lambda resume=None: make_session(ScriptedLLM()))
    async with app.run_test(size=SIZE) as pilot:
        assert await _wait(pilot, lambda: isinstance(app.screen, MainScreen))
        await pilot.pause(0.3)
        assert not isinstance(app.screen, SetupScreen)
        app.main.prompt.value = "/setup"
        await pilot.press("enter")
        assert await _wait(pilot, lambda: isinstance(app.screen, SetupScreen))
        assert app.screen.rerun
        await pilot.press("escape")                            # back on step 0 does nothing
        assert isinstance(app.screen, SetupScreen)


async def test_forced_setup_from_cli_flag(make_session, monkeypatch):
    monkeypatch.setattr(setup_mod, "scan", _fake_scan)
    app = AutoPwnApp(session_factory=lambda resume=None: make_session(ScriptedLLM()), setup=True)
    async with app.run_test(size=SIZE) as pilot:
        assert await _wait(pilot, lambda: isinstance(app.screen, SetupScreen))


def _client(status, body=""):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["headers"] = str(request.url), dict(request.headers)
        return httpx.Response(status, text=body)
    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_key_check_outcomes():
    client, seen = _client(200, "{}")
    r = check_key("anthropic", "sk-ant-x", client=client)
    assert r.ok and r.verified
    assert seen["headers"]["x-api-key"] == "sk-ant-x" and "sk-ant-x" not in seen["url"]

    client, seen = _client(200)
    check_key("gemini", "AIza-x", client=client)
    assert seen["headers"]["x-goog-api-key"] == "AIza-x" and "AIza" not in seen["url"]

    assert not check_key("openai", "bad", client=_client(401)[0]).ok
    assert not check_key("xai", "bad", client=_client(400, '{"error":"Incorrect API key"}')[0]).ok
    r = check_key("groq", "k", client=_client(429)[0])
    assert r.ok and r.verified
    r = check_key("mistral", "k", client=_client(503)[0])
    assert r.ok and not r.verified
    assert not check_key("openai", None).ok
    assert not check_key("openai_compatible", None).ok
    assert check_key("azure", "k", "https://x.openai.azure.com").ok


def test_scan_reports_providers_and_tools(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    sc = scan({"anthropic"}, {})
    found = {p.id: p.found for p in sc.providers}
    assert found["anthropic"] == "key saved" and found["groq"] == "$GROQ_API_KEY found"
    assert found["openai_compatible"] == ""                 # never borrows the OpenAI key
    assert {t.name for t in sc.tools} >= {"nmap", "nuclei", "playwright"}
    assert all(t.install for t in sc.tools if not t.path)
