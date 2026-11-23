"""Engine-layer tests: settings & credentials, the model catalog, EngineSession,
the agent-loop fixes, thread safety, a real MCP server, and the CLI.

Each test documents a concrete defect that existed before the restructure (cross-
thread SQLite crash, dotted MCP tool names, unanswered tool_call_ids, budget
starvation, swallowed MCP errors, …) so a regression is caught by name.
"""
from __future__ import annotations

import json
import stat
import sys
import threading
from pathlib import Path

import pytest
from conftest import ScriptedLLM, call, say
from cryptography.fernet import Fernet

from autopwn.agent import Agent, ApprovalDecision, ApprovalGate, Budget, Mode, ToolRegistry
from autopwn.agent.tools import ToolResult
from autopwn.config import Config, LLMConfig, load_config
from autopwn.core.findings import Status
from autopwn.core.logging import EventLogger
from autopwn.core.store import StateStore
from autopwn.detect.model import Candidate
from autopwn.govern import AuditLog, Redactor, Vault
from autopwn.llm import catalog
from autopwn.llm.provider import LLMError, LLMProvider, MissingAPIKey
from autopwn.memory import TargetMemory
from autopwn.settings import CredentialStore, Settings, mask


def test_settings_roundtrip_and_mcp_entries(tmp_path):
    s = Settings.load(tmp_path / "s.json")
    s.model = "openai/gpt-4.1"
    s.api_bases["ollama"] = "http://10.0.0.5:11434"
    s.upsert_mcp({"name": "fs", "command": "npx", "args": ["-y", "x"]})
    s.upsert_mcp({"name": "fs", "command": "uvx", "args": []})      # same name replaces
    s.save()
    again = Settings.load(tmp_path / "s.json")
    assert again.model == "openai/gpt-4.1"
    assert again.api_bases["ollama"] == "http://10.0.0.5:11434"
    assert [m["command"] for m in again.mcp_servers] == ["uvx"]
    assert again.remove_mcp("fs") and not again.mcp_servers


def test_settings_corrupt_file_never_blocks_startup(tmp_path):
    (tmp_path / "s.json").write_text("{not json")
    assert Settings.load(tmp_path / "s.json").model is None


def test_settings_file_is_private(tmp_path):
    s = Settings.load(tmp_path / "d" / "s.json")
    s.save()
    assert stat.S_IMODE((tmp_path / "d" / "s.json").stat().st_mode) == 0o600


def test_credentials_encrypted_and_private(tmp_path):
    store = CredentialStore(tmp_path / "c")
    store.set("anthropic", "sk-ant-SECRET-123456")
    raw = (tmp_path / "c" / "credentials.enc").read_bytes()
    assert b"SECRET" not in raw                                   # encrypted at rest
    assert stat.S_IMODE((tmp_path / "c" / "credentials.enc").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "c" / "credentials.key").stat().st_mode) == 0o600
    assert CredentialStore(tmp_path / "c").get("anthropic") == "sk-ant-SECRET-123456"  # key reused
    assert store.providers() == ["anthropic"]
    assert store.delete("anthropic") and store.get("anthropic") is None


def test_credentials_wrong_key_fails_closed(tmp_path):
    CredentialStore(tmp_path / "c", key=Fernet.generate_key()).set("openai", "sk-1234567890")
    other = CredentialStore(tmp_path / "c", key=Fernet.generate_key())
    assert other.get("openai") is None                            # no crash, no key


def test_credentials_reject_empty(tmp_path):
    with pytest.raises(ValueError):
        CredentialStore(tmp_path / "c").set("openai", "   ")


def test_mask_never_reveals_a_usable_key():
    assert mask("sk-ant-abcdefghijklmnop") == "sk-…mnop"
    assert mask("short") == "•••••"
    assert mask(None) == "—"


def test_catalog_lists_only_tool_capable_models():
    models = catalog.list_models("anthropic")
    assert models and all(m.id.startswith("anthropic/") for m in models)
    assert all(m.tools for m in models if not m.featured)
    assert models[0].featured                                     # featured first


def test_catalog_unknown_provider_is_empty():
    assert catalog.list_models("nope") == []


def test_catalog_local_runtime_unreachable_falls_back(monkeypatch):
    # nothing listens on this port → live query fails → catalog entries returned
    models = catalog.list_models("ollama", api_base="http://127.0.0.1:9")
    assert all(m.provider == "ollama" for m in models)


def test_catalog_helpers():
    assert catalog.provider_requires_key("anthropic") is True
    assert catalog.provider_requires_key("ollama") is False
    assert catalog.litellm_model("openai_compatible/my-model") == "openai/my-model"
    assert catalog.model_info("anthropic/claude-sonnet-4-5")["max_input_tokens"] > 0
    assert catalog.model_info("anthropic/definitely-not-a-model") is None


def test_provider_missing_key_message_points_to_the_app(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(MissingAPIKey) as e:
        LLMProvider(LLMConfig()).ensure_ready()
    assert "/provider" in str(e.value)


def test_local_provider_needs_no_key():
    p = LLMProvider(LLMConfig(model="ollama/llama3.1", api_key_env="", require_tool_calling=False))
    assert p.ensure_ready() == []


def test_config_parses_mcp_servers(tmp_path):
    (tmp_path / "config.toml").write_text(
        '[[mcp.servers]]\nname = "fs"\ncommand = "npx"\nargs = ["-y", "server"]\ntrusted = true\n')
    cfg = load_config(tmp_path / "config.toml")
    assert cfg.mcp_servers == [{"name": "fs", "command": "npx", "args": ["-y", "server"], "trusted": True}]


def test_config_rejects_incomplete_mcp_server(tmp_path):
    from autopwn.config import ConfigError
    (tmp_path / "config.toml").write_text('[[mcp.servers]]\nname = "fs"\n')
    with pytest.raises(ConfigError):
        load_config(tmp_path / "config.toml")


def test_state_store_usable_across_threads(tmp_path):
    store = StateStore.open(tmp_path / "s.db")
    errors = []

    def work(i):
        try:
            store.record_run(f"r{i}", goal="g", targets=[], profile="safe", model="m")
            store.remember("h", f"k{i}", i)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    assert len(store.recall("h")) == 16
    store.close()


def test_target_memory_usable_across_threads(tmp_path):
    mem = TargetMemory.open(tmp_path / "m.db", key=Fernet.generate_key())
    t = threading.Thread(target=lambda: mem.remember("h", "k", {"v": 1}))
    t.start()
    t.join()
    assert mem.recall("h", "k") == {"v": 1}
    mem.close()


def test_logger_sinks_and_concurrent_writes(tmp_path):
    log = EventLogger(tmp_path / "e.jsonl")
    seen = []
    log.add_sink(seen.append)
    log.add_sink(lambda r: 1 / 0)                     # a broken subscriber is ignored
    threads = [threading.Thread(target=lambda i=i: log.info("x", n=i, token="secret")) for i in range(50)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    log.close()
    lines = (tmp_path / "e.jsonl").read_text().splitlines()
    assert len(lines) == 50 and all(json.loads(line)["kind"] == "x" for line in lines)
    assert len(seen) == 50 and all(r["token"] == "«redacted»" for r in seen)


def _agent(provider, **kw):
    cfg = Config()
    cfg.logging.console = False
    reg = ToolRegistry()
    reg.add("probe", "p", lambda a, c: ToolResult(content="ok"))
    reg.add("finish", "f", lambda a, c: ToolResult.done(a.get("summary", "")))
    return Agent(provider, reg, config=cfg, **kw)


def test_finish_closes_every_pending_tool_call():
    """Providers reject a turn whose earlier tool_call_ids lack a response."""
    from autopwn.llm.provider import LLMResponse, ToolCall, Usage
    resp = LLMResponse(content=None, usage=Usage(total_tokens=1), tool_calls=[
        ToolCall("a", "finish", {"summary": "done"}), ToolCall("b", "probe", {}),
        ToolCall("c", "probe", {})])
    agent = _agent(ScriptedLLM([resp]))
    assert agent.run("go").reason == "finish"
    answered = {m.tool_call_id for m in agent.conversation.messages if m.role == "tool"}
    assert answered == {"a", "b", "c"}


def test_declined_reason_is_valid_json():
    gate = ApprovalGate(Mode.HITL, lambda c, t: ApprovalDecision(False, 'nope "quoted" \\ reason'))
    agent = _agent(ScriptedLLM([call("probe"), say("ok")]), gate=gate)
    agent.run("go")
    tool_msg = next(m for m in agent.conversation.messages if m.role == "tool")
    assert json.loads(tool_msg.content)["declined"] is True


def test_provider_error_ends_turn_cleanly():
    agent = _agent(ScriptedLLM([LLMError("rate limited")]))
    res = agent.run("go")
    assert res.reason == "error" and "rate limited" in res.error


def test_budget_is_per_turn_in_a_chat():
    """Turn N must not inherit turn N-1's spent steps/tokens."""
    script = [call("probe", cid=f"c{i}") for i in range(3)] + [say("t1")] + \
             [call("probe", cid=f"d{i}") for i in range(3)] + [say("t2")]
    agent = _agent(ScriptedLLM(script), budget=Budget(max_steps=4))
    assert agent.run("one").reason == "stop"
    assert agent.run("two").reason == "stop"            # would be max_steps before the fix
    assert agent.budget.total_tokens > agent.budget.tokens


def test_cancel_stops_the_turn():
    agent = _agent(ScriptedLLM([call("probe", cid=f"c{i}") for i in range(20)]))
    original = agent.registry.get("probe").handler
    pressed = []

    def handler(a, c):
        if not pressed:                                  # operator presses Esc once, mid-turn
            pressed.append(True)
            agent.cancel()
        return original(a, c)
    agent.registry.get("probe").handler = handler
    assert agent.run("go").reason == "cancelled"
    assert agent.run("again").reason == "stop"           # next turn starts clean


def test_redaction_replaces_exact_span_only():
    v = Vault.open()
    text = "token=token12345abc"                         # secret text also appears in the prefix
    out = Redactor(v).scrub(text)
    assert out.startswith("token=") and "token12345abc" not in out


def test_session_chat_multi_turn_with_tool(make_session):
    llm = ScriptedLLM([call("recall_target", host="app.lab"), say("first"), say("second")])
    s = make_session(llm, targets=["app.lab"])
    events = []
    s.subscribe(lambda r: events.append(r["kind"]))
    r1 = s.chat("what do you know?")
    r2 = s.chat("and now?")
    assert (r1.final, r2.final) == ("first", "second")
    assert {"agent.start", "tool.call", "tool.result", "agent.finish"} <= set(events)


def test_session_chat_runs_in_worker_thread(make_session):
    """The exact path that crashed before: tool writes to SQLite from a thread."""
    s = make_session(ScriptedLLM([call("record_observation", key="tech", value="nginx"), say("ok")]),
                     targets=["app.lab"])
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("r", s.chat("note it")))
    t.start()
    t.join()
    assert box["r"].reason == "stop"
    assert s.ctx.store.recall("app.lab", "tech") == "nginx"


def test_session_not_ready_returns_error_not_exception(make_session):
    s = make_session(ScriptedLLM(ready_error=MissingAPIKey("no API key")))
    res = s.chat("hi")
    assert res.reason == "error" and "no API key" in res.error


def test_session_set_model_aligns_provider_and_persists(make_session, tmp_path):
    s = make_session()
    state = s.set_model("ollama/llama3.1")
    assert s.provider_id == "ollama"
    assert s.config.llm.api_base == "http://localhost:11434"
    assert s.config.llm.requires_key is False
    assert state.ok
    assert Settings.load(tmp_path / "settings.json").model == "ollama/llama3.1"


def test_session_connect_provider_stores_key_locally(make_session):
    s = make_session()
    s.connect_provider("openai", "sk-openai-abcdef123456")
    assert s.creds.get("openai") == "sk-openai-abcdef123456"
    row = next(p for p in s.provider_status() if p["id"] == "openai")
    assert row["connected"] and row["source"] == "stored" and "abcdef" not in row["key"]
    s.set_model("openai/gpt-4.1")
    assert s.config.llm.api_key() == "sk-openai-abcdef123456"
    assert s.disconnect_provider("openai") and s.config.llm.api_key_value is None


def test_session_scope_is_shared_with_agent_and_audited(make_session):
    s = make_session(targets=["a.lab"])
    s.set_scope(targets=["a.lab", "b.lab"], out_of_scope=["prod.lab"], authorized=True, domain="network")
    assert s.agent.targets == ["a.lab", "b.lab"]            # same list the agent prompts with
    assert s.authorized and s.planner.methodology.value == "PTES"
    s.close()
    assert AuditLog.verify(s.ctx.run_dir / "audit.jsonl")


def test_session_hitl_approvals(make_session):
    s = make_session(ScriptedLLM([call("recall_target", host="x"), say("a"),
                                  call("recall_target", cid="c2", host="x"), say("b"),
                                  call("recall_target", cid="c3", host="x"), say("c")]))
    s.set_mode("hitl")
    asked = []
    s.set_approver(lambda c, t: asked.append(t.name) or True)
    s.chat("1")
    s.set_approver(lambda c, t: False)
    s.chat("2")
    s.set_approver(None)                                     # HITL with nobody to ask → fail closed
    s.chat("3")
    tool_msgs = [m.content for m in s.agent.conversation.messages if m.role == "tool"]
    assert asked == ["recall_target"]
    assert "declined" not in tool_msgs[0]
    assert all(json.loads(m)["declined"] for m in tool_msgs[1:])


def test_session_reports_require_verified_findings(make_session):
    s = make_session(targets=["app.lab"])
    assert "_error" in s.generate_report(["json"])
    f = s.pipeline.add(Candidate("sqli", host="app.lab", url="http://app.lab/x?id=1", param="id"))
    f.status = Status.VERIFIED
    res = s.generate_report(["json", "md"], "executive")
    assert res["json"]["ok"] and Path(res["md"]["path"]).is_file()


def test_session_close_is_idempotent_and_remembers(make_session):
    s = make_session(targets=["app.lab"])
    f = s.pipeline.add(Candidate("sqli", host="app.lab", url="http://app.lab/x?id=1", param="id"))
    f.status = Status.VERIFIED
    deltas = s.close()
    assert deltas == {"app.lab": "1 new · 0 fixed · 0 reopened · 0 unchanged"}
    assert s.close() == {}                                   # second close is a no-op


def test_session_context_stats(make_session):
    st = make_session(targets=["a"]).context_stats()
    for k in ("model", "context_window", "tokens_est", "compact_at", "phase", "tools",
              "verified", "authorized", "run_dir"):
        assert k in st
    assert Path(st["run_dir"]).is_absolute()


MCP_SERVER = '''
from mcp.server import MCPServer
server = MCPServer("demo")

@server.tool()
def lookup(product: str) -> str:
    """demo lookup"""
    return f"{product}: 2 advisories"

@server.tool()
def broken(x: str) -> str:
    """always fails"""
    raise ValueError("demo failure")

if __name__ == "__main__":
    server.run()
'''


@pytest.fixture
def mcp_server_script(tmp_path):
    pytest.importorskip("mcp.server")
    p = tmp_path / "demo_server.py"
    p.write_text(MCP_SERVER)
    return p


def test_mcp_real_server_lifecycle(make_session, mcp_server_script, capfd):
    from autopwn.llm.provider import ToolCall
    s = make_session()
    s.add_mcp_server("demo", sys.executable, [str(mcp_server_script)], env={"DEMO": "1"})
    names = s.connect_mcp("demo")
    assert sorted(names) == ["demo__broken", "demo__lookup"]        # provider-safe names
    assert s.registry.get("demo__lookup").requires_approval         # untrusted → gated
    ok = s.registry.dispatch(ToolCall("1", "demo__lookup", {"product": "nginx"}))
    assert ok.ok and "2 advisories" in ok.content
    bad = s.registry.dispatch(ToolCall("2", "demo__broken", {"x": "y"}))
    assert not bad.ok                                               # failure is not a success
    assert (s.ctx.run_dir / "mcp-demo.log").stat().st_size > 0      # stderr captured…
    assert "demo failure" not in capfd.readouterr().err             # …not on the terminal
    s.disconnect_mcp("demo")
    assert not [n for n in s.registry.names() if n.startswith("demo__")]
    assert s.mcp_status()[0]["connected"] is False


def test_mcp_trusted_server_is_not_gated(make_session, mcp_server_script):
    s = make_session()
    s.add_mcp_server("t", sys.executable, [str(mcp_server_script)], trusted=True)
    s.connect_mcp("t")
    assert s.registry.get("t__lookup").requires_approval is False


def test_mcp_bad_command_reports_error_and_leaks_nothing(make_session):
    s = make_session()
    s.add_mcp_server("ghost", "/nonexistent/binary")
    before = threading.active_count()
    with pytest.raises(RuntimeError, match="ghost"):
        s.connect_mcp("ghost")
    assert s.mcp_status()[0]["error"]
    assert threading.active_count() <= before + 1                    # loop thread torn down


def test_mcp_connect_enabled_reports_per_server(make_session, mcp_server_script):
    s = make_session()
    s.add_mcp_server("good", sys.executable, [str(mcp_server_script)])
    s.add_mcp_server("ghost", "/nonexistent/binary")
    results = s.connect_enabled_mcp()
    assert results["good"].startswith("ok (2 tools)")
    assert results["ghost"].startswith("error")


def _run_cli(argv):
    from autopwn.cli import main
    with pytest.raises(SystemExit) as e:
        main(argv)
    return e.value.code


def test_cli_models_and_providers(capsys):
    assert _run_cli(["models", "anthropic"]) == 0
    assert "anthropic/claude-sonnet-4-5" in capsys.readouterr().out
    assert _run_cli(["providers"]) == 0
    assert "Anthropic" in capsys.readouterr().out


def test_cli_connect_unknown_provider():
    assert _run_cli(["connect", "nope"]) == 2


def test_cli_connect_stores_key(monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt: "sk-test-1234567890")
    assert _run_cli(["connect", "openai"]) == 0
    assert CredentialStore().get("openai") == "sk-test-1234567890"


def test_cli_run_no_llm_boots_engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                          # no project config → app data dir
    assert _run_cli(["run", "boot check", "-t", "example.lab", "--no-llm"]) == 0


def test_cli_no_args_without_tty_prints_help(capsys, monkeypatch):
    from autopwn.cli import main
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    main([])
    assert "autopwnai" in capsys.readouterr().out


def test_entry_point_is_installed():
    from importlib.metadata import entry_points
    names = {e.name for e in entry_points(group="console_scripts") if e.value == "autopwn.cli:main"}
    assert {"autopwnai", "autopwn"} <= names


def test_every_default_path_respects_autopwn_home(isolated_home):
    """Settings, keys, runs and memory all live under AUTOPWN_HOME — nothing may
    default to a hard-coded location in the real home directory."""
    from autopwn.settings import config_dir, data_dir
    m = TargetMemory.open()
    try:
        assert m._conn.execute("PRAGMA database_list").fetchone()[2].startswith(str(isolated_home))
    finally:
        m.close()
    assert str(config_dir()).startswith(str(isolated_home))
    assert str(data_dir()).startswith(str(isolated_home))
    assert CredentialStore().dir == config_dir()


_OR_FIXTURE = {"data": [
    {"id": "openrouter/free", "context_length": 200000, "supported_parameters": ["tools", "temperature"],
     "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "nvidia/nemotron-x:free", "context_length": 1000000, "supported_parameters": ["tools"],
     "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "acme/no-tools:free", "context_length": 8000, "supported_parameters": ["temperature"],
     "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "openai/gpt-paid", "context_length": 128000, "supported_parameters": ["tools"],
     "pricing": {"prompt": "0.000002", "completion": "0.000008"}},
]}


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


@pytest.fixture
def openrouter_api(monkeypatch):
    """Serve a fixed OpenRouter /models response; count fetches."""
    import httpx
    calls = []

    def fake_get(url, timeout=None, **kw):
        calls.append(url)
        return _Resp(_OR_FIXTURE)
    catalog._live.clear()
    monkeypatch.setattr(httpx, "get", fake_get)
    yield calls
    catalog._live.clear()


def test_openrouter_catalog_lists_free_tool_models_first(openrouter_api):
    models = catalog.list_models("openrouter")
    ids = [m.id for m in models]
    assert ids[0] == "openrouter/openrouter/free" and models[0].featured     # featured default
    assert "openrouter/acme/no-tools:free" not in ids                       # no tools → hidden
    free = [m.id for m in models if m.free]
    assert free == ["openrouter/openrouter/free", "openrouter/nvidia/nemotron-x:free"]
    assert ids[-1] == "openrouter/openai/gpt-paid"                          # paid after free
    assert next(m for m in models if m.id.endswith("nemotron-x:free")).context == 1000000


def test_openrouter_catalog_is_cached(openrouter_api):
    catalog.list_models("openrouter")
    catalog.list_models("openrouter")
    assert len(openrouter_api) == 1


def test_openrouter_model_info_and_tool_support_from_live_catalog(openrouter_api):
    assert catalog.model_info("openrouter/nvidia/nemotron-x:free") is None   # cache cold: no fetch
    p = LLMProvider(LLMConfig(model="openrouter/nvidia/nemotron-x:free", api_key_value="k"))
    assert p.tool_support() is True                                          # warms, then knows
    assert p.ensure_ready() == []                                            # no "unverified" warning
    info = catalog.model_info("openrouter/nvidia/nemotron-x:free")
    assert info["max_input_tokens"] == 1000000 and info["free"] is True
    no_tools = LLMProvider(LLMConfig(model="openrouter/acme/no-tools:free", api_key_value="k"))
    from autopwn.llm.provider import ModelNotToolCapable
    with pytest.raises(ModelNotToolCapable):
        no_tools.ensure_ready()


def test_openrouter_catalog_offline_falls_back(monkeypatch):
    import httpx
    catalog._live.clear()

    def down(*a, **k):
        raise httpx.ConnectError("offline")
    monkeypatch.setattr(httpx, "get", down)
    models = catalog.list_models("openrouter")                              # static map instead
    assert all(m.id.startswith("openrouter/") for m in models)
    catalog._live.clear()


def test_rate_limit_on_free_model_suggests_the_free_router():
    import litellm

    from autopwn.llm.provider import explain_error
    raw = ('OpenrouterException - {"error":{"message":"Provider returned error","code":429,'
           '"metadata":{"raw":"google/x:free is temporarily rate-limited upstream."}}}')
    msg = explain_error(litellm.RateLimitError(raw, llm_provider="openrouter", model="x"),
                        "openrouter/google/x:free")
    assert "rate limited" in msg and "temporarily rate-limited upstream" in msg
    assert "openrouter/openrouter/free" in msg and "{" not in msg            # no raw JSON


def test_auth_error_points_to_provider_screen():
    import litellm

    from autopwn.llm.provider import explain_error
    e = litellm.AuthenticationError('{"error":{"message":"No auth credentials found"}}',
                                    llm_provider="openrouter", model="x")
    msg = explain_error(e, "openrouter/openrouter/free")
    assert "rejected the API key" in msg and "/provider" in msg


def test_transient_errors_are_retried():
    p = LLMProvider(LLMConfig(api_key_value="k"))
    assert p._common_kwargs(None)["num_retries"] == 2
    import tenacity  # noqa: F401  — LiteLLM's retries need it; without it every error is masked


def _creds_with(tmp_path, **keys):
    store = CredentialStore(tmp_path / "creds", key=Fernet.generate_key())
    for pid, k in keys.items():
        store.set(pid, k)
    return store


def test_auto_selects_connected_provider(make_session, tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    s = make_session(creds=_creds_with(tmp_path, openrouter="sk-or-test-123456"))
    assert s.auto_selected == "openrouter/openrouter/free"
    assert s.model == "openrouter/openrouter/free"
    assert s.config.llm.api_key() == "sk-or-test-123456"


def test_explicit_model_choice_is_never_overridden(make_session, tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    settings = Settings.load(tmp_path / "settings.json")
    settings.model = "anthropic/claude-sonnet-4-5"
    s = make_session(settings=settings, creds=_creds_with(tmp_path, openrouter="sk-or-test-123456"))
    assert s.auto_selected is None and s.model == "anthropic/claude-sonnet-4-5"


def test_no_auto_select_when_default_is_usable(make_session, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env-123456")
    s = make_session(creds=_creds_with(tmp_path, openrouter="sk-or-test-123456"))
    assert s.auto_selected is None and s.provider_id == "anthropic"
