"""Short-term memory (context window, compaction, rolling summary, persistence)
and long-term memory (facts, finding history, session episodes, the brief)."""
from __future__ import annotations

from conftest import ScriptedLLM, call, say
from cryptography.fernet import Fernet

from autopwn.agent.conversation import Conversation, digest
from autopwn.core.findings import Finding, Severity, SeverityInfo, Status, Target
from autopwn.detect.model import Candidate
from autopwn.engine import EngineSession, list_sessions
from autopwn.govern import AuditLog
from autopwn.llm.provider import LLMError, Message, ToolCall
from autopwn.llm.tokens import context_window, make_counter
from autopwn.memory import MemoryCompactor, TargetMemory
from autopwn.memory.brief import long_term_brief


def _chars(n: int) -> str:
    return "x" * n


def _turn(conv: Conversation, i: int, *, size: int = 400, tool: bool = True) -> None:
    conv.add_user(f"request {i} " + _chars(size))
    if tool:
        tc = ToolCall(f"c{i}", "probe", {"i": i})
        conv.messages.append(Message.assistant(None, [tc]))
        conv.add_tool_result(tc, f"observation {i} " + _chars(size))
    conv.add_assistant_text(f"answer {i} " + _chars(size))


def _orphans(messages: list[Message]) -> set[str]:
    issued = {c.id for m in messages for c in m.tool_calls}
    answered = {m.tool_call_id for m in messages if m.role == "tool"}
    return answered - issued


# ── budget ────────────────────────────────────────────────────────────────────
def test_budget_comes_from_window_reserve_and_system():
    conv = Conversation(window=10_000, reserve=1_000)
    conv.set_system(_chars(4_000))                         # ~1000 tokens
    usage = conv.usage()
    assert usage["window"] == 10_000 and usage["system"] > 900
    assert conv.budget == int((10_000 - 1_000 - usage["system"]) * 0.85)
    assert 0 < usage["percent"] < 100


def test_budget_is_capped_for_huge_windows():
    assert Conversation(window=2_000_000, reserve=4_000).budget == 150_000


def test_no_compaction_under_budget():
    conv = Conversation(window=50_000)
    _turn(conv, 1)
    assert conv.maybe_compact() is False and conv.compactions == 0


# ── compaction ────────────────────────────────────────────────────────────────
def test_compaction_folds_whole_turns_and_keeps_pairs():
    conv = Conversation(window=3_000, reserve=200)
    for i in range(12):
        _turn(conv, i)
    assert conv.history_tokens() > conv.budget
    assert conv.maybe_compact() is True
    assert conv.messages[0].role == "user"                 # providers require it
    assert not _orphans(conv.messages)                     # every result has its call
    assert conv.history_tokens() <= conv.budget
    assert "request" in conv.summary and conv.folded_messages > 0


def test_only_one_system_message_and_summary_lives_in_it():
    conv = Conversation(window=3_000, reserve=200)
    conv.set_system("PREAMBLE")
    for i in range(12):
        _turn(conv, i)
    conv.maybe_compact()
    rendered = conv.render()
    assert [m.role for m in rendered].count("system") == 1
    assert rendered[0].content.startswith("PREAMBLE") and "Working memory" in rendered[0].content


def test_single_huge_turn_keeps_its_request_first():
    conv = Conversation(window=2_000, reserve=100)
    conv.add_user("map the target")
    for i in range(20):                                    # one long agentic turn
        tc = ToolCall(f"c{i}", "probe", {})
        conv.messages.append(Message.assistant(f"step {i}", [tc]))
        conv.add_tool_result(tc, _chars(300))
    assert conv.maybe_compact() is True
    assert conv.messages[0].content == "map the target"
    assert conv.messages[1].role == "assistant"
    assert not _orphans(conv.messages)


def test_summary_is_rolling():
    seen = []

    def summarizer(previous, folded):
        seen.append(previous)
        return f"{previous}|{len(folded)}"
    conv = Conversation(window=3_000, reserve=200, summarizer=summarizer)
    for i in range(12):
        _turn(conv, i)
    conv.maybe_compact()
    first = conv.summary
    for i in range(12, 24):
        _turn(conv, i)
    conv.maybe_compact()
    assert seen[1] == first and conv.summary.startswith(first)


def test_force_compaction_folds_old_turns_first():
    conv = Conversation(window=100_000)
    _turn(conv, 1)
    _turn(conv, 2)
    assert conv.maybe_compact(force=True) is True
    assert conv.messages[0].content.startswith("request 2")
    assert not _orphans(conv.messages)


def test_force_compaction_of_one_turn_keeps_its_request():
    conv = Conversation(window=100_000)
    _turn(conv, 1)
    assert conv.maybe_compact(force=True) is True
    assert conv.messages[0].content.startswith("request 1")
    assert not _orphans(conv.messages)


def test_nothing_to_fold_in_a_bare_request():
    conv = Conversation(window=100_000)
    conv.add_user("hello")
    assert conv.maybe_compact(force=True) is False


def test_digest_carries_previous_summary_forward():
    msgs = [Message.user("check login"), Message.tool("c", "HTTP 200", name="web_recon")]
    out = digest("earlier: nginx found", msgs)
    assert "earlier: nginx found" in out and "check login" in out and "web_recon" in out


# ── token counting ────────────────────────────────────────────────────────────
def test_counter_tokenizes_each_message_once(monkeypatch):
    import autopwn.llm.tokens as tokens
    calls = []
    monkeypatch.setattr(tokens, "_count", lambda model, m: calls.append(m) or 10)
    conv = Conversation(counter=make_counter("openai/gpt-4.1"))
    _turn(conv, 1)
    conv.history_tokens(); conv.history_tokens()
    assert len(calls) == 4                                 # 4 messages, counted once each
    conv.recount()
    conv.history_tokens()
    assert len(calls) == 8


def test_real_counter_and_window():
    count = make_counter("anthropic/claude-sonnet-4-5")
    assert count(Message.user("hello there")) > 0
    assert context_window("anthropic/claude-sonnet-4-5") == 200_000
    assert context_window("ollama/some-unknown-model") == 32_000


# ── model-written summary ─────────────────────────────────────────────────────
def _finding(fid="AP-1", status=Status.VERIFIED):
    return Finding(id=fid, title="SQL Injection", target=Target(host="app.lab", url="http://app.lab/x"),
                   severity=SeverityInfo(cvss_score=9.8, rating=Severity.CRITICAL), status=status)


def test_compactor_uses_the_model_and_appends_findings_index():
    llm = ScriptedLLM([say("- goal: assess app.lab\n- found SQLi on /x")])
    comp = MemoryCompactor(findings_provider=lambda: [_finding()], provider_getter=lambda: llm)
    out = comp("", [Message.user("assess app.lab")])
    assert "found SQLi" in out and "findings index" in out and "AP-1" in out
    assert "TRANSCRIPT EXCERPT" in llm.calls[0][1].content


def test_compactor_falls_back_when_the_model_fails():
    comp = MemoryCompactor(findings_provider=lambda: [],
                           provider_getter=lambda: ScriptedLLM([LLMError("down")]))
    out = comp("", [Message.user("assess app.lab")])
    assert "assess app.lab" in out and "findings index: none yet" in out


def test_old_findings_index_is_not_resummarized():
    llm = ScriptedLLM([say("new summary")])
    comp = MemoryCompactor(findings_provider=lambda: [], provider_getter=lambda: llm)
    comp("old notes\n\nfindings index (details: list_findings):\n- AP-9 stale", [Message.user("x")])
    prompt = llm.calls[0][1].content
    assert "old notes" in prompt and "AP-9" not in prompt


# ── long-term memory ──────────────────────────────────────────────────────────
def test_episodes_are_encrypted_and_ordered(tmp_path):
    mem = TargetMemory.open(tmp_path / "m.db", key=Fernet.generate_key())
    mem.add_episode("app.lab", "first: mapped login", run_id="r1")
    mem.add_episode("app.lab", "second: verified SQLi", run_id="r2")
    assert [e["summary"] for e in mem.episodes("app.lab")] == ["second: verified SQLi", "first: mapped login"]
    assert "app.lab" in mem.known_targets()
    mem.close()
    assert b"verified SQLi" not in (tmp_path / "m.db").read_bytes()


def test_long_term_brief(tmp_path):
    mem = TargetMemory.open(tmp_path / "m.db", key=Fernet.generate_key())
    mem.remember("app.lab", "stack", {"server": "nginx"})
    mem.record_findings("app.lab", [_finding("AP-1")], run_id="r1")
    mem.add_episode("app.lab", "assessed the login form", run_id="r1")
    brief = long_term_brief(mem, ["app.lab", "unknown.lab"])
    assert "### app.lab" in brief and "nginx" in brief
    assert "SQL Injection (AP-1)" in brief and "assessed the login form" in brief
    assert "unknown.lab" not in brief
    assert len(long_term_brief(mem, ["app.lab"], max_chars=60)) <= 60
    mem.close()


# ── engine integration ────────────────────────────────────────────────────────
def test_long_term_memory_reaches_the_system_prompt(make_session):
    llm = ScriptedLLM([say("ok")])
    s = make_session(llm, targets=["app.lab"])
    s.memory.remember("app.lab", "stack", {"server": "nginx 1.18"})
    s.chat("what do you know?")
    system = llm.calls[0][0]
    assert system.role == "system" and "Long-term memory" in system.content and "nginx 1.18" in system.content
    assert "Rules of engagement" in system.content and "Current state" in system.content


def test_session_close_writes_an_episode(make_session, tmp_path):
    s = make_session(ScriptedLLM([say("mapped the login form")]), targets=["app.lab"])
    s.chat("map app.lab")
    s.close()
    mem = TargetMemory.open(tmp_path / "memory.db")
    ep = mem.episodes("app.lab")
    assert ep and "map app.lab" in ep[0]["summary"] and "mapped the login form" in ep[0]["summary"]
    mem.close()


def test_idle_session_writes_no_episode(make_session, tmp_path):
    make_session(targets=["app.lab"]).close()
    mem = TargetMemory.open(tmp_path / "memory.db")
    assert mem.episodes("app.lab") == []
    mem.close()


def test_session_resume_restores_everything(make_session, tmp_path):
    llm = ScriptedLLM([call("recall_target", host="app.lab"), say("first answer"), say("second answer"),
                       say("after resume")])
    s = make_session(llm, targets=["app.lab"], domain="web")
    s.set_scope(authorized=True, out_of_scope=["prod.lab"])
    s.chat("map app.lab")
    s.chat("anything else?")
    f = s.pipeline.add(Candidate("sqli", host="app.lab", url="http://app.lab/x?id=1", param="id"))
    f.status = Status.VERIFIED
    s.pipeline._persist(f)
    run_dir, messages = s.ctx.run_dir, len(s.agent.conversation.messages)
    s.close()

    from autopwn.config import Config
    from autopwn.settings import CredentialStore, Settings
    cfg = Config(); cfg.run.root = str(tmp_path / "runs")
    r = EngineSession.create(config=cfg, settings=Settings.load(tmp_path / "settings.json"),
                             credentials=CredentialStore(tmp_path / "c2", key=Fernet.generate_key()),
                             memory_path=tmp_path / "memory.db", provider_factory=llm, resume=run_dir)
    try:
        assert r.ctx.run_dir == run_dir and r.title == "map app.lab" and r.turns == 2
        assert r.targets == ["app.lab"] and r.authorized and r.config.scope.out_of_scope == ["prod.lab"]
        assert len(r.agent.conversation.messages) == messages
        assert [x.title for x in r.pipeline.reportable()] == ["SQL Injection"]
        assert r.chat("continue").final == "after resume"
        assert r.turns == 3
    finally:
        r.close()
    assert AuditLog.verify(run_dir / "audit.jsonl")


def test_list_sessions_most_recent_first(make_session, tmp_path):
    a = make_session(ScriptedLLM([say("a")]))
    a.chat("first session")
    a.close()
    b = make_session(ScriptedLLM([say("b")]))
    b.chat("second session")
    idle = make_session()                                  # no turns → not listed
    rows = list_sessions(tmp_path / "runs")
    assert [r["title"] for r in rows] == ["second session", "first session"]
    assert all(r["turns"] == 1 for r in rows)
    assert [r["title"] for r in b.sessions()] == ["first session"]   # excludes itself
    b.close(); idle.close()


def test_set_model_resizes_the_window(make_session):
    s = make_session()
    s.set_model("anthropic/claude-sonnet-4-5")
    assert s.agent.conversation.window == 200_000
    s.set_model("ollama/llama3.1")
    assert s.agent.conversation.window == context_window("ollama/llama3.1")


def test_context_stats_report_real_usage(make_session):
    s = make_session(ScriptedLLM([say("ok")]))
    s.chat("hello")
    st = s.context_stats()
    assert st["tokens_est"] == st["system_tokens"] + st["history_tokens"]
    assert 0 < st["percent"] < 100 and st["turns"] == 1


def test_phase_change_compacts_only_large_histories():
    from autopwn.agent.builtins import register_builtins
    from autopwn.agent.loop import Agent
    from autopwn.agent.planner import Planner
    from autopwn.agent.tools import ToolRegistry
    from autopwn.config import Config
    cfg = Config(); cfg.logging.console = False
    planner = Planner()
    reg = ToolRegistry(); register_builtins(reg, planner)
    llm = ScriptedLLM([call("advance_phase"), say("planning now")])
    agent = Agent(llm, reg, config=cfg, planner=planner, conversation=Conversation(window=200_000))
    agent.run("hi")
    agent.run("go on")
    assert agent.conversation.compactions == 0            # tiny history: nothing folded


def test_window_is_refreshed_when_the_model_becomes_ready(make_session, monkeypatch):
    """Live catalogs (OpenRouter) are only known after a fetch; the budget must
    follow the real window, not the 32k default used before it is known."""
    import autopwn.engine as engine
    sizes = {"before": 32_000, "after": 200_000}
    state = {"warm": False}
    monkeypatch.setattr(engine, "warm_live", lambda pid: state.update(warm=True))
    monkeypatch.setattr(engine, "context_window",
                        lambda model: sizes["after" if state["warm"] else "before"])
    s = make_session()
    s.agent.conversation.window = 32_000
    assert s.ready().ok
    assert s.agent.conversation.window == 200_000
