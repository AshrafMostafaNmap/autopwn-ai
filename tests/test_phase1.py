"""Phase-1 agent-core tests.

The loop is exercised with a scripted fake provider (no network): it returns a
pre-planned sequence of tool calls then a final answer, so we can assert the loop
dispatches tools, feeds results back, respects max_steps, and that HITL denial is
handled — the Phase-1 DoD.
"""
from __future__ import annotations

import pytest

from autopwn.agent.builtins import register_builtins
from autopwn.agent.loop import Agent, Budget
from autopwn.agent.modes import ApprovalDecision, ApprovalGate, Mode
from autopwn.agent.planner import Methodology, Phase, Planner, methodology_for
from autopwn.agent.tools import Tool, ToolError, ToolRegistry, ToolResult
from autopwn.config import Config
from autopwn.llm.provider import LLMResponse, ToolCall, Usage
from autopwn.mcp import register_mcp_tools


# ── a scripted provider ───────────────────────────────────────────────────────
class FakeProvider:
    """Returns queued LLMResponses in order; records messages it was given."""
    def __init__(self, script: list[LLMResponse]):
        self.script = list(script)
        self.calls: list[list] = []

    def complete(self, messages, tools=None, **kw):
        self.calls.append(messages)
        if self.script:
            return self.script.pop(0)
        # safety net: if script runs dry, end the loop
        return LLMResponse(content="(script exhausted)", usage=Usage())


def _tc(name, **args):
    return ToolCall(id=f"c{abs(hash((name, tuple(sorted(args)))))%10000}", name=name, arguments=args)


def _cfg():
    c = Config()
    c.logging.console = False
    return c


# ── tool registry ─────────────────────────────────────────────────────────────
def test_registry_dispatch_and_errors():
    reg = ToolRegistry()
    reg.add("echo", "echo back", lambda a, c: ToolResult(content=a.get("x", "")))
    assert "echo" in reg
    r = reg.dispatch(_tc("echo", x="hi"))
    assert r.ok and r.content == "hi"
    # unknown tool → structured failure, not an exception
    assert reg.dispatch(_tc("nope")).ok is False

def test_registry_refuses_destructive_and_duplicates():
    reg = ToolRegistry()
    reg.add("t", "d", lambda a, c: ToolResult())
    with pytest.raises(ToolError):
        reg.add("t", "d2", lambda a, c: ToolResult())        # duplicate
    with pytest.raises(ToolError):
        reg.register(Tool("boom", "d", handler=lambda a, c: ToolResult(), destructive=True))

def test_handler_exception_becomes_failure():
    reg = ToolRegistry()
    def boom(a, c): raise RuntimeError("kaboom")
    reg.add("boom", "d", boom)
    r = reg.dispatch(_tc("boom"))
    assert r.ok is False and "kaboom" in r.error

def test_specs_phase_scoping():
    reg = ToolRegistry()
    reg.add("a", "d", lambda a, c: ToolResult(), phase="recon")
    reg.add("b", "d", lambda a, c: ToolResult(), phase="detection")
    reg.add("c", "d", lambda a, c: ToolResult())             # untagged → always shown
    names = {s.name for s in reg.specs(phase="recon")}
    assert names == {"a", "c"}


# ── planner ───────────────────────────────────────────────────────────────────
def test_planner_forward_only():
    p = Planner()
    assert p.phase is Phase.RECON
    p.advance(); assert p.phase is Phase.PLANNING
    p.goto(Phase.VERIFY); assert p.phase is Phase.VERIFY
    with pytest.raises(ValueError):
        p.goto(Phase.RECON)                                  # backwards rejected

def test_methodology_selection():
    assert methodology_for("web") is Methodology.OWASP_WSTG
    assert methodology_for("android") is Methodology.MOBILE
    assert methodology_for("network") is Methodology.PTES


# ── conversation / compaction ─────────────────────────────────────────────────
# ── approval gate / modes ─────────────────────────────────────────────────────
def test_gate_autonomous_only_flagged():
    reg = ToolRegistry()
    plain = reg.add("plain", "d", lambda a, c: ToolResult())
    flagged = reg.add("flag", "d", lambda a, c: ToolResult(), requires_approval=True)
    gate = ApprovalGate(Mode.AUTONOMOUS)                     # default auto-approves
    assert gate.needs_approval(plain) is False
    assert gate.needs_approval(flagged) is True
    assert gate.check(_tc("flag"), flagged).approved is True

def test_gate_hitl_gates_everything():
    reg = ToolRegistry()
    plain = reg.add("plain", "d", lambda a, c: ToolResult())
    denier = lambda call, tool: ApprovalDecision(False, "no")
    gate = ApprovalGate(Mode.HITL, denier)
    assert gate.needs_approval(plain) is True
    assert gate.check(_tc("plain"), plain).approved is False


def _recon_stub(reg):
    """A deterministic stand-in recon tool for loop tests (no network)."""
    reg.add("recon_target", "stub recon",
            lambda a, c: ToolResult(content=f"recon of {a.get('host')}: nginx 1.25, PHP, /login + /api",
                                    data={"host": a.get("host"), "server": "nginx/1.25"}),
            phase="recon")


# ── the full loop ─────────────────────────────────────────────────────────────
def test_loop_calls_tool_then_finishes():
    reg = ToolRegistry()
    planner = Planner()
    register_builtins(reg, planner)
    _recon_stub(reg)
    provider = FakeProvider([
        # turn 1: the model calls the demo recon tool
        LLMResponse(content=None, tool_calls=[_tc("recon_target", host="juice.lab")], usage=Usage(total_tokens=10)),
        # turn 2: the model finishes
        LLMResponse(content=None, tool_calls=[_tc("finish", summary="done: nginx + PHP, /login worth probing")],
                    usage=Usage(total_tokens=8)),
    ])
    agent = Agent(provider, reg, config=_cfg(), planner=planner)
    res = agent.run("recon juice.lab")
    assert res.reason == "finish"
    assert "nginx" in res.final
    assert res.tool_calls == 2
    # the recon result was fed back as a tool message before the finish turn
    second_turn = provider.calls[1]
    assert any(m.role == "tool" for m in second_turn)

def test_loop_respects_max_steps():
    reg = ToolRegistry()
    planner = Planner()
    register_builtins(reg, planner)
    _recon_stub(reg)
    # model loops forever calling recon; the step guard must stop it
    looping = LLMResponse(content=None, tool_calls=[_tc("recon_target", host="h")], usage=Usage(total_tokens=1))
    provider = FakeProvider([looping] * 100)
    agent = Agent(provider, reg, config=_cfg(), budget=Budget(max_steps=3), planner=planner)
    res = agent.run("loop")
    assert res.reason == "max_steps"
    assert res.steps == 3

def test_loop_hitl_denial_feeds_back_and_continues():
    reg = ToolRegistry()
    planner = Planner()
    register_builtins(reg, planner)
    _recon_stub(reg)
    provider = FakeProvider([
        LLMResponse(content=None, tool_calls=[_tc("recon_target", host="h")], usage=Usage(total_tokens=5)),
        LLMResponse(content="ok, I'll stop", usage=Usage(total_tokens=5)),
    ])
    denier = lambda call, tool: ApprovalDecision(False, "declined by operator")
    gate = ApprovalGate(Mode.HITL, denier)
    agent = Agent(provider, reg, config=_cfg(), gate=gate, planner=planner)
    res = agent.run("try recon")
    assert res.reason == "stop"
    # the denied call produced a "declined" tool observation on the next turn
    second_turn = provider.calls[1]
    declined = [m for m in second_turn if m.role == "tool" and "declined" in (m.content or "")]
    assert declined

def test_loop_advance_phase_tool_moves_planner():
    reg = ToolRegistry()
    planner = Planner()
    register_builtins(reg, planner)
    _recon_stub(reg)
    provider = FakeProvider([
        LLMResponse(content=None, tool_calls=[_tc("advance_phase")], usage=Usage(total_tokens=3)),
        LLMResponse(content=None, tool_calls=[_tc("finish", summary="moved")], usage=Usage(total_tokens=3)),
    ])
    agent = Agent(provider, reg, config=_cfg(), planner=planner)
    res = agent.run("advance")
    assert planner.phase is Phase.PLANNING
    assert res.phase == "planning"


# ── MCP surfacing (no live server) ────────────────────────────────────────────
def test_mcp_tools_surface_into_registry():
    reg = ToolRegistry()
    calls = []
    def invoker(name, args):
        calls.append((name, args))
        return f"ran {name}", {"ok": True}
    defs = [{"name": "scan", "description": "scan a host",
             "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}}}}]
    added = register_mcp_tools(reg, "netsec", defs, invoker)
    # provider-safe name: LLM APIs reject dots in tool names
    assert added == ["netsec__scan"]
    tool = reg.get("netsec__scan")
    assert tool.source == "mcp:netsec"
    assert tool.requires_approval is True          # external tools are gated by default
    r = reg.dispatch(_tc("netsec__scan", host="h"))
    assert r.ok and r.data["ok"] is True
    assert calls == [("scan", {"host": "h"})]
