"""The agent loop: think → act → observe until the model answers, calls `finish`,
is cancelled, errors, or hits a per-turn guard.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import Config
from ..core.context import RunContext
from ..llm.provider import LLMError, LLMProvider, Usage
from .conversation import Conversation
from .modes import ApprovalGate, Mode
from .planner import Planner
from .prompts import build_system_prompt
from .tools import ToolRegistry


@dataclass
class Budget:
    """Per-turn guard. In a chat session every user message is a new turn: the
    step/token/time counters reset at the start of each turn (`start_turn`), so
    a long conversation never starves later requests. `total_tokens` keeps the
    whole-session spend for display/cost."""
    max_steps: int = 40
    max_tokens: int = 500_000           # per turn
    max_seconds: float | None = None    # None = no wall-clock cap (depth over speed)
    steps: int = 0
    tokens: int = 0
    total_tokens: int = 0               # across every turn of the session
    total_cost: float = 0.0             # USD, when the provider reports it
    _started: float = field(default_factory=time.time)

    def start_turn(self) -> None:
        self.steps = 0
        self.tokens = 0
        self._started = time.time()

    def tick(self) -> None:
        self.steps += 1

    def add_usage(self, usage: Usage) -> None:
        n = usage.total_tokens or 0
        self.tokens += n
        self.total_tokens += n
        self.total_cost += usage.cost_usd or 0.0

    def exhausted(self) -> str | None:
        if self.steps >= self.max_steps:
            return "max_steps"
        if self.tokens >= self.max_tokens:
            return "max_tokens"
        if self.max_seconds is not None and (time.time() - self._started) >= self.max_seconds:
            return "max_seconds"
        return None

    @classmethod
    def from_config(cls, cfg: Config) -> Budget:
        prof = cfg.active_profile()
        return cls(max_steps=prof.max_steps)


@dataclass
class AgentResult:
    final: str | None
    # stop | finish | max_steps | max_tokens | max_seconds | cancelled | error
    reason: str
    steps: int
    tokens: int
    phase: str
    tool_calls: int = 0
    error: str = ""


class Agent:
    def __init__(
        self,
        provider: LLMProvider,
        registry: ToolRegistry,
        *,
        config: Config,
        planner: Planner | None = None,
        conversation: Conversation | None = None,
        gate: ApprovalGate | None = None,
        budget: Budget | None = None,
        ctx: RunContext | None = None,
        targets: list[str] | None = None,
        context: Callable[[], dict] | None = None,
    ):
        self.provider = provider
        self.registry = registry
        self.config = config
        self.planner = planner or Planner()
        self.conversation = conversation or Conversation()
        self.gate = gate or ApprovalGate(Mode.AUTONOMOUS)
        self.budget = budget or Budget.from_config(config)
        self.ctx = ctx
        self.targets = targets or (ctx.targets if ctx else [])
        self.context = context            # extra prompt state: model, memory, mcp_servers
        self._tool_calls = 0
        self._last_phase = self.planner.phase
        self._cancel = threading.Event()

    def cancel(self) -> None:
        """Ask the running turn to stop at the next safe point (thread-safe)."""
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def _refresh_system(self) -> None:
        """Rebuild the preamble so phase/scope reflect the latest state."""
        extra = self.context() if self.context else {}
        mode = "hitl" if self.gate.mode is Mode.HITL else "autonomous"
        self.conversation.set_system(
            build_system_prompt(self.config, self.planner, self.targets, mode=mode, **extra))

    def _log(self, kind: str, **f) -> None:
        if self.ctx is not None:
            self.ctx.logger.info(kind, **f)

    def run(self, goal: str) -> AgentResult:
        """Run one turn: add the operator's message and loop until the model
        answers, calls `finish`, is cancelled, errors, or hits a per-turn guard.
        Calling `run` again continues the same conversation (multi-turn chat)."""
        self._cancel.clear()
        self.budget.start_turn()
        self._tool_calls = 0
        self.conversation.add_user(goal)
        self._log("agent.start", goal=goal, mode=self.gate.mode.value,
                  max_steps=self.budget.max_steps)

        while True:
            if self.cancelled:
                return self._finish(None, "cancelled")
            reason = self.budget.exhausted()
            if reason:
                return self._finish(None, reason)

            self._refresh_system()
            # compact at a phase boundary (working summary + findings index) or
            # whenever the token budget is exceeded.
            # a new phase is a natural point to fold a long history early
            conv = self.conversation
            phase_changed = self.planner.phase is not self._last_phase
            conv.maybe_compact(force=phase_changed and conv.history_tokens() > conv.budget // 2)
            self._last_phase = self.planner.phase

            # THINK — one model turn, tools scoped to the current phase.
            tools = self.registry.specs(phase=self.planner.phase.value) or self.registry.specs()
            try:
                resp = self.provider.complete(self.conversation.render(), tools=tools)
            except LLMError as e:
                # A provider failure ends the turn cleanly — never crashes the app.
                self._log("agent.error", error=str(e))
                return self._finish(None, "error", error=str(e))
            self.budget.add_usage(resp.usage)
            self.conversation.add_assistant(resp)
            self._log("llm.result", phase=self.planner.phase.value,
                      finish_reason=resp.finish_reason, tool_calls=len(resp.tool_calls),
                      total_tokens=resp.usage.total_tokens)

            # No tool calls → the model's content is the final answer.
            if not resp.tool_calls:
                return self._finish(resp.content, "stop")

            # The model may narrate while it acts — surface that to the operator.
            if resp.content:
                self._log("agent.message", text=resp.content)

            # ACT + OBSERVE — dispatch each requested tool, feed results back.
            calls = list(resp.tool_calls)
            for i, call in enumerate(calls):
                if self.cancelled:
                    self._close_pending(calls[i:], "cancelled by operator")
                    return self._finish(None, "cancelled")
                self._tool_calls += 1
                tool = self.registry.get(call.name)

                if tool is None:
                    self.conversation.add_tool_result(
                        call, json.dumps({"error": f"unknown tool {call.name}"}))
                    continue

                decision = self.gate.check(call, tool)
                if not decision.approved:
                    self._log("tool.declined", tool=call.name, reason=decision.reason)
                    self.conversation.add_tool_result(
                        call, json.dumps({"declined": True, "reason": decision.reason}))
                    continue

                self._log("tool.call", tool=call.name, phase=self.planner.phase.value,
                          args=call.arguments)
                result = self.registry.dispatch(call, self.ctx)
                self.conversation.add_tool_result(call, result.render())

                if result.final:
                    # Every tool_call_id must have a response, or the provider
                    # rejects the next turn — close any calls we will not run.
                    self._close_pending(calls[i + 1:], "skipped: engagement finished")
                    return self._finish(result.content, "finish")

            self.budget.tick()

    def _close_pending(self, calls, reason: str) -> None:
        for call in calls:
            self.conversation.add_tool_result(call, json.dumps({"skipped": True, "reason": reason}))

    def _finish(self, final: str | None, reason: str, *, error: str = "") -> AgentResult:
        self._log("agent.finish", reason=reason, steps=self.budget.steps,
                  tokens=self.budget.tokens, phase=self.planner.phase.value,
                  tool_calls=self._tool_calls)
        return AgentResult(
            final=final, reason=reason, steps=self.budget.steps,
            tokens=self.budget.tokens, phase=self.planner.phase.value,
            tool_calls=self._tool_calls, error=error,
        )
