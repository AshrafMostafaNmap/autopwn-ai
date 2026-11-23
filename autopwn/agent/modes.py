"""Run modes and the approval gate: flagged tools always ask; in human-in-the-loop
mode every tool call asks.
"""
from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..llm.provider import ToolCall

if TYPE_CHECKING:
    from .tools import Tool


class Mode(enum.Enum):
    AUTONOMOUS = "autonomous"       # agent decides and acts; only flagged tools gate
    HITL = "human-in-the-loop"      # operator approves every tool call


@dataclass
class ApprovalDecision:
    approved: bool
    reason: str = ""


# decide(call, tool) -> ApprovalDecision | bool
DecisionFn = Callable[[ToolCall, "Tool"], "ApprovalDecision | bool"]


def auto_approve(_call: ToolCall, _tool: Tool) -> ApprovalDecision:
    return ApprovalDecision(True, "auto")


def console_prompt(console):
    """Build a decision function that asks the operator on the Rich console."""
    def _decide(call: ToolCall, tool: Tool) -> ApprovalDecision:
        args = ", ".join(f"{k}={v!r}" for k, v in (call.arguments or {}).items())
        console.print(f"[yellow]approve[/] [bold]{tool.name}[/]({args})?  [dim][y/N][/]")
        try:
            answer = console.input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        ok = answer in ("y", "yes")
        return ApprovalDecision(ok, "operator" if ok else "declined by operator")
    return _decide


class ApprovalGate:
    """Decides whether a tool call needs approval and obtains it."""

    def __init__(self, mode: Mode, decide: DecisionFn | None = None):
        self.mode = mode
        # default decision depends on mode: autonomous auto-approves the
        # (few) flagged tools too unless a decider is supplied.
        self._decide = decide or auto_approve

    def needs_approval(self, tool: Tool) -> bool:
        if self.mode is Mode.HITL:
            return True
        return tool.requires_approval

    def check(self, call: ToolCall, tool: Tool) -> ApprovalDecision:
        if not self.needs_approval(tool):
            return ApprovalDecision(True, "not gated")
        result = self._decide(call, tool)
        if isinstance(result, bool):
            return ApprovalDecision(result, "operator" if result else "declined by operator")
        return result
