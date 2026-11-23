"""Control tools every run has: advance_phase, record_observation, finish."""
from __future__ import annotations

from typing import Any

from .planner import Phase, Planner
from .tools import ToolRegistry, ToolResult


def register_builtins(registry: ToolRegistry, planner: Planner) -> None:
    def advance_phase(args: dict[str, Any], _ctx) -> ToolResult:
        to = args.get("to")
        if to:
            try:
                target = Phase(to)
            except ValueError:
                return ToolResult.fail(f"unknown phase '{to}'",
                                       valid=[p.value for p in Phase])
            try:
                planner.goto(target)
            except ValueError as e:
                return ToolResult.fail(str(e))
        else:
            if not planner.can_advance():
                return ToolResult.fail("already at the final phase")
            planner.advance()
        return ToolResult(content=f"entered phase: {planner.phase.value}",
                          data={"phase": planner.phase.value, "intent": planner.intent})

    registry.add(
        "advance_phase",
        "Move the engagement forward to the next methodology phase (recon → "
        "planning → detection → verify → report). Optionally jump to a specific "
        "later phase with 'to'. Forward-only.",
        advance_phase,
        parameters={
            "type": "object",
            "properties": {
                "to": {"type": "string", "enum": [p.value for p in Phase],
                       "description": "optional target phase to jump to (must be later than the current one)"}
            },
        },
    )

    def record_observation(args: dict[str, Any], ctx) -> ToolResult:
        key = args.get("key")
        value = args.get("value")
        if not key:
            return ToolResult.fail("'key' is required")
        target = args.get("target") or (ctx.targets[0] if ctx and ctx.targets else "run")
        if ctx is not None:
            ctx.store.remember(str(target), str(key), value, run_id=ctx.run_id)
        return ToolResult(content=f"recorded {key} for {target}",
                          data={"target": target, "key": key})

    registry.add(
        "record_observation",
        "Persist a recon/detection observation (tech, service, endpoint, note) "
        "to the state store so it survives compaction and future runs.",
        record_observation,
        parameters={
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {},
                "target": {"type": "string", "description": "host/target this is about (defaults to the primary target)"},
            },
            "required": ["key", "value"],
        },
    )

    def finish(args: dict[str, Any], _ctx) -> ToolResult:
        return ToolResult.done(args.get("summary") or "engagement complete")

    registry.add(
        "finish",
        "End the engagement and return a final summary to the operator. Call "
        "this only when the goal is met or no further safe progress is possible.",
        finish,
        parameters={
            "type": "object",
            "properties": {"summary": {"type": "string", "description": "the final answer / wrap-up"}},
            "required": ["summary"],
        },
    )
