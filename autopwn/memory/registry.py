"""Memory tools for the agent: recall_target, remember, lookup_technique."""
from __future__ import annotations

from typing import Any

from ..agent.tools import ToolRegistry, ToolResult


def register_memory_tools(registry: ToolRegistry, *, ctx=None, memory, kb) -> None:

    def _default_target() -> str:
        return (ctx.targets[0] if ctx and ctx.targets else "")

    def recall_target(args: dict[str, Any], _ctx) -> ToolResult:
        host = args.get("host") or _default_target()
        if not host:
            return ToolResult.fail("'host' is required")
        facts = memory.recall(host)
        history = memory.target_findings(host)
        known = bool(facts) or bool(history)
        note = (f"known target: {len(facts)} fact(s), {len(history)} prior finding(s)"
                if known else "no prior knowledge — first assessment")
        return ToolResult(content=note, data={
            "host": host, "known": known, "facts": facts,
            "prior_findings": history,
            "open_prior": [h for h in history if h["status"] == "open"],
        })

    registry.add(
        "recall_target",
        "Recall cross-run knowledge about a target before scanning: prior "
        "tech/stack facts and the history of findings (so a re-scan is smarter "
        "and can report new/fixed/reopened).",
        recall_target, phase="recon",
        parameters={"type": "object", "properties": {"host": {"type": "string"}}},
    )

    def remember(args: dict[str, Any], _ctx) -> ToolResult:
        key = args.get("key")
        if not key:
            return ToolResult.fail("'key' is required")
        host = args.get("host") or _default_target()
        if not host:
            return ToolResult.fail("'host' is required")
        memory.remember(host, str(key), args.get("value"),
                        run_id=(ctx.run_id if ctx else None))
        return ToolResult(content=f"remembered {key} for {host} (persists across runs)",
                          data={"host": host, "key": key})

    registry.add(
        "remember",
        "Persist a durable fact about a target across runs (tech, credentials "
        "policy, scope notes). Encrypted at rest. Secrets still belong in the vault.",
        remember, phase="recon",
        parameters={"type": "object",
                    "properties": {"key": {"type": "string"}, "value": {},
                                   "host": {"type": "string"}},
                    "required": ["key", "value"]},
    )

    def lookup_technique(args: dict[str, Any], _ctx) -> ToolResult:
        class_id = args.get("class_id")
        query = args.get("query")
        if class_id:
            t = kb.lookup(class_id)
            if not t:
                return ToolResult.fail(f"unknown class '{class_id}'")
            results = [t]
        elif query:
            results = kb.search(query)
        else:
            return ToolResult.fail("provide 'class_id' or 'query'")
        data = [{"class_id": t.class_id, "title": t.title, "cvss": t.cvss,
                 "owasp": t.owasp, "cwe": t.cwe, "detection": t.detection,
                 "remediation": t.remediation} for t in results]
        return ToolResult(content=f"{len(data)} technique(s)", data={"techniques": data})

    registry.add(
        "lookup_technique",
        "Look up a vulnerability technique in the knowledge base by class_id or "
        "keyword — returns CVSS, OWASP/CWE, detection guidance, and remediation.",
        lookup_technique, phase="planning",
        parameters={"type": "object",
                    "properties": {"class_id": {"type": "string"}, "query": {"type": "string"}}},
    )
