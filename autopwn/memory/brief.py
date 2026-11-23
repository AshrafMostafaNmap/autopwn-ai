"""Long-term memory brief injected into the system prompt."""
from __future__ import annotations

import json
from datetime import datetime


def _fmt_value(v) -> str:
    text = v if isinstance(v, str) else json.dumps(v, default=str)
    return text if len(text) <= 160 else text[:157] + "…"


def long_term_brief(memory, targets: list[str], *, max_chars: int = 4000) -> str:
    """What earlier sessions learned about the in-scope targets: durable facts,
    open findings, what was fixed, and short summaries of past sessions."""
    blocks = []
    for target in targets:
        facts = memory.recall(target) or {}
        history = memory.target_findings(target)
        episodes = memory.episodes(target, limit=3)
        if not (facts or history or episodes):
            continue
        lines = [f"### {target}"]
        if facts:
            lines.append("facts: " + "; ".join(f"{k}={_fmt_value(v)}" for k, v in list(facts.items())[:12]))
        open_f = [h for h in history if h["status"] == "open"]
        fixed = [h for h in history if h["status"] == "fixed"]
        if open_f:
            lines.append("open findings: " + "; ".join(
                f"[{h['severity']}] {h['title']} ({h['finding_id']})" for h in open_f[:10]))
        if fixed:
            lines.append("fixed since earlier runs: " + "; ".join(h["title"] for h in fixed[:6]))
        for ep in episodes:
            day = datetime.fromtimestamp(ep["at"]).strftime("%Y-%m-%d")
            lines.append(f"session {day}: {ep['summary'][:400]}")
        blocks.append("\n".join(lines))
    text = "\n\n".join(blocks)
    return text if len(text) <= max_chars else text[: max_chars - 1] + "…"
