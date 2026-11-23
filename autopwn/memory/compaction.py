"""Working-summary compaction for long sessions.

When old turns are folded out of the context window, the model itself rewrites
the rolling summary (objective, scope, what was done, what was found, what is
pending). If that call fails the deterministic digest is used, so compaction
never blocks a turn. A live findings index is always appended — details stay in
the state store and are retrievable with `list_findings`.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..agent.conversation import digest
from ..core.findings import Finding, Status
from ..llm.provider import Message

FindingsProvider = Callable[[], list[Finding]]
ProviderGetter = Callable[[], object]

_INSTRUCTIONS = """You maintain the working memory of a security-assessment agent.
Merge the PREVIOUS SUMMARY with the TRANSCRIPT EXCERPT into one updated summary.
Keep: the operator's goals and instructions, scope and authorization, targets and
discovered technology, actions taken and their results, suspected and verified
findings (with ids), decisions, open questions, and next steps.
Drop pleasantries and anything superseded. Plain bullet points, at most 350 words.
Never include secret values; keep placeholders like «secret:…» as they are."""

_MAX_EXCERPT_CHARS = 40_000


def _excerpt(folded: list[Message]) -> str:
    lines = []
    for m in folded:
        if m.role == "tool":
            lines.append(f"[tool {m.name}] {(m.content or '')[:600]}")
        elif m.tool_calls:
            calls = ", ".join(f"{c.name}({c.arguments})" for c in m.tool_calls)
            lines.append(f"[assistant → {calls}] {m.content or ''}".strip())
        elif m.content:
            lines.append(f"[{m.role}] {m.content}")
    text = "\n".join(lines)
    return text[-_MAX_EXCERPT_CHARS:]


@dataclass
class MemoryCompactor:
    findings_provider: FindingsProvider
    provider_getter: ProviderGetter | None = None     # returns the live LLM provider
    max_summary_tokens: int = 700

    def __call__(self, previous: str, folded: list[Message]) -> str:
        body = self._llm_summary(previous, folded) or digest(_strip_index(previous), folded)
        return f"{body.strip()}\n\n{self.findings_index()}"

    def _llm_summary(self, previous: str, folded: list[Message]) -> str | None:
        provider = self.provider_getter() if self.provider_getter else None
        if provider is None:
            return None
        prompt = (f"PREVIOUS SUMMARY:\n{_strip_index(previous) or '(none)'}\n\n"
                  f"TRANSCRIPT EXCERPT:\n{_excerpt(folded)}")
        try:
            resp = provider.complete([Message.system(_INSTRUCTIONS), Message.user(prompt)],
                                     max_tokens=self.max_summary_tokens)
            text = (resp.content or "").strip()
            return text or None
        except Exception:
            return None

    def findings_index(self) -> str:
        findings = self.findings_provider() or []
        if not findings:
            return "findings index: none yet"
        rows = sorted(findings, key=lambda f: f.severity.cvss_score, reverse=True)
        lines = ["findings index (details: list_findings):"]
        for f in rows[:40]:
            mark = "verified" if f.status is Status.VERIFIED else "suspected"
            where = f.target.url or f.target.host
            lines.append(f"- {f.id} [{f.severity.rating.value}] {f.title} · {where} ({mark})")
        return "\n".join(lines)


def _strip_index(summary: str) -> str:
    """The findings index is regenerated each time; don't summarize the old one."""
    head, sep, _ = summary.partition("findings index")
    return head.rstrip() if sep else summary
