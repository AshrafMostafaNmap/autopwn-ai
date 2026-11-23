"""Short-term memory: the conversation and its context-window budget.

The model sees one system message (preamble + rolling working summary) followed
by the live dialogue. When the dialogue outgrows its budget, the oldest whole
turns are folded into the rolling summary. Folding happens only at the start of
a user turn, so every tool call keeps its result and the dialogue always opens
with a user message (required by several providers).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..llm.provider import LLMResponse, Message, ToolCall

# summarizer(previous_summary, folded_messages) -> new summary
Summarizer = Callable[[str, list[Message]], str]


def estimate_tokens(text: str | None) -> int:
    return max(1, len(text) // 4) if text else 0


def _estimate(m: Message) -> int:
    n = estimate_tokens(m.content)
    for tc in m.tool_calls:
        n += estimate_tokens(tc.name) + estimate_tokens(str(tc.arguments))
    return n + 4


def digest(previous: str, folded: list[Message]) -> str:
    """Deterministic summary: carries the previous summary forward and keeps the
    operator's requests and the latest tool observations."""
    asks = [m.content.strip()[:200] for m in folded if m.role == "user" and m.content]
    notes = [f"- {m.name or 'tool'}: {m.content.strip()[:180]}" for m in folded
             if m.role == "tool" and m.content]
    answers = [m.content.strip()[:240] for m in folded
               if m.role == "assistant" and m.content and not m.tool_calls]
    parts = [previous.strip()] if previous.strip() else []
    if asks:
        parts.append("operator asked:\n" + "\n".join(f"- {a}" for a in asks[-6:]))
    if notes:
        parts.append("observations:\n" + "\n".join(notes[-10:]))
    if answers:
        parts.append(f"last conclusion: {answers[-1]}")
    return "\n".join(parts)


@dataclass
class Conversation:
    window: int = 128_000             # model context window (tokens)
    reserve: int = 4_096              # kept free for the model's reply
    cap: int = 150_000                # never let history grow past this (cost)
    keep_ratio: float = 0.5           # after folding, history fits in this share of the budget
    counter: Callable[[Message], int] = _estimate
    summarizer: Summarizer = digest
    preamble: str = ""
    summary: str = ""
    messages: list[Message] = field(default_factory=list)
    compactions: int = 0
    folded_messages: int = 0

    def set_system(self, *sections: str) -> None:
        self.preamble = "\n\n".join(s for s in sections if s)

    def add_user(self, text: str) -> None:
        self.messages.append(Message.user(text))

    def add_assistant(self, resp: LLMResponse) -> None:
        self.messages.append(Message.assistant(resp.content, resp.tool_calls))

    def add_assistant_text(self, text: str) -> None:
        self.messages.append(Message.assistant(text))

    def add_tool_result(self, call: ToolCall, content: str) -> None:
        self.messages.append(Message.tool(call.id, content, name=call.name))

    def system_message(self) -> Message:
        text = self.preamble
        if self.summary:
            text += ("\n\n## Working memory (earlier in this session, summarized)\n" + self.summary)
        return Message.system(text)

    def render(self) -> list[Message]:
        return [self.system_message(), *self.messages]

    def system_tokens(self) -> int:
        return self.counter(self.system_message())

    def history_tokens(self) -> int:
        return sum(self.counter(m) for m in self.messages)

    def token_estimate(self) -> int:
        return self.system_tokens() + self.history_tokens()

    @property
    def budget(self) -> int:
        room = int((self.window - self.reserve - self.system_tokens()) * 0.85)
        return max(512, min(room, self.cap))        # floor only guards a negative budget

    def usage(self) -> dict:
        system, history = self.system_tokens(), self.history_tokens()
        total = system + history
        return {"system": system, "history": history, "total": total, "window": self.window,
                "budget": self.budget, "percent": round(100 * total / max(1, self.window), 1)}

    def recount(self, counter: Callable[[Message], int] | None = None) -> None:
        """Forget cached counts (e.g. after switching model/tokenizer)."""
        if counter is not None:
            self.counter = counter
        for m in self.messages:
            m.tokens = None

    def maybe_compact(self, *, force: bool = False) -> bool:
        """Fold the oldest turns into the working summary when over budget.
        `force` folds anyway (operator request), as far as turn boundaries allow."""
        if not force and self.history_tokens() <= self.budget:
            return False
        split = self._split_point(int(self.budget * self.keep_ratio))
        if split <= 0:
            return False
        folded, kept = self.messages[:split], self.messages[split:]
        if kept and kept[0].role != "user":
            # mid-turn fold: keep the request that started this turn in front
            first_user = next((m for m in folded if m.role == "user"), None)
            if first_user is not None:
                folded.remove(first_user)
                kept.insert(0, first_user)
        self.summary = self.summarizer(self.summary, folded)
        self.messages = kept
        self.compactions += 1
        self.folded_messages += len(folded)
        return True

    def _split_point(self, target: int) -> int:
        """Earliest user-turn start whose suffix fits `target` tokens; else the
        last user-turn start; for a single huge turn, the latest assistant step
        boundary (never between a tool call and its result)."""
        sizes = [self.counter(m) for m in self.messages]
        suffix = [0] * (len(sizes) + 1)
        for i in range(len(sizes) - 1, -1, -1):
            suffix[i] = suffix[i + 1] + sizes[i]
        user_starts = [i for i, m in enumerate(self.messages) if i > 0 and m.role == "user"]
        for i in user_starts:
            if suffix[i] <= target:
                return i
        if user_starts:
            return user_starts[-1]
        steps = [i for i, m in enumerate(self.messages) if i > 1 and m.role == "assistant"]
        fitting = [i for i in steps if suffix[i] <= target]
        if fitting:
            return fitting[0]
        return steps[-1] if steps else 0
