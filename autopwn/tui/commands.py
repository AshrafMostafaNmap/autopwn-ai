"""App commands: one table for `/name` in the prompt, the Ctrl+P menu and
Ctrl+X leader shortcuts."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Command:
    name: str          # typed as /name
    action: str        # App method: action_<action>
    help: str
    key: str = ""      # leader key: ctrl+x <key>
    arg: str = ""


COMMANDS: tuple[Command, ...] = (
    Command("new", "new_session", "start a new session", "n"),
    Command("sessions", "open_sessions", "resume an earlier session", "l"),
    Command("model", "open_model", "switch model", "m", "[provider/model]"),
    Command("provider", "open_provider", "connect a provider (API key / endpoint)", "p"),
    Command("mcp", "open_mcp", "MCP servers: connect, add, presets", "g"),
    Command("scope", "open_scope", "targets, authorization, domain", "s"),
    Command("mode", "toggle_mode", "autonomous ⇄ human-in-the-loop", "", "[auto|hitl]"),
    Command("tools", "open_tools", "tools the agent can use", "t"),
    Command("context", "open_context", "context window and memory", "i"),
    Command("compact", "compact", "summarize older turns now", "c"),
    Command("findings", "open_findings", "findings with evidence and fixes", "f"),
    Command("report", "open_report", "generate the report", "r"),
    Command("memory", "open_memory", "long-term memory by target", "y"),
    Command("copy", "copy", "copy the last answer to the clipboard", "o", "[all|N]"),
    Command("export", "export", "export the whole chat (txt / md / html)", "x", "[txt|md|html] [clean]"),
    Command("setup", "setup", "run the setup wizard again", "w"),
    Command("help", "help", "keys and commands", "h"),
    Command("quit", "save_quit", "save and exit", "q"),
)


@dataclass(frozen=True)
class Variant:
    """A ready-made `/command arg` offered by the autocomplete and the menu."""
    text: str          # "copy all" → typed as /copy all
    help: str


VARIANTS: tuple[Variant, ...] = (
    Variant("copy all", "copy the whole chat as clean text"),
    Variant("export txt", "export the chat as a clean .txt file"),
    Variant("export txt full", "export as .txt, including tool activity"),
    Variant("export md", "export the chat as Markdown"),
    Variant("export html", "export the chat as a styled HTML page"),
)

BY_NAME = {c.name: c for c in COMMANDS}
BY_KEY = {c.key: c for c in COMMANDS if c.key}
ALIASES = {"connect": "provider", "models": "model", "providers": "provider", "exit": "quit",
           "q": "quit", "resume": "sessions", "clear": "new", "?": "help", "servers": "mcp"}


def parse(text: str) -> tuple[Command, str] | None:
    if not text.startswith("/"):
        return None
    head, _, arg = text[1:].strip().partition(" ")
    cmd = BY_NAME.get(ALIASES.get(head.lower(), head.lower()))
    return (cmd, arg.strip()) if cmd else None


def matches(prefix: str) -> list[Command]:
    """Commands for the `/` autocomplete: name prefix first, then help text."""
    p = prefix.lower().lstrip("/")
    first = [c for c in COMMANDS if c.name.startswith(p)]
    rest = [c for c in COMMANDS if c not in first and p and p in c.help.lower()]
    return first + rest


def suggestions(prefix: str) -> list[tuple[str, str]]:
    """(text, help) rows for the autocomplete: commands, each followed by its
    ready-made variants; once a space is typed, only the matching variants."""
    p = prefix.lower().lstrip("/")
    if " " in p:
        return [(v.text, v.help) for v in VARIANTS if v.text.startswith(p) and v.text != p.strip()]
    rows: list[tuple[str, str]] = []
    for c in matches(p):
        rows.append((c.name, c.help))
        rows += [(v.text, v.help) for v in VARIANTS if v.text.split()[0] == c.name]
    return rows
