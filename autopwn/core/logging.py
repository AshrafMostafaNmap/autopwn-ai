"""Structured event log (events.jsonl) with key-based redaction and subscriber
sinks. Thread-safe.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from rich.console import Console

# Keys whose values must never be written to the event log.
_SECRET_KEYS = {
    "api_key", "apikey", "authorization", "auth", "token", "password", "passwd",
    "secret", "cookie", "set-cookie", "session", "bearer", "credential",
}
_REDACTION = "«redacted»"

_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}


def redact(obj: Any) -> Any:
    """Replace values of secret-looking keys before they are logged (a safety
    net behind the vault/redactor)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _SECRET_KEYS:
                out[k] = _REDACTION
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


@dataclass
class EventLogger:
    """Writes structured events to `events.jsonl` and mirrors to the console.

    Use via `RunContext.logger`; construct directly only in tests.
    """
    path: Path
    level: str = "info"
    console: Console | None = None
    json_enabled: bool = True
    # Subscribers notified with every (already-redacted) record — how the TUI
    # receives live engine events without touching stdout.
    sinks: list[Callable[[dict], None]] = field(default_factory=list)
    _fh: TextIO | None = None

    def __post_init__(self) -> None:
        if self.json_enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")
        self._threshold = _LEVELS.get(self.level, 20)
        self._lock = threading.Lock()

    def add_sink(self, sink: Callable[[dict], None]) -> None:
        self.sinks.append(sink)

    def event(self, kind: str, *, level: str = "info", **fields: Any) -> dict:
        """Record one event. `kind` is a dotted verb like 'run.start',
        'llm.call', 'tool.result', 'phase.enter', 'finding.verified'.
        Thread-safe: the agent loop logs from a worker thread."""
        rec = {
            "ts": round(time.time(), 3),
            "level": level,
            "kind": kind,
            **redact(fields),
        }
        with self._lock:
            if self._fh is not None:
                self._fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                self._fh.flush()
            if self.console is not None and _LEVELS.get(level, 20) >= self._threshold:
                self._echo(rec)
        for sink in list(self.sinks):
            try:
                sink(rec)
            except Exception:
                pass                        # a broken subscriber never breaks the engine
        return rec

    def debug(self, kind: str, **f: Any) -> dict:   return self.event(kind, level="debug", **f)
    def info(self, kind: str, **f: Any) -> dict:    return self.event(kind, level="info", **f)
    def warning(self, kind: str, **f: Any) -> dict: return self.event(kind, level="warning", **f)
    def error(self, kind: str, **f: Any) -> dict:   return self.event(kind, level="error", **f)

    def _echo(self, rec: dict) -> None:
        colors = {"debug": "dim", "info": "cyan", "warning": "yellow", "error": "red"}
        style = colors.get(rec["level"], "white")
        extra = {k: v for k, v in rec.items() if k not in ("ts", "level", "kind")}
        tail = "  ".join(f"{k}={v}" for k, v in extra.items())
        self.console.print(f"[dim]·[/] [{style}]{rec['kind']}[/]  {tail}", highlight=False)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
