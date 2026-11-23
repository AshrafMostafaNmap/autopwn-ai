"""Shared fixtures: an isolated app home and a scripted LLM.

Every test that touches settings, credentials, memory or runs gets its own
temporary AUTOPWN_HOME, so the suite never reads or writes the user's real
`~/.config/autopwn` (keys, settings) or `~/.local/share/autopwn` (runs).
"""
from __future__ import annotations

import time

import pytest
from cryptography.fernet import Fernet

from autopwn.config import Config
from autopwn.llm.provider import LLMError, LLMResponse, ToolCall, Usage


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "autopwn-home"
    monkeypatch.setenv("AUTOPWN_HOME", str(home))
    for var in ("AUTOPWN_MODEL", "AUTOPWN_PROFILE", "AUTOPWN_RUN_ROOT", "AUTOPWN_API_BASE"):
        monkeypatch.delenv(var, raising=False)
    import autopwn.recon.installer as installer

    def no_downloads(*_a, **_k):
        raise installer.InstallError("downloads are disabled in tests")
    monkeypatch.setattr(installer, "_http", no_downloads)               # never fetch real scanners
    monkeypatch.setattr(installer, "install_browser", no_downloads)     # nor Chromium
    return home


class ScriptedLLM:
    """A provider stand-in. `script` items are LLMResponse objects, or callables
    (messages, tools) -> LLMResponse, or an Exception instance to raise. When the
    script runs out it answers with a plain final message."""

    def __init__(self, script=None, *, delay: float = 0.0, ready_error: Exception | None = None):
        self.script = list(script or [])
        self.delay = delay
        self.ready_error = ready_error
        self.calls: list[list] = []
        self.tools_seen: list[list] = []

    def __call__(self, _llm_config):          # used as a provider_factory
        return self

    def ensure_ready(self):
        if self.ready_error:
            raise self.ready_error
        return []

    def complete(self, messages, tools=None, **kw):
        self.calls.append(list(messages))
        self.tools_seen.append([t.name for t in (tools or [])])
        if self.delay:
            time.sleep(self.delay)
        if not self.script:
            return LLMResponse(content="done", usage=Usage(total_tokens=3))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            return step(messages, tools)
        return step


def say(text: str, tokens: int = 5) -> LLMResponse:
    return LLMResponse(content=text, usage=Usage(total_tokens=tokens))


def call(name: str, cid: str = "c1", content: str | None = None, **args) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=[ToolCall(cid, name, args)],
                       usage=Usage(total_tokens=5))


@pytest.fixture
def make_session(tmp_path):
    """Build an EngineSession fully contained in tmp_path."""
    from autopwn.engine import EngineSession
    from autopwn.settings import CredentialStore, Settings
    made = []

    shared_creds = CredentialStore(tmp_path / "creds", key=Fernet.generate_key())

    def _make(provider=None, *, targets=None, domain=None, settings=None, creds=None, resume=None,
              first_run=False):
        cfg = Config()
        cfg.run.root = str(tmp_path / "runs")
        if settings is None:
            settings = Settings.load(tmp_path / "settings.json")
            settings.setup_done = settings.setup_done or not first_run
        s = EngineSession.create(
            config=cfg,
            settings=settings,
            credentials=creds or shared_creds,
            memory_path=tmp_path / "memory.db",
            targets=targets, domain=domain, resume=resume,
            provider_factory=provider or ScriptedLLM())
        made.append(s)
        return s

    yield _make
    for s in made:
        s.close()


__all__ = ["ScriptedLLM", "say", "call", "LLMError"]
