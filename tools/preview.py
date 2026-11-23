"""Capture screenshots of the real app (headless, scripted model) into docs/preview/.

    python tools/preview.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("AUTOPWN_HOME", tempfile.mkdtemp(prefix="autopwn-preview-"))

from cryptography.fernet import Fernet  # noqa: E402

from autopwn.config import Config  # noqa: E402
from autopwn.core.findings import Status  # noqa: E402
from autopwn.detect.model import Candidate  # noqa: E402
from autopwn.engine import EngineSession  # noqa: E402
from autopwn.llm.provider import LLMResponse, ToolCall, Usage  # noqa: E402
from autopwn.settings import CredentialStore, Settings, config_dir  # noqa: E402
from autopwn.tui.app import AutoPwnApp  # noqa: E402

OUT = ROOT / "docs" / "preview"


class ScriptedModel:
    """Plays back a short, realistic turn so the screenshots show real widgets."""

    def __init__(self) -> None:
        self.script = [
            LLMResponse(content="Starting with what I already know, then a safe recon.",
                        tool_calls=[ToolCall("a", "recall_target", {"host": "juice.lab"})],
                        usage=Usage(total_tokens=820)),
            LLMResponse(content=None, tool_calls=[ToolCall("b", "web_recon", {"url": "http://juice.lab"})],
                        usage=Usage(total_tokens=640)),
            LLMResponse(content="## Recon summary\n\n- **juice.lab** runs **nginx 1.18** + Express\n"
                                "- missing CSP and HSTS\n- `/rest/products/search` takes a `q` parameter\n\n"
                                "Next: probe `q` for injection in the detection phase.",
                        usage=Usage(total_tokens=410)),
        ]

    def __call__(self, _llm_config):
        return self

    def ensure_ready(self):
        return []

    def complete(self, messages, tools=None, **kw):
        return self.script.pop(0) if self.script else LLMResponse(content="done", usage=Usage(total_tokens=5))


def factory(resume=None):
    cfg = Config()
    cfg.run.root = str(config_dir() / "runs")
    creds = CredentialStore(config_dir() / "creds", key=Fernet.generate_key())
    creds.set("openrouter", "sk-or-preview")
    settings = Settings.load(config_dir() / "settings.json")
    settings.model = "openrouter/openrouter/free"
    settings.setup_done = True
    s = EngineSession.create(config=cfg, settings=settings, credentials=creds, memory_path=config_dir() / "m.db",
                             targets=["juice.lab"], domain="web", provider_factory=ScriptedModel())
    s.set_scope(authorized=True)
    return s


async def capture() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = AutoPwnApp(session_factory=factory)
    async with app.run_test(size=(140, 38)) as pilot:
        await pilot.pause(0.8)
        app.save_screenshot("01_home.svg", path=str(OUT))
        app.main.prompt.value = "map juice.lab and tell me what it runs"
        await pilot.press("enter")
        for _ in range(80):
            await pilot.pause(0.1)
            if not app.session.busy and app.main._working is None:
                break
        f = app.session.pipeline.add(Candidate("sqli", host="juice.lab", param="q",
                                               url="http://juice.lab/rest/products/search?q=x"))
        f.status = Status.VERIFIED
        app.main.on_engine({"kind": "verify", "verified": True, "finding": f.id, "method": "boolean"})
        await pilot.pause(0.3)
        app.save_screenshot("02_session.svg", path=str(OUT))
        for name, action in (("03_commands", app.action_command_menu), ("04_mcp", app.action_open_mcp),
                             ("05_context", app.action_open_context)):
            action()
            await pilot.pause(0.5)
            app.save_screenshot(f"{name}.svg", path=str(OUT))
            await pilot.press("escape")
            await pilot.pause(0.2)
        app.action_save_quit()


if __name__ == "__main__":
    asyncio.run(capture())
    print("wrote", OUT)
