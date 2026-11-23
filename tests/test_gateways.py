"""Gateways working together.

1. Every LLM provider routes through LiteLLM with the right route, key and
   endpoint (no network: litellm.completion is captured).
2. One offline session drives every gateway in sequence — long-term memory,
   recon, an MCP server, detection, safe verification, reporting — against a
   real local vulnerable target, then persists memory and the audit trail.
3. The same flow against a real model (opt-in: AUTOPWN_LIVE=1 and a stored
   OpenRouter key).
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import litellm
import pytest
from conftest import ScriptedLLM, call, say
from cryptography.fernet import Fernet

from autopwn.config import Config
from autopwn.engine import EngineSession, _align_llm
from autopwn.eval.targets import PlantedTarget
from autopwn.govern import AuditLog
from autopwn.llm.catalog import PROVIDERS
from autopwn.llm.provider import LLMProvider, Message, ToolSpec
from autopwn.memory import TargetMemory
from autopwn.settings import CredentialStore, Settings

ENDPOINTS = {"azure": "https://example.openai.azure.com",
             "openai_compatible": "http://127.0.0.1:8000/v1"}
EXPECTED_ROUTE = {"openai_compatible": "openai"}


def _fake_response(**_kw):
    msg = SimpleNamespace(content="ok", tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")],
                           usage=SimpleNamespace(prompt_tokens=3, completion_tokens=1, total_tokens=4),
                           model="m", _hidden_params={})


@pytest.mark.parametrize("pid", list(PROVIDERS))
def test_every_provider_routes_through_litellm(pid, tmp_path, monkeypatch):
    info = PROVIDERS[pid]
    model = info.featured[0] if info.featured else f"{pid}/test-model"
    settings = Settings.load(tmp_path / "s.json")
    if pid in ENDPOINTS:
        settings.api_bases[pid] = ENDPOINTS[pid]
    creds = CredentialStore(tmp_path / "c", key=Fernet.generate_key())
    creds.set(pid, f"sk-{pid}-test-123456")
    cfg = Config()
    cfg.llm.model = model
    _align_llm(cfg, settings, creds)

    captured = {}
    monkeypatch.setattr(litellm, "completion", lambda **kw: captured.update(kw) or _fake_response())
    tool = ToolSpec("probe", "p", {"type": "object", "properties": {}})
    resp = LLMProvider(cfg.llm).complete([Message.user("hi")], tools=[tool])

    assert resp.content == "ok"
    route = litellm.get_llm_provider(captured["model"], api_base=captured.get("api_base"))[1]
    assert route == EXPECTED_ROUTE.get(pid, pid)
    assert captured["api_key"] == f"sk-{pid}-test-123456"
    if pid in ENDPOINTS or info.api_base:
        assert captured["api_base"] == (ENDPOINTS.get(pid) or info.api_base)
    assert captured["tools"][0]["function"]["name"] == "probe" and captured["tool_choice"] == "auto"
    assert captured["num_retries"] == 2


MCP_SERVER = '''
from mcp.server import MCPServer
server = MCPServer("advisories")

@server.tool()
def lookup(product: str) -> str:
    """Known advisories for a product."""
    return f"{product}: CVE-2021-23017 (resolver off-by-one)"

if __name__ == "__main__":
    server.run()
'''


def _session(tmp_path, llm, **kw):
    cfg = Config()
    cfg.run.root = str(tmp_path / "runs")
    return EngineSession.create(config=cfg, settings=Settings.load(tmp_path / "settings.json"),
                                credentials=CredentialStore(tmp_path / "c", key=Fernet.generate_key()),
                                memory_path=tmp_path / "memory.db", provider_factory=llm, **kw)


def test_all_gateways_in_one_session(tmp_path):
    pytest.importorskip("mcp.server")
    server = tmp_path / "advisories.py"
    server.write_text(MCP_SERVER)
    with PlantedTarget() as lab:
        host = "127.0.0.1"
        item, search = f"{lab.base_url}/item?id=1", f"{lab.base_url}/search?q=hi"
        llm = ScriptedLLM([
            call("recall_target", cid="m1", host=host),
            call("web_recon", cid="r1", url=lab.base_url),
            call("advisories__lookup", cid="x1", product="nginx"),
            call("advance_phase", cid="p1", to="detection"),
            call("detect_web", cid="d1", url=item),
            call("detect_web", cid="d2", url=search),
            call("advance_phase", cid="p2", to="verify"),
            call("verify_findings", cid="v1"),
            call("advance_phase", cid="p3", to="report"),
            call("generate_report", cid="g1", formats=["json", "md"], style="technical"),
            say("Assessment complete: SQL injection and reflected XSS verified; report written."),
        ])
        s = _session(tmp_path, llm, targets=[host], domain="web")
        s.set_scope(authorized=True)
        s.add_mcp_server("advisories", sys.executable, [str(server)], trusted=True)
        assert s.connect_mcp("advisories") == ["advisories__lookup"]
        events = []
        s.subscribe(lambda r: events.append((r["kind"], r.get("tool"))))

        result = s.chat(f"Assess {lab.base_url} for injection and report.")

        assert result.reason == "stop", result.error
        called = [t for k, t in events if k == "tool.call"]
        assert called == ["recall_target", "web_recon", "advisories__lookup", "advance_phase",
                          "detect_web", "detect_web", "advance_phase", "verify_findings",
                          "advance_phase", "generate_report"]
        assert all(ok for k, ok in ((k, r) for k, r in events if k == "tool.result"))
        mcp_out = next(m.content for m in s.agent.conversation.messages
                       if m.role == "tool" and m.name == "advisories__lookup")
        assert "CVE-2021-23017" in mcp_out
        verified = {f.title for f in s.pipeline.reportable()}
        assert {"SQL Injection", "Reflected Cross-Site Scripting"} <= verified
        reports = {p.suffix for p in (s.ctx.run_dir / "reports").iterdir()}
        assert {".json", ".md"} <= reports
        assert s.planner.phase.value == "report"
        run_dir = s.ctx.run_dir
        s.close()

    mem = TargetMemory.open(tmp_path / "memory.db")
    try:
        assert any(h["title"] == "SQL Injection" for h in mem.target_findings(host))
        assert "SQL injection" in mem.episodes(host)[0]["summary"]
    finally:
        mem.close()
    assert AuditLog.verify(run_dir / "audit.jsonl")
    assert (run_dir / "session.json").is_file() and (run_dir / "conversation.json").is_file()


@pytest.mark.skipif(os.environ.get("AUTOPWN_LIVE") != "1", reason="live: set AUTOPWN_LIVE=1")
def test_live_model_drives_the_agent(tmp_path):
    key = CredentialStore(_real_config_dir()).get("openrouter")
    if not key:
        pytest.skip("no stored OpenRouter key")
    model = os.environ.get("AUTOPWN_LIVE_MODEL", "openrouter/openrouter/free")
    with PlantedTarget() as lab:
        cfg = Config()
        cfg.run.root = str(tmp_path / "runs")
        creds = CredentialStore(tmp_path / "c", key=Fernet.generate_key())
        creds.set("openrouter", key)
        settings = Settings.load(tmp_path / "settings.json")
        settings.model = model
        s = EngineSession.create(config=cfg, settings=settings, credentials=creds,
                                 memory_path=tmp_path / "memory.db", targets=["127.0.0.1"], domain="web")
        s.set_scope(authorized=True)
        events = []
        s.subscribe(lambda r: events.append(r["kind"]))
        result = s.chat(f"Run a safe recon of {lab.base_url} with web_recon and tell me the server and "
                        f"which security headers are missing. Be brief.")
        s.close()
    assert result.reason in ("stop", "finish"), result.error
    assert "tool.call" in events and result.final


def _real_config_dir():
    from pathlib import Path
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autopwn"
