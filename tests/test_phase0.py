"""Phase-0 foundation tests: config, store, run context, LLM adapter types.

No network: the LLM provider is tested for its types, capability gate, and
message/tool serialization — the live round-trip is exercised by `autopwn doctor`
and `autopwn run` against a real key, not in unit tests.
"""
from __future__ import annotations

import json

import pytest

from autopwn.config import Config, ConfigError, LLMConfig, load_config
from autopwn.core.context import RunContext, new_run_id
from autopwn.core.findings import Finding, Severity, SeverityInfo, Status, Target
from autopwn.core.logging import redact
from autopwn.core.store import StateStore
from autopwn.llm.provider import (
    LLMProvider,
    Message,
    MissingAPIKey,
    ModelNotToolCapable,
    ToolCall,
    ToolSpec,
)


def test_defaults_without_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)          # no config.toml here
    monkeypatch.delenv("AUTOPWN_CONFIG", raising=False)
    cfg = load_config()
    assert cfg.source is None
    assert "safe" in cfg.profiles
    assert cfg.active_profile().destructive is False


def test_loads_toml(tmp_path):
    (tmp_path / "config.toml").write_text(
        '[llm]\nmodel="openai/gpt-4o"\n[run]\nprofile="standard"\n'
        '[profiles.standard]\nmax_steps=99\n'
    )
    cfg = load_config(tmp_path / "config.toml")
    assert cfg.llm.model == "openai/gpt-4o"
    assert cfg.active_profile().max_steps == 99


def test_unknown_key_errors(tmp_path):
    (tmp_path / "config.toml").write_text('[llm]\nnope=1\n')
    with pytest.raises(ConfigError):
        load_config(tmp_path / "config.toml")


def test_env_override(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text('[llm]\nmodel="a/b"\n')
    monkeypatch.setenv("AUTOPWN_MODEL", "x/y")
    cfg = load_config(tmp_path / "config.toml")
    assert cfg.llm.model == "x/y"


def test_api_key_resolves_from_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "sk-secret")
    llm = LLMConfig(api_key_env="MY_KEY")
    assert llm.api_key() == "sk-secret"


def _finding(fid="F-1", status=Status.VERIFIED, score=9.1):
    return Finding(
        id=fid, title="SQLi in login", target=Target(host="juice.company.lab", url="/login"),
        severity=SeverityInfo(cvss_score=score, rating=Severity.from_cvss(score)),
        owasp="A03", cwe="CWE-89", status=status,
        detection_guidance="watch for 500s w/ SQL errors", remediation="parameterize queries",
    )


def test_store_run_and_findings():
    s = StateStore.in_memory()
    s.record_run("r1", goal="g", targets=["t"], profile="safe", model="m")
    s.save_finding("r1", _finding("F-1", Status.VERIFIED, 9.1))
    s.save_finding("r1", _finding("F-2", Status.SUSPECTED, 5.0))
    assert len(s.findings("r1")) == 2
    reportable = s.reportable_findings("r1")        # FP filter: verified only
    assert len(reportable) == 1
    assert reportable[0]["id"] == "F-1"
    # ordered by cvss desc
    assert s.findings("r1")[0]["severity"]["cvss_score"] == 9.1


def test_store_upsert_finding_status_change():
    s = StateStore.in_memory()
    s.record_run("r1", goal="g", targets=[], profile="safe", model="m")
    s.save_finding("r1", _finding("F-1", Status.SUSPECTED, 7.0))
    assert len(s.reportable_findings("r1")) == 0
    s.save_finding("r1", _finding("F-1", Status.VERIFIED, 7.0))   # same id upserts
    assert len(s.findings("r1")) == 1
    assert len(s.reportable_findings("r1")) == 1


def test_store_memory_roundtrip():
    s = StateStore.in_memory()
    s.remember("host.lab", "tech", {"server": "nginx", "php": True})
    assert s.recall("host.lab", "tech")["server"] == "nginx"
    s.remember("host.lab", "tech", {"server": "apache"})           # upsert
    assert s.recall("host.lab", "tech")["server"] == "apache"
    assert "tech" in s.recall("host.lab")


def test_store_targets():
    s = StateStore.in_memory()
    s.record_run("r1", goal="g", targets=[], profile="safe", model="m")
    s.upsert_target("r1", "h1", url="http://h1", domain="web", fingerprint={"stack": "LAMP"})
    rows = s.targets("r1")
    assert rows[0]["domain"] == "web"
    assert json.loads(rows[0]["fingerprint"])["stack"] == "LAMP"


def test_run_id_shape():
    rid = new_run_id()
    assert len(rid.split("-")) == 3        # date-time-short


def test_run_context_creates_layout(tmp_path):
    cfg = Config(profiles={"safe": __import__("autopwn.config", fromlist=["ProfileConfig"]).ProfileConfig()})
    cfg.run.root = str(tmp_path / "runs")
    cfg.logging.console = False
    ctx = RunContext.create(cfg, goal="scan", targets=["t1"])
    assert (ctx.run_dir / "run.json").is_file()
    assert (ctx.run_dir / "artifacts").is_dir()
    assert (ctx.run_dir / "state.db").is_file()
    meta = json.loads((ctx.run_dir / "run.json").read_text())
    assert meta["goal"] == "scan"
    assert meta["config"]["llm"]["api_key_env"]      # name kept, value never
    ctx.finish("completed")                 # closes the store
    reopened = StateStore.open(ctx.run_dir / "state.db")
    assert reopened.get_run(ctx.run_id)["status"] == "completed"
    reopened.close()


def test_config_snapshot_has_no_secret_value(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-appear")
    cfg = Config()
    cfg.run.root = str(tmp_path / "runs")
    cfg.logging.console = False
    ctx = RunContext.create(cfg, goal="g", targets=[])
    blob = (ctx.run_dir / "run.json").read_text()
    assert "sk-should-not-appear" not in blob
    ctx.finish()


def test_redact_nested():
    out = redact({"api_key": "x", "nested": {"cookie": "y", "ok": 1}, "list": [{"token": "z"}]})
    assert out["api_key"] == "«redacted»"
    assert out["nested"]["cookie"] == "«redacted»"
    assert out["nested"]["ok"] == 1
    assert out["list"][0]["token"] == "«redacted»"


def test_message_openai_shape():
    m = Message.assistant(tool_calls=[ToolCall(id="c1", name="nmap", arguments={"host": "h"})])
    d = m.to_openai()
    assert d["tool_calls"][0]["function"]["name"] == "nmap"
    assert json.loads(d["tool_calls"][0]["function"]["arguments"])["host"] == "h"
    t = Message.tool("c1", "open: 80,443", name="nmap").to_openai()
    assert t["role"] == "tool" and t["tool_call_id"] == "c1"


def test_toolspec_openai_shape():
    spec = ToolSpec("httpx", "probe http", {"type": "object", "properties": {"url": {"type": "string"}}})
    d = spec.to_openai()
    assert d["type"] == "function"
    assert d["function"]["name"] == "httpx"


def test_gate_rejects_non_tool_model(monkeypatch):
    llm = LLMConfig(model="anthropic/claude-sonnet-4-5", api_key_env="K", require_tool_calling=True)
    monkeypatch.setenv("K", "sk-x")
    p = LLMProvider(llm)
    monkeypatch.setattr(p, "tool_support", lambda: False)   # catalog says: no tools
    with pytest.raises(ModelNotToolCapable):
        p.ensure_ready()


def test_gate_requires_key(monkeypatch):
    llm = LLMConfig(model="anthropic/claude-sonnet-4-5", api_key_env="ABSENT_KEY")
    monkeypatch.delenv("ABSENT_KEY", raising=False)
    p = LLMProvider(llm)
    monkeypatch.setattr(p, "supports_tools", lambda: True)
    with pytest.raises(MissingAPIKey):
        p.ensure_ready()


def test_gate_local_model_needs_no_key(monkeypatch):
    import autopwn.llm.catalog as catalog
    monkeypatch.setattr(catalog, "endpoint_reachable", lambda base, timeout=1.5: True)
    llm = LLMConfig(model="ollama/llama3.1", api_base="http://localhost:11434",
                    api_key_env="", require_tool_calling=False)
    p = LLMProvider(llm)
    p.ensure_ready()        # server up, no key, no tools required → passes


def test_gate_unknown_model_is_allowed_with_warning(monkeypatch):
    """A model the catalog doesn't know (local / brand-new) is not rejected —
    it passes with a warning; only a model KNOWN not to support tools is refused."""
    llm = LLMConfig(model="anthropic/brand-new-model", api_key_env="K")
    monkeypatch.setenv("K", "sk-x")
    p = LLMProvider(llm)
    monkeypatch.setattr(p, "tool_support", lambda: None)
    warnings = p.ensure_ready()
    assert warnings and "unverified" in warnings[0]


def test_requires_key_follows_the_model_prefix():
    # provider field left at its default — the model id decides
    assert LLMConfig(model="ollama/llama3.1").requires_key is False
    assert LLMConfig(model="openai/gpt-4.1").requires_key is True


def test_runtime_key_value_takes_precedence(monkeypatch):
    monkeypatch.setenv("K", "from-env")
    llm = LLMConfig(api_key_env="K", api_key_value="from-store")
    assert llm.api_key() == "from-store"
    assert "from-store" not in repr(llm)          # never shown in repr/logs
