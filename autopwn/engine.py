"""EngineSession: the single place the agent and everything around it is assembled.

Used by both front-ends: the app keeps a session open and chats turn by turn; the
one-shot CLI opens one, runs a goal and closes it. `chat()` blocks for a whole
turn, so callers run it on a worker thread. Events reach subscribers through the
run logger's sinks; HITL approvals go through an injected `approver`.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .agent import Agent, ApprovalDecision, ApprovalGate, Budget, Mode, Planner, ToolRegistry
from .agent.builtins import register_builtins
from .agent.conversation import Conversation
from .agent.loop import AgentResult
from .agent.planner import Phase, methodology_for
from .browser.engine import BrowserEngine
from .browser.tools import register_browser_tools
from .browser.workflow import register_workflows
from .config import Config, apply_env_overrides, load_config
from .core.context import RunContext
from .core.findings import Finding
from .detect import CoverageTracker, FindingsPipeline, SafeVerifier, register_detection_tools
from .govern import Acknowledgement, AuditLog, Redactor, Vault
from .govern.scope import ScopeGuard
from .llm.catalog import PROVIDERS, endpoint_reachable, is_local_endpoint, provider_of, warm_live
from .llm.provider import LLMError, LLMProvider, _has_credentials
from .llm.provider import Message as LLMMessage
from .llm.tokens import context_window, make_counter
from .mcp import PRESETS, MCPManager, MCPServerConfig
from .memory import KnowledgeBase, MemoryCompactor, TargetMemory, register_memory_tools
from .memory.brief import long_term_brief
from .recon import TargetModel, register_recon_tools
from .recon.scanners import register_scanner_tools
from .report import ReportBuilder, ReportMeta, register_report_tools
from .settings import CredentialStore, Settings, data_dir, mask
from .transcript import TRANSCRIPT_FILE, ExportMeta, Transcript, entries_from_messages, read_entries
from .transcript import export as export_transcript

Approver = Callable[[Any, Any], bool]
ProviderFactory = Callable[[Any], Any]          # (LLMConfig) -> provider

SESSION_FILE = "session.json"
CONVERSATION_FILE = "conversation.json"


@dataclass
class ReadyState:
    ok: bool
    message: str = ""
    warnings: list[str] = field(default_factory=list)


class EngineSession:
    # ── construction ──────────────────────────────────────────────────────────
    @classmethod
    def create(cls, *, config: Config | None = None, config_path: str | None = None,
               settings: Settings | None = None, credentials: CredentialStore | None = None,
               memory_path: str | Path | None = None, goal: str = "interactive session",
               targets: list[str] | None = None, domain: str | None = None, echo: bool = False,
               console=None, provider_factory: ProviderFactory | None = None,
               ephemeral: bool = False, resume: str | Path | None = None) -> EngineSession:
        """`ephemeral` puts the run folder in a temp dir that is removed on close
        (status checks). `resume` reopens an earlier session's run folder."""
        cfg = config or load_config(config_path)
        settings = settings if settings is not None else Settings.load()
        creds = credentials if credentials is not None else CredentialStore()

        if settings.model:
            cfg.llm.model = settings.model
        if settings.profile:
            cfg.run.profile = settings.profile
        apply_env_overrides(cfg)
        _align_llm(cfg, settings, creds)

        auto_selected = None
        if not settings.model and not os.environ.get("AUTOPWN_MODEL"):
            auto_selected = _usable_fallback(cfg, creds)
            if auto_selected:
                cfg.llm.model = auto_selected
                _align_llm(cfg, settings, creds)

        cfg.run.root = str(runs_root(cfg))
        ephemeral_root = None
        if ephemeral:
            ephemeral_root = tempfile.mkdtemp(prefix="autopwn-check-")
            cfg.run.root = ephemeral_root
        cfg.logging.console = echo

        if resume:
            ctx = RunContext.resume(cfg, Path(resume), console=console)
        else:
            ctx = RunContext.create(cfg, goal=goal, console=console,
                                    targets=list(targets if targets is not None else cfg.scope.in_scope))
        session = cls(cfg, settings, creds, ctx, domain=domain, memory_path=memory_path,
                      provider_factory=provider_factory)
        session._ephemeral_root = ephemeral_root
        session.auto_selected = auto_selected
        if resume:
            session._restore()
        return session

    def __init__(self, cfg: Config, settings: Settings, creds: CredentialStore, ctx: RunContext,
                 *, domain: str | None, memory_path, provider_factory: ProviderFactory | None):
        self.config, self.settings, self.creds, self.ctx = cfg, settings, creds, ctx
        self._provider_factory = provider_factory or LLMProvider
        self._provider = None
        self._approver: Approver | None = None
        self._turn_lock = threading.Lock()
        self._closed = False
        self._ephemeral_root: str | None = None
        self._brief = ""
        self.auto_selected: str | None = None
        self.last_warnings: list[str] = []
        self.title = ""
        self.turns = 0
        self.last_answer = ""
        self.created = time.time()

        self.vault = Vault.open()
        self.redactor = Redactor(self.vault)
        self.audit = AuditLog.open(ctx.run_dir / "audit.jsonl")
        self.transcript = Transcript(ctx.run_dir / TRANSCRIPT_FILE)

        self.target_model = TargetModel(ctx)
        self.pipeline = FindingsPipeline(ctx)
        self.verifier = SafeVerifier()
        self.coverage = CoverageTracker()
        self.memory = TargetMemory.open(memory_path)
        self.kb = KnowledgeBase()

        self.planner = Planner(domain=domain)
        self.registry = ToolRegistry()
        register_builtins(self.registry, self.planner)
        register_recon_tools(self.registry, ctx=ctx, vault=self.vault, redactor=self.redactor,
                             target_model=self.target_model)
        register_scanner_tools(self.registry, ctx=ctx, vault=self.vault, redactor=self.redactor,
                               target_model=self.target_model, pipeline=self.pipeline)
        self._browser: BrowserEngine | None = None
        register_browser_tools(self.registry, engine=self.browser, ctx=ctx, pipeline=self.pipeline,
                               target_model=self.target_model, redactor=self.redactor)
        register_detection_tools(self.registry, ctx=ctx, pipeline=self.pipeline,
                                 verifier=self.verifier, coverage=self.coverage,
                                 target_model=self.target_model, redactor=self.redactor)
        register_report_tools(self.registry, ctx=ctx, pipeline=self.pipeline)
        register_memory_tools(self.registry, ctx=ctx, memory=self.memory, kb=self.kb)
        self.mcp = MCPManager(self.registry, log_dir=ctx.run_dir)
        register_workflows(self.registry, ctx=ctx)
        self.registry.guard = ScopeGuard(lambda: list(self.ctx.targets),
                                         lambda: list(self.config.scope.out_of_scope),
                                         lambda: bool(self.config.scope.authorized_ack))

        conversation = Conversation(
            window=context_window(cfg.llm.model), reserve=cfg.llm.max_tokens + 512,
            counter=make_counter(cfg.llm.model),
            summarizer=MemoryCompactor(findings_provider=self.pipeline.all,
                                       provider_getter=lambda: self._provider))
        mode = Mode.HITL if settings.mode == "hitl" else Mode.AUTONOMOUS
        self.agent = Agent(None, self.registry, config=cfg, planner=self.planner,
                           conversation=conversation, gate=ApprovalGate(mode, self._decide),
                           budget=Budget.from_config(cfg), ctx=ctx, targets=ctx.targets,
                           context=self._prompt_context)

        for t in ctx.targets:
            self.coverage.expect_target(t, domain or "web")
        self.audit.acknowledge(Acknowledgement(
            operator=settings.operator or "operator", in_scope=list(ctx.targets),
            out_of_scope=list(cfg.scope.out_of_scope), authorized=cfg.scope.authorized_ack,
            profile=cfg.run.profile))
        self.audit.record("session.start", model=cfg.llm.model, mode=mode.value)
        ctx.logger.add_sink(self._record_event)

    def subscribe(self, sink: Callable[[dict], None]) -> None:
        """Receive every (redacted) engine event, on the agent's thread."""
        self.ctx.logger.add_sink(sink)

    # ── provider / model ──────────────────────────────────────────────────────
    @property
    def model(self) -> str:
        return self.config.llm.model

    @property
    def provider_id(self) -> str:
        return self.config.llm.provider

    @property
    def provider(self):
        return self._provider

    def _build_provider(self):
        self._provider = self._provider_factory(self.config.llm)
        self.agent.provider = self._provider
        return self._provider

    def ready(self) -> ReadyState:
        """Can the session talk to its model right now? Never raises."""
        try:
            provider = self._provider or self._build_provider()
            warnings = provider.ensure_ready() if hasattr(provider, "ensure_ready") else []
            self.last_warnings = list(warnings or [])
            self._refresh_window()
            return ReadyState(True, f"{self.model} ready", self.last_warnings)
        except Exception as e:
            return ReadyState(False, str(e))

    def _refresh_window(self) -> None:
        """Size the context budget from the model's real window (live catalogs
        such as OpenRouter are only known once fetched)."""
        warm_live(self.provider_id)
        self.agent.conversation.window = context_window(self.model)

    def set_model(self, model_id: str, *, api_base: str | None = None) -> ReadyState:
        self.settings.model = model_id
        self.settings.provider = provider_of(model_id)
        if api_base:
            self.settings.api_bases[self.settings.provider] = api_base
        self.config.llm.model = model_id
        _align_llm(self.config, self.settings, self.creds)
        warm_live(self.provider_id)
        conv = self.agent.conversation
        conv.window = context_window(model_id)
        conv.recount(make_counter(model_id))
        self._provider = None
        self._save_settings()
        self.audit.record("model.change", model=model_id)
        return self.ready()

    def connect_provider(self, provider_id: str, key: str | None = None, *,
                         api_base: str | None = None) -> ReadyState:
        """Store a provider key (encrypted, local) and/or endpoint."""
        if key:
            self.creds.set(provider_id, key)
        if api_base:
            self.settings.api_bases[provider_id] = api_base
            self._save_settings()
        self.audit.record("provider.connect", provider=provider_id, key_stored=bool(key))
        if provider_id == self.provider_id:
            _align_llm(self.config, self.settings, self.creds)
            self._provider = None
            return self.ready()
        label = PROVIDERS[provider_id].label if provider_id in PROVIDERS else provider_id
        return ReadyState(True, f"{label} saved")

    def disconnect_provider(self, provider_id: str) -> bool:
        removed = self.creds.delete(provider_id)
        if provider_id == self.provider_id:
            _align_llm(self.config, self.settings, self.creds)
            self._provider = None
        self.audit.record("provider.disconnect", provider=provider_id)
        return removed

    def provider_status(self) -> list[dict]:
        bases = {p.id: self.settings.api_bases.get(p.id) or p.api_base for p in PROVIDERS.values()}
        running = _probe_local({pid: b for pid, b in bases.items() if is_local_endpoint(b)})
        rows = []
        for p in PROVIDERS.values():
            stored = self.creds.get(p.id)
            env = os.environ.get(p.env_var) if p.env_var else None
            if stored:
                source, connected = "stored", True
            elif env:
                source, connected = f"env ${p.env_var}", True
            elif p.credentials_env:
                found = next((v for v in p.credentials_env if os.environ.get(v)), None)
                if found:
                    source, connected = f"env ${found}", True
                elif _has_credentials(()):
                    source, connected = "~/.aws/credentials", True
                else:
                    source, connected = "no credentials found", False
            elif not p.requires_key:
                source, connected = "no key needed", True
            else:
                source, connected = "—", False
            if p.needs_api_base and not bases[p.id]:
                source, connected = "needs an endpoint", False
            elif p.id in running and not running[p.id]:
                source, connected = "not running", False
            rows.append({"id": p.id, "label": p.label, "connected": connected, "source": source,
                         "key": mask(stored or env),
                         "api_base": bases[p.id],
                         "active": p.id == self.provider_id, "note": p.note,
                         "needs_api_base": p.needs_api_base})
        return rows

    # ── chat ──────────────────────────────────────────────────────────────────
    def chat(self, message: str) -> AgentResult:
        """Run one turn (blocking)."""
        with self._turn_lock:
            self.transcript.add("user", text=message)
            state = self.ready()
            if not state.ok:
                self.transcript.add("answer", text="", error=state.message)
                return AgentResult(final=None, reason="error", steps=0, tokens=0,
                                   phase=self.planner.phase.value, error=state.message)
            self._brief = self._long_term_brief()
            cost_before = self.agent.budget.total_cost
            self.title = self.title or message.strip().splitlines()[0][:80]
            self.audit.record("chat.turn", chars=len(message))
            try:
                result = self.agent.run(message)
            except LLMError as e:
                result = AgentResult(final=None, reason="error", steps=0, tokens=0,
                                     phase=self.planner.phase.value, error=str(e))
            self.turns += 1
            if result.final:
                self.last_answer = result.final
            error = result.error or ("interrupted" if result.reason == "cancelled" else "")
            self.transcript.add("answer", text=result.final or "", error=error, tokens=result.tokens,
                                cost=round(self.agent.budget.total_cost - cost_before, 6))
            self.save_state()
            return result

    def cancel(self) -> None:
        self.agent.cancel()

    @property
    def busy(self) -> bool:
        return self._turn_lock.locked()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        if self._turn_lock.acquire(timeout=timeout):
            self._turn_lock.release()
            return True
        return False

    def _prompt_context(self) -> dict:
        return {"model": self.model, "memory": self._brief,
                "mcp_servers": self.mcp.connected_names()}

    def _long_term_brief(self) -> str:
        try:
            return long_term_brief(self.memory, self.targets)
        except Exception:
            return ""

    # ── approvals / mode ──────────────────────────────────────────────────────
    def set_approver(self, approver: Approver | None) -> None:
        self._approver = approver

    def _decide(self, call, tool) -> ApprovalDecision:
        if self._approver is None:
            auto = self.agent.gate.mode is Mode.AUTONOMOUS    # nobody to ask: HITL fails closed
            return ApprovalDecision(auto, "auto" if auto else "no operator available")
        approved = bool(self._approver(call, tool))
        self.audit.record("approval", tool=tool.name, approved=approved)
        return ApprovalDecision(approved, "operator" if approved else "declined by operator")

    @property
    def mode(self) -> str:
        return "hitl" if self.agent.gate.mode is Mode.HITL else "autonomous"

    def set_mode(self, mode: str) -> None:
        self.agent.gate.mode = Mode.HITL if mode == "hitl" else Mode.AUTONOMOUS
        self.settings.mode = self.mode
        self._save_settings()
        self.audit.record("mode.change", mode=self.mode)

    # ── scope ─────────────────────────────────────────────────────────────────
    def set_scope(self, *, targets: list[str] | None = None, out_of_scope: list[str] | None = None,
                  authorized: bool | None = None, domain: str | None = None) -> None:
        sc = self.config.scope
        if targets is not None:
            clean = [t.strip() for t in targets if t and t.strip()]
            self.ctx.targets[:] = clean                    # the agent shares this list
            sc.in_scope = list(clean)
        if out_of_scope is not None:
            sc.out_of_scope = [t.strip() for t in out_of_scope if t and t.strip()]
        if authorized is not None:
            sc.authorized_ack = bool(authorized)
        if domain:
            self.planner.domain = domain
            self.planner.methodology = methodology_for(domain)
        for t in self.ctx.targets:
            self.coverage.expect_target(t, self.planner.domain or "web")
        self.audit.acknowledge(Acknowledgement(
            operator=self.settings.operator or "operator", in_scope=list(self.ctx.targets),
            out_of_scope=list(sc.out_of_scope), authorized=sc.authorized_ack,
            profile=self.config.run.profile))

    @property
    def targets(self) -> list[str]:
        return list(self.ctx.targets)

    @property
    def authorized(self) -> bool:
        return self.config.scope.authorized_ack

    # ── introspection ─────────────────────────────────────────────────────────
    def tools_info(self) -> list[dict]:
        return [{"name": t.name, "description": t.description, "source": t.source,
                 "phase": t.phase or "any", "approval": t.requires_approval}
                for t in self.registry.tools()]

    def context_stats(self) -> dict:
        conv = self.agent.conversation
        usage = conv.usage()
        budget = self.agent.budget
        return {
            "model": self.model, "provider": self.provider_id,
            "context_window": usage["window"], "tokens_est": usage["total"],
            "system_tokens": usage["system"], "history_tokens": usage["history"],
            "percent": usage["percent"], "compact_at": usage["budget"],
            "messages": len(conv.messages), "compactions": conv.compactions,
            "folded_messages": conv.folded_messages, "has_summary": bool(conv.summary),
            "phase": self.planner.phase.value,
            "phase_path": [p.value for p in self.planner.history],
            "methodology": self.planner.methodology.value,
            "turn_tokens": budget.tokens, "session_tokens": budget.total_tokens,
            "session_cost": round(budget.total_cost, 6), "max_steps": budget.max_steps,
            "secrets_vaulted": len(self.vault), "tools": len(self.registry),
            "verified": len(self.pipeline.reportable()), "suspected": len(self.pipeline.suspected()),
            "targets": self.targets, "authorized": self.authorized, "mode": self.mode,
            "turns": self.turns, "run_dir": str(self.ctx.run_dir.resolve()),
        }

    def browser(self) -> BrowserEngine:
        """The session's browser, started on first use."""
        if self._browser is None:
            session_file = self.ctx.run_dir / "browser" / "session.json"
            self._browser = BrowserEngine(guard=self.registry.guard, vault=self.vault,
                                          artifacts_dir=self.ctx.run_dir / "artifacts",
                                          storage_state=str(session_file) if session_file.is_file() else None)
        return self._browser

    def findings(self) -> list[Finding]:
        return self.pipeline.all()

    # ── transcript / export ───────────────────────────────────────────────────
    def _record_event(self, rec: dict) -> None:
        if rec.get("kind") == "verify" and rec.get("verified"):
            f = next((x for x in self.pipeline.all() if x.id == rec.get("finding")), None)
            if f is not None:
                self.transcript.add("finding", title=f.title, severity=f.severity.rating.value,
                                    target=f.target.url or f.target.host, method=rec.get("method", ""))
            return
        self.transcript.on_event(rec)

    def chat_entries(self) -> list[dict]:
        """Everything shown in the chat, uncompacted."""
        entries = self.transcript.entries()
        if entries:
            return entries
        convo = _read_json(self.ctx.run_dir / CONVERSATION_FILE)
        return entries_from_messages(convo.get("messages") or [m.to_dict() for m in self.agent.conversation.messages])

    def answer_count(self) -> int:
        """How many question/answer pairs the chat holds (the N of /copy N)."""
        from .transcript import build_turns
        return len(build_turns(self.chat_entries()))

    def chat_meta(self) -> ExportMeta:
        return ExportMeta(title=self.title, model=self.model, targets=self.targets,
                          authorized=self.authorized, run_id=self.ctx.run_id)

    def export_chat(self, fmt: str = "txt", *, tools: bool = True, path: Path | None = None) -> Path:
        """Write the full chat — every question and answer — as text, Markdown or HTML."""
        out = export_transcript(self.chat_entries(), self.chat_meta(), self.ctx.run_dir / "exports", fmt,
                                tools=tools, path=path)
        self.audit.record("chat.export", format=fmt, tools=tools)
        return out

    def compact(self) -> bool:
        return self.agent.conversation.maybe_compact(force=True)

    # ── reports ───────────────────────────────────────────────────────────────
    def generate_report(self, formats: list[str], style: str = "technical") -> dict:
        verified = self.pipeline.reportable()
        if not verified:
            return {"_error": "no verified findings yet — nothing to report"}
        meta = ReportMeta(run_id=self.ctx.run_id, goal=self.title or self.ctx.goal,
                          targets=self.targets, profile=self.config.run.profile)
        results = ReportBuilder(self.ctx.run_dir / "reports").build(
            verified, meta, formats=formats, style=style,
            suspected_count=len(self.pipeline.suspected()))
        self.audit.record("report", formats=formats, style=style, findings=len(verified))
        return results

    # ── memory ────────────────────────────────────────────────────────────────
    def memory_overview(self) -> list[dict]:
        return [{"target": t, "facts": self.memory.recall(t),
                 "history": self.memory.target_findings(t),
                 "episodes": self.memory.episodes(t, limit=5)}
                for t in self.memory.known_targets()]

    # ── MCP ───────────────────────────────────────────────────────────────────
    def mcp_configs(self) -> list[MCPServerConfig]:
        merged = {s["name"]: s for s in self.config.mcp_servers}
        merged.update({s["name"]: s for s in self.settings.mcp_servers})   # app entries win
        configs = []
        for data in merged.values():
            try:
                configs.append(MCPServerConfig.from_dict(data))
            except (ValueError, TypeError, KeyError):
                continue
        return configs

    def mcp_status(self) -> list[dict]:
        return self.mcp.status(self.mcp_configs())

    def add_mcp_server(self, name: str, command: str = "", args: list[str] | None = None, *,
                       env: dict[str, str] | None = None, trusted: bool = False,
                       transport: str = "stdio", url: str = "",
                       headers: dict[str, str] | None = None) -> MCPServerConfig:
        if not name:
            raise ValueError("an MCP server needs a name")
        cfg = MCPServerConfig(name=name, command=command, args=list(args or []), env=dict(env or {}),
                              url=url, headers=dict(headers or {}), transport=transport,
                              trusted=trusted)
        self.settings.upsert_mcp(cfg.to_dict())
        self._save_settings()
        return cfg

    def mcp_presets(self) -> list[dict]:
        added = {c.name for c in self.mcp_configs()}
        return [{"name": p.name, "title": p.title, "description": p.description,
                 "requires": p.requires, "available": p.available, "added": p.name in added,
                 "trusted": p.trusted, "notes": p.notes} for p in PRESETS.values()]

    def add_mcp_preset(self, name: str, *, directory: str | None = None) -> MCPServerConfig:
        preset = PRESETS[name]
        if not preset.available:
            raise RuntimeError(f"'{preset.requires}' is not installed — needed to run {preset.title}")
        cfg = preset.to_config(directory=directory)
        self.settings.upsert_mcp(cfg.to_dict())
        self._save_settings()
        return cfg

    def remove_mcp_server(self, name: str) -> bool:
        self.disconnect_mcp(name)
        removed = self.settings.remove_mcp(name)
        self._save_settings()
        return removed

    def connect_mcp(self, name: str) -> list[str]:
        cfg = next((c for c in self.mcp_configs() if c.name == name), None)
        if cfg is None:
            raise KeyError(f"no MCP server named '{name}'")
        names = self.mcp.connect(cfg)
        self.audit.record("mcp.connect", server=name, tools=len(names))
        return names

    def disconnect_mcp(self, name: str) -> None:
        self.mcp.disconnect(name)

    def connect_enabled_mcp(self) -> dict[str, str]:
        return self.mcp.connect_all(self.mcp_configs())

    # ── persistence / resume ──────────────────────────────────────────────────
    def save_state(self) -> None:
        """Write the session so it can be resumed after the app closes."""
        conv = self.agent.conversation
        state = {"title": self.title, "created": self.created, "updated": time.time(),
                 "model": self.model, "mode": self.mode, "turns": self.turns,
                 "targets": self.targets, "out_of_scope": self.config.scope.out_of_scope,
                 "authorized": self.authorized, "domain": self.planner.domain,
                 "phase_history": [p.value for p in self.planner.history],
                 "last_answer": self.last_answer[:2000],
                 "verified": len(self.pipeline.reportable())}
        convo = {"summary": conv.summary, "compactions": conv.compactions,
                 "folded_messages": conv.folded_messages,
                 "messages": [m.to_dict() for m in conv.messages]}
        _write_json(self.ctx.run_dir / SESSION_FILE, state)
        _write_json(self.ctx.run_dir / CONVERSATION_FILE, convo)

    def _restore(self) -> None:
        run_dir = self.ctx.run_dir
        state = _read_json(run_dir / SESSION_FILE)
        convo = _read_json(run_dir / CONVERSATION_FILE)
        self.title = state.get("title", "")
        self.turns = state.get("turns", 0)
        self.last_answer = state.get("last_answer", "")
        self.created = state.get("created", self.created)
        self.set_scope(targets=state.get("targets"), out_of_scope=state.get("out_of_scope"),
                       authorized=state.get("authorized"), domain=state.get("domain"))
        history = [Phase(p) for p in state.get("phase_history") or [] if p in Phase._value2member_map_]
        if history:
            self.planner.history = history
            self.planner.phase = history[-1]
        conv = self.agent.conversation
        conv.summary = convo.get("summary", "")
        conv.compactions = convo.get("compactions", 0)
        conv.folded_messages = convo.get("folded_messages", 0)
        conv.messages = [LLMMessage.from_dict(m) for m in convo.get("messages") or []]
        self.pipeline.restore([Finding.from_dict(d) for d in self.ctx.store.findings(self.ctx.run_id)])

    def sessions(self, limit: int = 30) -> list[dict]:
        return [s for s in list_sessions(Path(self.config.run.root), limit=limit + 1)
                if Path(s["path"]).resolve() != self.ctx.run_dir.resolve()][:limit]

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def close(self, status: str = "completed") -> dict[str, str]:
        """Save the session, write long-term memory, finish the audit trail and
        release resources. Idempotent. Returns per-target new/fixed/reopened."""
        if self._closed:
            return {}
        self._closed = True
        deltas: dict[str, str] = {}
        reportable = self.pipeline.reportable()
        for host in self.targets:
            mine = [f for f in reportable if host in (f.target.host or "") or host in (f.target.url or "")]
            try:
                deltas[host] = self.memory.record_findings(host, mine, run_id=self.ctx.run_id).summary()
                if self.turns:
                    self.memory.add_episode(host, self._episode(mine, deltas[host]), run_id=self.ctx.run_id)
            except Exception:
                pass
        for f in reportable:
            self.audit.record("finding.verified", id=f.id, title=f.title,
                              severity=f.severity.rating.value, cvss=f.severity.cvss_score)
        self.audit.record("session.finish", status=status, verified=len(reportable))
        if self.turns and not self._ephemeral_root:
            try:
                self.save_state()
            except OSError:
                pass
        self.mcp.close_all()
        if self._browser is not None:
            self._browser.close()
        for closer in (self.verifier.close, self.memory.close):
            try:
                closer()
            except Exception:
                pass
        self.ctx.finish(status)
        if self._ephemeral_root:
            shutil.rmtree(self._ephemeral_root, ignore_errors=True)
        return deltas

    def _episode(self, findings: list[Finding], delta: str) -> str:
        verified = ", ".join(f"{f.title} ({f.severity.rating.value})" for f in findings[:6]) or "none"
        parts = [f"goal: {self.title or self.ctx.goal}", f"{self.turns} turn(s)",
                 f"verified: {verified}", f"change since last run: {delta}"]
        if self.last_answer:
            parts.append(f"last conclusion: {' '.join(self.last_answer.split())[:300]}")
        return "; ".join(parts)

    def _save_settings(self) -> None:
        try:
            self.settings.save()
        except OSError:
            pass


def _probe_local(bases: dict[str, str]) -> dict[str, bool]:
    """Which local model servers answer, checked in parallel (cached briefly)."""
    from concurrent.futures import ThreadPoolExecutor
    now = time.monotonic()
    todo = {pid: b for pid, b in bases.items() if _PROBE_CACHE.get((pid, b), (0.0, False))[0] < now - 5.0}
    if todo:
        with ThreadPoolExecutor(max_workers=len(todo)) as pool:
            results = dict(zip(todo, pool.map(lambda b: endpoint_reachable(b, timeout=0.8), todo.values()),
                               strict=True))
        for pid, ok in results.items():
            _PROBE_CACHE[(pid, todo[pid])] = (now, ok)
    return {pid: _PROBE_CACHE[(pid, b)][1] for pid, b in bases.items()}


_PROBE_CACHE: dict[tuple[str, str], tuple[float, bool]] = {}


def runs_root(cfg: Config) -> Path:
    """Where sessions live: ./runs in a project with config.toml, else the data dir."""
    if cfg.source is None and cfg.run.root == "runs":
        return data_dir() / "runs"
    return Path(cfg.run.root)


def export_session(run_dir: Path, fmt: str = "txt", *, tools: bool = True, path: Path | None = None) -> Path:
    """Export a saved session without opening it (CLI)."""
    state = _read_json(run_dir / SESSION_FILE)
    entries = read_entries(run_dir / TRANSCRIPT_FILE) or \
        entries_from_messages(_read_json(run_dir / CONVERSATION_FILE).get("messages") or [])
    meta = ExportMeta(title=state.get("title", ""), model=state.get("model", ""),
                      targets=state.get("targets") or [], authorized=bool(state.get("authorized")),
                      run_id=run_dir.name)
    return export_transcript(entries, meta, run_dir / "exports", fmt, tools=tools, path=path)


def list_sessions(root: Path, *, limit: int = 30) -> list[dict]:
    """Saved sessions under a runs folder, most recent first."""
    if not root.is_dir():
        return []
    rows = []
    for state_file in root.glob(f"*/{SESSION_FILE}"):
        state = _read_json(state_file)
        if not state.get("turns"):
            continue
        rows.append({"path": str(state_file.parent), "title": state.get("title") or "(untitled)",
                     "updated": state.get("updated", 0), "model": state.get("model", ""),
                     "turns": state.get("turns", 0), "targets": state.get("targets") or [],
                     "verified": state.get("verified", 0)})
    rows.sort(key=lambda r: r["updated"], reverse=True)
    return rows[:limit]


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _usable_fallback(cfg: Config, creds: CredentialStore) -> str | None:
    """When the configured model's provider has no key, the featured model of a
    connected provider (stored keys first, then the environment)."""
    if not cfg.llm.requires_key or cfg.llm.api_key():
        return None
    candidates = [p for p in creds.providers() if p in PROVIDERS]
    candidates += [p.id for p in PROVIDERS.values()
                   if p.env_var and os.environ.get(p.env_var) and p.id not in candidates]
    for pid in candidates:
        if PROVIDERS[pid].featured:
            return PROVIDERS[pid].featured[0]
    return None


def _align_llm(cfg: Config, settings: Settings, creds: CredentialStore) -> None:
    """Provider, key source, endpoint and runtime key, all derived from the model id."""
    llm = cfg.llm
    prov = provider_of(llm.model)
    info = PROVIDERS.get(prov)
    llm.provider = prov
    if info is not None:
        llm.api_key_env = info.env_var
        llm.api_base = settings.api_bases.get(prov) or info.api_base
    else:
        llm.api_base = settings.api_bases.get(prov) or llm.api_base
    llm.api_key_value = creds.get(prov)
