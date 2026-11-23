"""RunContext: one run folder (run.json, events.jsonl, state.db, audit.jsonl,
artifacts/) with its logger and state store.
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from ..config import Config
from .logging import EventLogger, redact
from .store import StateStore


def new_run_id(now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    return f"{now:%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


@dataclass
class RunContext:
    config: Config
    goal: str
    targets: list[str]
    run_id: str
    run_dir: Path
    logger: EventLogger
    store: StateStore
    console: Console
    started_at: float = field(default_factory=time.time)

    @classmethod
    def create(
        cls,
        config: Config,
        *,
        goal: str,
        targets: list[str] | None = None,
        console: Console | None = None,
    ) -> RunContext:
        console = console or Console()
        run_id = new_run_id()
        run_dir = Path(config.run.root).expanduser() / run_id
        (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)

        logger = EventLogger(
            path=run_dir / "events.jsonl",
            level=config.logging.level,
            console=console if config.logging.console else None,
            json_enabled=config.logging.json,
        )
        store = StateStore.open(run_dir / "state.db")

        ctx = cls(
            config=config,
            goal=goal,
            targets=targets or list(config.scope.in_scope),
            run_id=run_id,
            run_dir=run_dir,
            logger=logger,
            store=store,
            console=console,
        )
        ctx._write_metadata()
        store.record_run(run_id, goal=goal, targets=ctx.targets,
                         profile=config.run.profile, model=config.llm.model)
        logger.info("run.start", run_id=run_id, goal=goal, targets=ctx.targets,
                    profile=config.run.profile, model=config.llm.model)
        return ctx

    @classmethod
    def resume(cls, config: Config, run_dir: Path, *, console: Console | None = None) -> RunContext:
        """Reopen an existing run folder: events append, the state store and audit
        chain continue where they stopped."""
        run_dir = Path(run_dir)
        meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        console = console or Console()
        logger = EventLogger(path=run_dir / "events.jsonl", level=config.logging.level,
                             console=console if config.logging.console else None,
                             json_enabled=config.logging.json)
        ctx = cls(config=config, goal=meta.get("goal", ""), targets=list(meta.get("targets") or []),
                  run_id=meta["run_id"], run_dir=run_dir, logger=logger,
                  store=StateStore.open(run_dir / "state.db"), console=console)
        logger.info("run.resume", run_id=ctx.run_id)
        return ctx

    def _write_metadata(self) -> None:
        meta = {
            "run_id": self.run_id,
            "started_at": datetime.fromtimestamp(self.started_at, UTC).isoformat(),
            "goal": self.goal,
            "targets": self.targets,
            "config": self._config_snapshot(),
        }
        (self.run_dir / "run.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )

    def _config_snapshot(self) -> dict:
        """A redacted, serializable view of the config for the run record.
        Only the env-var NAME is kept for the key — never a resolved value."""
        c = self.config
        prof = c.active_profile()
        snap = {
            "llm": {
                "model": c.llm.model, "provider": c.llm.provider,
                "api_key_env": c.llm.api_key_env, "api_base": c.llm.api_base,
                "temperature": c.llm.temperature, "max_tokens": c.llm.max_tokens,
                "require_tool_calling": c.llm.require_tool_calling,
            },
            "run": {"root": c.run.root, "profile": c.run.profile},
            "active_profile": {
                "name": prof.name, "destructive": prof.destructive,
                "max_steps": prof.max_steps, "rate_limit_rps": prof.rate_limit_rps,
            },
            "scope": {
                "in_scope": c.scope.in_scope, "out_of_scope": c.scope.out_of_scope,
                "authorized_ack": c.scope.authorized_ack,
            },
            "source": str(c.source) if c.source else None,
        }
        return redact(snap)

    def artifact_path(self, name: str) -> Path:
        """A path inside this run's artifacts/ dir (dirs created as needed)."""
        p = self.run_dir / "artifacts" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def finish(self, status: str = "completed") -> None:
        elapsed = round(time.time() - self.started_at, 2)
        self.store.finish_run(self.run_id, status=status, elapsed=elapsed)
        self.logger.info("run.finish", run_id=self.run_id, status=status, elapsed=elapsed)
        self.logger.close()
        self.store.close()

    def __enter__(self) -> RunContext:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish("failed" if exc_type else "completed")
