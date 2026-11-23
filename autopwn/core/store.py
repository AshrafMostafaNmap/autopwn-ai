"""Per-run SQLite state: runs, targets, findings, artifacts, memory. Thread-safe."""
from __future__ import annotations

import functools
import json
import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .findings import Finding

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    goal       TEXT,
    targets    TEXT,                         -- json array
    profile    TEXT,
    model      TEXT,
    status     TEXT NOT NULL DEFAULT 'running',
    started_at REAL NOT NULL,
    ended_at   REAL,
    elapsed    REAL
);

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    host        TEXT NOT NULL,
    url         TEXT,
    domain      TEXT,                         -- web | network | server | mobile
    fingerprint TEXT,                         -- json: tech/stack/surface
    created_at  REAL NOT NULL,
    UNIQUE(run_id, host, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,             -- Finding.id
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    title       TEXT NOT NULL,
    host        TEXT,
    status      TEXT NOT NULL,                -- suspected | verified
    severity    TEXT,                         -- rating word
    cvss_score  REAL,
    owasp       TEXT,
    cwe         TEXT,
    confidence  REAL,
    data        TEXT NOT NULL,                -- full Finding.to_dict() json
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    finding_id  TEXT REFERENCES findings(id),
    kind        TEXT NOT NULL,                -- request | response | screenshot | raw
    path        TEXT NOT NULL,                -- relative to run_dir
    meta        TEXT,                         -- json
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS memory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_key  TEXT NOT NULL,                -- stable per-target id (e.g. host)
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,                -- json
    run_id      TEXT,
    created_at  REAL NOT NULL,
    UNIQUE(target_key, key)
);

CREATE INDEX IF NOT EXISTS idx_findings_run    ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_targets_run     ON targets(run_id);
CREATE INDEX IF NOT EXISTS idx_memory_target   ON memory(target_key);
"""


def _locked(fn):
    """Serialize access to the shared SQLite connection. The engine runs the agent
    in a worker thread while the UI reads from the main thread, so every public
    method takes the store's re-entrant lock."""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    return wrapper


class StateStore:
    """Thin, typed wrapper over a per-run SQLite database."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()

    @classmethod
    def open(cls, path: str | Path) -> StateStore:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        store = cls(conn)
        store._migrate()
        return store

    @classmethod
    def in_memory(cls) -> StateStore:
        """For tests."""
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        store = cls(conn)
        store._migrate()
        return store

    @_locked
    def _migrate(self) -> None:
        self._conn.executescript(_SCHEMA)
        cur = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'")
        row = cur.fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    @_locked
    def close(self) -> None:
        self._conn.commit()
        self._conn.close()

    @_locked
    def record_run(self, run_id: str, *, goal: str, targets: list[str],
                   profile: str, model: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO runs(run_id, goal, targets, profile, model, status, started_at)"
            " VALUES(?,?,?,?,?, 'running', ?)",
            (run_id, goal, json.dumps(targets), profile, model, time.time()),
        )
        self._conn.commit()

    @_locked
    def finish_run(self, run_id: str, *, status: str, elapsed: float) -> None:
        self._conn.execute(
            "UPDATE runs SET status=?, ended_at=?, elapsed=? WHERE run_id=?",
            (status, time.time(), elapsed, run_id),
        )
        self._conn.commit()

    @_locked
    def get_run(self, run_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    @_locked
    def upsert_target(self, run_id: str, host: str, *, url: str | None = None,
                      domain: str | None = None, fingerprint: dict | None = None) -> None:
        self._conn.execute(
            "INSERT INTO targets(run_id, host, url, domain, fingerprint, created_at)"
            " VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(run_id, host, url) DO UPDATE SET"
            "   domain=excluded.domain, fingerprint=excluded.fingerprint",
            (run_id, host, url, domain,
             json.dumps(fingerprint) if fingerprint is not None else None, time.time()),
        )
        self._conn.commit()

    @_locked
    def targets(self, run_id: str) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM targets WHERE run_id=?", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    @_locked
    def save_finding(self, run_id: str, finding: Finding) -> None:
        d = finding.to_dict()
        now = time.time()
        sev = d.get("severity", {}) or {}
        self._conn.execute(
            "INSERT INTO findings(id, run_id, title, host, status, severity, cvss_score,"
            " owasp, cwe, confidence, data, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   title=excluded.title, host=excluded.host, status=excluded.status,"
            "   severity=excluded.severity, cvss_score=excluded.cvss_score,"
            "   owasp=excluded.owasp, cwe=excluded.cwe, confidence=excluded.confidence,"
            "   data=excluded.data, updated_at=excluded.updated_at",
            (
                finding.id, run_id, finding.title,
                finding.target.host, finding.status.value,
                sev.get("rating"), sev.get("cvss_score"),
                finding.owasp, finding.cwe, finding.confidence,
                json.dumps(d, ensure_ascii=False, default=str), now, now,
            ),
        )
        self._conn.commit()

    @_locked
    def findings(self, run_id: str, *, status: str | None = None) -> list[dict]:
        if status:
            rows = self._conn.execute(
                "SELECT data FROM findings WHERE run_id=? AND status=? ORDER BY cvss_score DESC",
                (run_id, status),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM findings WHERE run_id=? ORDER BY cvss_score DESC",
                (run_id,),
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    @_locked
    def reportable_findings(self, run_id: str) -> list[dict]:
        """The FP filter in SQL form: only verified findings are reportable."""
        return self.findings(run_id, status="verified")

    @_locked
    def add_artifact(self, run_id: str, kind: str, path: str, *,
                     finding_id: str | None = None, meta: dict | None = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO artifacts(run_id, finding_id, kind, path, meta, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (run_id, finding_id, kind, path,
             json.dumps(meta) if meta else None, time.time()),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    @_locked
    def remember(self, target_key: str, key: str, value: Any, *, run_id: str | None = None) -> None:
        self._conn.execute(
            "INSERT INTO memory(target_key, key, value, run_id, created_at)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(target_key, key) DO UPDATE SET value=excluded.value, run_id=excluded.run_id",
            (target_key, key, json.dumps(value, default=str), run_id, time.time()),
        )
        self._conn.commit()

    @_locked
    def recall(self, target_key: str, key: str | None = None) -> Any:
        if key is not None:
            row = self._conn.execute(
                "SELECT value FROM memory WHERE target_key=? AND key=?", (target_key, key)
            ).fetchone()
            return json.loads(row["value"]) if row else None
        rows = self._conn.execute(
            "SELECT key, value FROM memory WHERE target_key=?", (target_key,)
        ).fetchall()
        return {r["key"]: json.loads(r["value"]) for r in rows}

    @_locked
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, tuple(params))
