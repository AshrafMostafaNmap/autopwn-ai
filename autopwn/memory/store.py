"""Long-term memory that outlives runs: encrypted facts per target, finding
history (new / fixed / reopened) and session episodes. Thread-safe.
"""
from __future__ import annotations

import functools
import json
import os
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.findings import Finding

_KEY_ENV = "AUTOPWN_MEMORY_KEY"
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS target_memory (
    target_key TEXT NOT NULL,
    key        TEXT NOT NULL,
    value_enc  BLOB NOT NULL,            -- encrypted JSON value
    run_id     TEXT,
    updated_at REAL NOT NULL,
    PRIMARY KEY (target_key, key)
);

CREATE TABLE IF NOT EXISTS target_findings (
    target_key TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    title      TEXT,
    severity   TEXT,
    cvss       REAL,
    status     TEXT,                     -- open | fixed
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    last_run   TEXT,
    PRIMARY KEY (target_key, finding_id)
);

CREATE TABLE IF NOT EXISTS episodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_key TEXT NOT NULL,
    run_id     TEXT,
    at         REAL NOT NULL,
    summary    BLOB NOT NULL                 -- encrypted text
);

CREATE INDEX IF NOT EXISTS idx_tf_target ON target_findings(target_key);
CREATE INDEX IF NOT EXISTS idx_ep_target ON episodes(target_key, at);
"""


# ── encryption ────────────────────────────────────────────────────────────────
class _Cipher:
    def __init__(self, key: bytes):
        from cryptography.fernet import Fernet
        self._f = Fernet(key)

    def enc(self, value: Any) -> bytes:
        return self._f.encrypt(json.dumps(value, default=str).encode("utf-8"))

    def dec(self, blob: bytes) -> Any:
        return json.loads(self._f.decrypt(bytes(blob)).decode("utf-8"))


def _resolve_key(db_path: Path, key: bytes | str | None) -> bytes:
    from cryptography.fernet import Fernet
    if isinstance(key, str):
        return key.encode()
    if key is not None:
        return key
    env = os.environ.get(_KEY_ENV)
    if env:
        return env.encode()
    # generated key file beside the db, locked down to the owner
    key_file = db_path.parent / "memory.key"
    if key_file.is_file():
        return key_file.read_bytes().strip()
    new_key = Fernet.generate_key()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(new_key)
    try:
        key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)      # 0600
    except OSError:
        pass
    return new_key


# ── diff result ───────────────────────────────────────────────────────────────
@dataclass
class FindingsDelta:
    new: list[str]            # finding ids seen now but not before
    fixed: list[str]          # previously open, absent now → considered fixed
    reopened: list[str]       # previously fixed, present again now
    unchanged: list[str]

    def summary(self) -> str:
        return (f"{len(self.new)} new · {len(self.fixed)} fixed · "
                f"{len(self.reopened)} reopened · {len(self.unchanged)} unchanged")


# ── the store ─────────────────────────────────────────────────────────────────

def _locked(fn):
    """Serialize access to the shared SQLite connection. The engine runs the agent
    in a worker thread while the UI reads from the main thread, so every public
    method takes the store's re-entrant lock."""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    return wrapper


class TargetMemory:
    def __init__(self, conn: sqlite3.Connection, cipher: _Cipher):
        self._conn = conn
        self._conn.row_factory = sqlite3.Row
        self._cipher = cipher
        self._lock = threading.RLock()

    @classmethod
    def open(cls, path: str | Path | None = None, *, key: bytes | str | None = None) -> TargetMemory:
        if path:
            db_path = Path(path)
        else:
            # same home as settings/runs, so AUTOPWN_HOME isolates everything
            from ..settings import data_dir
            db_path = data_dir() / "memory.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        resolved = _resolve_key(db_path, key)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        store = cls(conn, _Cipher(resolved))
        store._migrate()
        return store

    @_locked
    def _migrate(self) -> None:
        self._conn.executescript(_SCHEMA)
        row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self._conn.execute("INSERT INTO meta(key,value) VALUES('schema_version',?)",
                               (str(SCHEMA_VERSION),))
            self._conn.commit()

    # ── encrypted KV ──────────────────────────────────────────────────────────
    @_locked
    def remember(self, target_key: str, key: str, value: Any, *, run_id: str | None = None) -> None:
        self._conn.execute(
            "INSERT INTO target_memory(target_key,key,value_enc,run_id,updated_at)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(target_key,key) DO UPDATE SET"
            "   value_enc=excluded.value_enc, run_id=excluded.run_id, updated_at=excluded.updated_at",
            (target_key, key, self._cipher.enc(value), run_id, time.time()),
        )
        self._conn.commit()

    @_locked
    def recall(self, target_key: str, key: str | None = None) -> Any:
        if key is not None:
            row = self._conn.execute(
                "SELECT value_enc FROM target_memory WHERE target_key=? AND key=?",
                (target_key, key)).fetchone()
            return self._cipher.dec(row["value_enc"]) if row else None
        rows = self._conn.execute(
            "SELECT key, value_enc FROM target_memory WHERE target_key=?", (target_key,)).fetchall()
        return {r["key"]: self._cipher.dec(r["value_enc"]) for r in rows}

    @_locked
    def known_targets(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT target_key FROM target_memory"
            " UNION SELECT DISTINCT target_key FROM target_findings"
            " UNION SELECT DISTINCT target_key FROM episodes").fetchall()
        return sorted(r[0] for r in rows)

    # ── findings history + diff ───────────────────────────────────────────────
    @_locked
    def record_findings(self, target_key: str, findings: list[Finding], *, run_id: str | None = None):
        """Persist this run's verified findings and return the delta vs last run.

        Must be called with the CURRENT run's verified findings. Findings present
        before but absent now are marked fixed; a fixed one that returns is reopened.
        """
        now = time.time()
        prior = {r["finding_id"]: r for r in self._conn.execute(
            "SELECT finding_id, status FROM target_findings WHERE target_key=?",
            (target_key,)).fetchall()}
        current_ids = {f.id for f in findings}

        new, reopened, unchanged = [], [], []
        for f in findings:
            prev = prior.get(f.id)
            if prev is None:
                new.append(f.id)
            elif prev["status"] == "fixed":
                reopened.append(f.id)
            else:
                unchanged.append(f.id)
            self._conn.execute(
                "INSERT INTO target_findings(target_key,finding_id,title,severity,cvss,status,first_seen,last_seen,last_run)"
                " VALUES(?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(target_key,finding_id) DO UPDATE SET"
                "   title=excluded.title, severity=excluded.severity, cvss=excluded.cvss,"
                "   status='open', last_seen=excluded.last_seen, last_run=excluded.last_run",
                (target_key, f.id, f.title, f.severity.rating.value, f.severity.cvss_score,
                 "open", now, now, run_id))

        fixed = [fid for fid, r in prior.items() if fid not in current_ids and r["status"] != "fixed"]
        for fid in fixed:
            self._conn.execute(
                "UPDATE target_findings SET status='fixed', last_seen=? WHERE target_key=? AND finding_id=?",
                (now, target_key, fid))
        self._conn.commit()
        return FindingsDelta(new=new, fixed=fixed, reopened=reopened, unchanged=unchanged)

    @_locked
    def target_findings(self, target_key: str, *, status: str | None = None) -> list[dict]:
        if status:
            rows = self._conn.execute(
                "SELECT * FROM target_findings WHERE target_key=? AND status=? ORDER BY cvss DESC",
                (target_key, status)).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM target_findings WHERE target_key=? ORDER BY cvss DESC",
                (target_key,)).fetchall()
        return [dict(r) for r in rows]

    @_locked
    def add_episode(self, target_key: str, summary: str, *, run_id: str | None = None) -> None:
        self._conn.execute("INSERT INTO episodes(target_key, run_id, at, summary) VALUES(?,?,?,?)",
                           (target_key, run_id, time.time(), self._cipher.enc(summary)))
        self._conn.commit()

    @_locked
    def episodes(self, target_key: str, *, limit: int = 5) -> list[dict]:
        rows = self._conn.execute(
            "SELECT run_id, at, summary FROM episodes WHERE target_key=? ORDER BY at DESC LIMIT ?",
            (target_key, limit)).fetchall()
        return [{"run_id": r["run_id"], "at": r["at"], "summary": self._cipher.dec(r["summary"])}
                for r in rows]

    @_locked
    def has_history(self, target_key: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM target_findings WHERE target_key=? LIMIT 1", (target_key,)).fetchone()
        return row is not None

    @_locked
    def close(self) -> None:
        self._conn.commit()
        self._conn.close()
