"""Hash-chained audit log and the operator's authorization acknowledgement.
Tampering with or removing an entry breaks verification.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

_GENESIS = "0" * 64


def _hash(prev: str, payload: str) -> str:
    return hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()


@dataclass
class Acknowledgement:
    """The operator's authorization to assess the declared scope."""
    operator: str
    in_scope: list[str]
    out_of_scope: list[str] = field(default_factory=list)
    authorized: bool = False
    profile: str = "safe"
    note: str = ""
    at: float = field(default_factory=time.time)

    def as_entry(self) -> dict:
        return {"ack": asdict(self)}


@dataclass
class AuditLog:
    path: Path
    _prev: str = _GENESIS
    _count: int = 0

    @classmethod
    def open(cls, path: str | Path) -> AuditLog:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        log = cls(path=p)
        # continue an existing chain (resume) if the file is already there
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                try:
                    rec = json.loads(line)
                    log._prev = rec.get("hash", log._prev)
                    log._count += 1
                except json.JSONDecodeError:
                    continue
        return log

    def record(self, action: str, **fields) -> dict:
        """Append one hash-chained entry. Returns the written record."""
        body = {"seq": self._count, "ts": round(time.time(), 3), "action": action, **fields}
        payload = json.dumps(body, sort_keys=True, default=str)
        digest = _hash(self._prev, payload)
        rec = {**body, "prev": self._prev, "hash": digest}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self._prev = digest
        self._count += 1
        return rec

    def acknowledge(self, ack: Acknowledgement) -> dict:
        return self.record("authorization", **ack.as_entry())

    @staticmethod
    def verify(path: str | Path) -> bool:
        """Recompute the chain and confirm no entry was altered or removed."""
        p = Path(path)
        if not p.is_file():
            return False
        prev = _GENESIS
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
            payload = json.dumps(body, sort_keys=True, default=str)
            if rec.get("prev") != prev or rec.get("hash") != _hash(prev, payload):
                return False
            prev = rec["hash"]
        return True

    def __len__(self) -> int:
        return self._count
