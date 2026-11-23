"""User settings and the encrypted provider-key store, in $AUTOPWN_HOME or
~/.config/autopwn. Keys never reach logs, run metadata or the model.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_HOME_ENV = "AUTOPWN_HOME"
_CRED_KEY_ENV = "AUTOPWN_CRED_KEY"


def config_dir() -> Path:
    if v := os.environ.get(_HOME_ENV):
        return Path(v).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autopwn"


def data_dir() -> Path:
    if v := os.environ.get(_HOME_ENV):
        return Path(v).expanduser() / "data"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "autopwn"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(stat.S_IRWXU)                     # 0700
    except OSError:
        pass
    return path


def _private_write(path: Path, data: bytes) -> None:
    """Write a file readable only by the owner (created 0600 from the start)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


@dataclass
class Settings:
    provider: str | None = None
    model: str | None = None
    api_bases: dict[str, str] = field(default_factory=dict)   # provider → endpoint
    mode: str = "autonomous"                                   # autonomous | hitl
    profile: str | None = None
    operator: str = ""
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    setup_done: bool = False                                   # first-run wizard completed
    terms_accepted: str = ""                                   # "<terms version>@<ISO time>"
    _path: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path | None = None) -> Settings:
        path = path or (config_dir() / "settings.json")
        data: dict[str, Any] = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}                           # a corrupt file never blocks startup
        known = {f for f in cls.__dataclass_fields__ if not f.startswith("_")}
        s = cls(**{k: v for k, v in data.items() if k in known})
        s._path = path
        return s

    def save(self) -> None:
        path = self._path or (config_dir() / "settings.json")
        _private_dir(path.parent)
        body = {k: v for k, v in asdict(self).items() if not k.startswith("_")}
        _private_write(path, json.dumps(body, indent=2).encode("utf-8"))

    def upsert_mcp(self, entry: dict[str, Any]) -> None:
        self.mcp_servers = [s for s in self.mcp_servers if s.get("name") != entry["name"]]
        self.mcp_servers.append(entry)

    def remove_mcp(self, name: str) -> bool:
        before = len(self.mcp_servers)
        self.mcp_servers = [s for s in self.mcp_servers if s.get("name") != name]
        return len(self.mcp_servers) != before


def mask(secret: str | None) -> str:
    """Display form of a key: enough to recognise it, never enough to use it."""
    if not secret:
        return "—"
    if len(secret) <= 8:
        return "•" * len(secret)
    return f"{secret[:3]}…{secret[-4:]}"


class CredentialStore:
    """Encrypted provider-key store (Fernet)."""

    def __init__(self, directory: Path | None = None, *, key: bytes | None = None):
        self.dir = directory or config_dir()
        self.path = self.dir / "credentials.enc"
        self._fernet = self._load_fernet(key)
        self._cache: dict[str, str] | None = None

    def _load_fernet(self, key: bytes | None):
        from cryptography.fernet import Fernet
        if key is None and (env := os.environ.get(_CRED_KEY_ENV)):
            key = env.encode()
        if key is None:
            key_file = self.dir / "credentials.key"
            if key_file.is_file():
                key = key_file.read_bytes().strip()
            else:
                _private_dir(self.dir)
                key = Fernet.generate_key()
                _private_write(key_file, key)
        return Fernet(key)

    def _read(self) -> dict[str, str]:
        if self._cache is not None:
            return self._cache
        if not self.path.is_file():
            self._cache = {}
            return self._cache
        try:
            raw = self._fernet.decrypt(self.path.read_bytes())
            self._cache = json.loads(raw.decode("utf-8"))
        except Exception:
            # wrong key / corrupt file — fail closed (no keys) rather than crash
            self._cache = {}
        return self._cache

    def _write(self, data: dict[str, str]) -> None:
        _private_dir(self.dir)
        _private_write(self.path, self._fernet.encrypt(json.dumps(data).encode("utf-8")))
        self._cache = dict(data)

    def get(self, provider: str) -> str | None:
        return self._read().get(provider)

    def set(self, provider: str, secret: str) -> None:
        secret = (secret or "").strip()
        if not secret:
            raise ValueError("empty key")
        data = dict(self._read())
        data[provider] = secret
        self._write(data)

    def delete(self, provider: str) -> bool:
        data = dict(self._read())
        if provider not in data:
            return False
        del data[provider]
        self._write(data)
        return True

    def providers(self) -> list[str]:
        return sorted(self._read())
