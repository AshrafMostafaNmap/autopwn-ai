"""Local secret vault. Captured secrets become «secret:…» placeholders for the
model; real values stay encrypted on this machine and are injected only at
execution.
"""
from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field
from typing import Any

PLACEHOLDER_RE = re.compile(r"«secret:([a-zA-Z0-9._-]+)»")
_KEY_ENV = "AUTOPWN_VAULT_KEY"


def _make_placeholder(token_id: str) -> str:
    return f"«secret:{token_id}»"


class _Cipher:
    """Fernet wrapper with a plaintext fallback (still never shown to the LLM)."""

    def __init__(self, key: bytes | None):
        self.enabled = False
        self._fernet = None
        try:
            from cryptography.fernet import Fernet
            self._fernet = Fernet(key or Fernet.generate_key())
            self.enabled = True
        except Exception:
            self._fernet = None

    def encrypt(self, value: str) -> bytes:
        if self._fernet is not None:
            return self._fernet.encrypt(value.encode("utf-8"))
        # fallback: base64 so the raw string isn't sitting in memory as plaintext
        return base64.b64encode(value.encode("utf-8"))

    def decrypt(self, blob: bytes) -> str:
        if self._fernet is not None:
            return self._fernet.decrypt(blob).decode("utf-8")
        return base64.b64decode(blob).decode("utf-8")


@dataclass
class _Entry:
    token_id: str
    kind: str
    hint: str
    blob: bytes            # encrypted real value


@dataclass
class Vault:
    """Per-run secret store. Construct via `Vault.open()`."""
    cipher: _Cipher
    encrypted_at_rest: bool = True
    _entries: dict[str, _Entry] = field(default_factory=dict)   # token_id -> entry
    _by_value: dict[str, str] = field(default_factory=dict)     # real value -> token_id
    _counter: dict[str, int] = field(default_factory=dict)      # per-kind sequence

    @classmethod
    def open(cls, key: bytes | str | None = None) -> Vault:
        if isinstance(key, str):
            key = key.encode()
        if key is None and (env := os.environ.get(_KEY_ENV)):
            key = env.encode()
        cipher = _Cipher(key)
        return cls(cipher=cipher, encrypted_at_rest=cipher.enabled)

    def tokenize(self, value: str, *, kind: str = "secret", hint: str = "") -> str:
        """Store `value` encrypted and return a stable placeholder. Idempotent:
        the same value always maps to the same placeholder within a run."""
        if value is None or value == "":
            return value
        if value in self._by_value:
            return _make_placeholder(self._by_value[value])
        n = self._counter.get(kind, 0) + 1
        self._counter[kind] = n
        token_id = f"{kind}.{n}"
        self._entries[token_id] = _Entry(token_id, kind, hint, self.cipher.encrypt(value))
        self._by_value[value] = token_id
        return _make_placeholder(token_id)

    def resolve(self, placeholder_or_id: str) -> str | None:
        """Placeholder (or bare token id) → real value. LOCAL USE ONLY."""
        m = PLACEHOLDER_RE.fullmatch(placeholder_or_id.strip())
        token_id = m.group(1) if m else placeholder_or_id
        entry = self._entries.get(token_id)
        if entry is None:
            return None
        return self.cipher.decrypt(entry.blob)

    def redact(self, text: str) -> str:
        """Replace any KNOWN secret value in `text` with its placeholder. Used
        on anything heading to the LLM. Longest values first so substrings of a
        bigger secret don't get partially replaced."""
        if not text:
            return text
        for value in sorted(self._by_value, key=len, reverse=True):
            if value and value in text:
                text = text.replace(value, _make_placeholder(self._by_value[value]))
        return text

    def inject(self, text: str) -> str:
        """Replace placeholders with real values. LOCAL EXECUTION ONLY — never
        call this on anything that will be sent to the LLM or logged."""
        if not text:
            return text
        def _sub(m: re.Match) -> str:
            val = self.resolve(m.group(0))
            return val if val is not None else m.group(0)
        return PLACEHOLDER_RE.sub(_sub, text)

    def inject_args(self, args: Any) -> Any:
        """Deep-inject placeholders inside a tool-call argument structure."""
        if isinstance(args, str):
            return self.inject(args)
        if isinstance(args, dict):
            return {k: self.inject_args(v) for k, v in args.items()}
        if isinstance(args, list):
            return [self.inject_args(v) for v in args]
        return args

    def placeholders(self) -> list[str]:
        return [_make_placeholder(tid) for tid in self._entries]

    def manifest(self) -> list[dict]:
        """Non-secret metadata about stored secrets (for the run record)."""
        return [{"placeholder": _make_placeholder(e.token_id), "kind": e.kind, "hint": e.hint}
                for e in self._entries.values()]

    def __len__(self) -> int:
        return len(self._entries)
