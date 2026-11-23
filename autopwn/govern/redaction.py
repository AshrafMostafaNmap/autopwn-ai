"""Pattern redaction: tokenize high-confidence secret shapes (auth headers,
cookies, JWTs, cloud keys) into the vault before text reaches the model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .vault import Vault

# (name, compiled regex, index of the capture group holding the secret, kind)
_PATTERNS: list[tuple[str, re.Pattern, int, str]] = [
    ("authorization", re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)([A-Za-z0-9._\-+/=]{8,})"), 2, "auth"),
    ("set-cookie",    re.compile(r"(?i)(set-cookie:\s*[^=;\r\n]+=)([^;\r\n]{6,})"), 2, "cookie"),
    ("cookie-header", re.compile(r"(?i)(\bcookie:\s*)([^\r\n]{6,})"), 2, "cookie"),
    ("jwt",           re.compile(r"\b(eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,})\b"), 1, "jwt"),
    ("aws-akid",      re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1, "aws"),
    ("generic-key",   re.compile(r"(?i)((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*)([^\s&;\"']{6,})"), 2, "secret"),
]


@dataclass
class Redactor:
    vault: Vault

    def scrub(self, text: str) -> str:
        """Tokenize high-confidence secrets into the vault, then apply the vault's
        known-value redaction. Result is safe to send to the LLM."""
        if not text:
            return text
        for name, rx, grp, kind in _PATTERNS:
            def _sub(m: re.Match, _grp=grp, _kind=kind, _hint=name) -> str:
                secret = m.group(_grp)
                placeholder = self.vault.tokenize(secret, kind=_kind, hint=_hint)
                # replace exactly the secret's span — never other occurrences of
                # the same text elsewhere in the match (e.g. inside the prefix)
                start, end = m.span(_grp)
                base = m.start(0)
                whole = m.group(0)
                return whole[:start - base] + placeholder + whole[end - base:]
            text = rx.sub(_sub, text)
        # finally swap any other already-known values (e.g. a cookie captured by
        # the browser tool before it ever hit text form)
        return self.vault.redact(text)

    def scrub_obj(self, obj):
        """Deep-scrub a JSON-ish structure (dict/list/str)."""
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {k: self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.scrub_obj(v) for v in obj]
        return obj
