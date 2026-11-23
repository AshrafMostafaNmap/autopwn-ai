"""Per-domain methodology playbooks (Markdown), loaded into the prompt by phase."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).parent

# domain → playbook file
_FILES = {
    "web": "web.md",
    "network": "network.md",
    "server": "server.md",
    "mobile": "mobile.md",
}


def available() -> list[str]:
    return sorted(_FILES)


@lru_cache(maxsize=8)
def load(domain: str) -> str:
    """Return the playbook text for a domain ('' if none)."""
    fname = _FILES.get((domain or "").lower())
    if not fname:
        return ""
    path = _DIR / fname
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def for_domains(domains: list[str]) -> str:
    """Concatenate the playbooks for several domains (deduped, in order)."""
    seen, out = set(), []
    for d in domains:
        d = (d or "").lower()
        if d in seen or d not in _FILES:
            continue
        seen.add(d)
        out.append(load(d))
    return "\n\n---\n\n".join(p for p in out if p)
