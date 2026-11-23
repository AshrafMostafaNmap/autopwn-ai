"""Non-destructive HTTP recon: server, technology, title, security headers,
cookies (vaulted) and DNS.
"""
from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

from .target_model import Surface

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# header/body signatures → tech label
_TECH_HEADER_SIGNS = {
    "x-powered-by": lambda v: v,
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-generator": lambda v: v,
}
_BODY_SIGNS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"Drupal.settings|/sites/default/", re.I), "Drupal"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|react", re.I), "React"),
]

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]


def _normalize_url(target: str) -> str:
    if "://" not in target:
        return "https://" + target
    return target


def dns_lookup(host: str) -> dict:
    """A/AAAA via the resolver (pure Python, always works)."""
    out: dict[str, list[str]] = {"A": [], "AAAA": []}
    try:
        for fam, _t, _p, _c, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if fam == socket.AF_INET and ip not in out["A"]:
                out["A"].append(ip)
            elif fam == socket.AF_INET6 and ip not in out["AAAA"]:
                out["AAAA"].append(ip)
    except Exception as e:
        out["error"] = str(e)
    return out


def http_probe(target: str, *, vault=None, redactor=None, timeout: float = 15.0,
               domain: str = "web") -> tuple[Surface, dict]:
    """Safe GET probe. Returns (Surface, raw_artifact). Raw artifact is for local
    storage; the Surface is what the agent sees (already secret-free)."""
    import httpx

    url = _normalize_url(target)
    parsed = urlparse(url)
    host = parsed.hostname or target
    surface = Surface(host=host, domain=domain, scheme=parsed.scheme)

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                          headers={"User-Agent": "AutoPwn-Recon/0.1 (+purple-team)"}) as client:
            resp = client.get(url)
    except Exception as e:
        surface.notes.append(f"probe failed: {type(e).__name__}: {e}")
        return surface, {"error": str(e)}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text or ""

    surface.scheme = str(resp.url).split("://", 1)[0]
    surface.server = headers.get("server", "")
    if (m := _TITLE_RE.search(body)):
        surface.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    for hk, fn in _TECH_HEADER_SIGNS.items():
        if hk in headers:
            surface.tech.append(fn(headers[hk]))
    for rx, label in _BODY_SIGNS:
        if rx.search(body):
            surface.tech.append(label)
    surface.tech = list(dict.fromkeys(surface.tech))

    # security-header posture → notes
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        surface.notes.append("missing security headers: " + ", ".join(missing))

    # cookies → vault (real values never reach the agent)
    cookie_names = []
    for sc in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
        name = sc.split("=", 1)[0].strip()
        cookie_names.append(name)
        if vault is not None and "=" in sc:
            raw_val = sc.split("=", 1)[1].split(";", 1)[0]
            vault.tokenize(raw_val, kind="cookie", hint=f"set-cookie:{name}")
    if cookie_names:
        surface.notes.append("cookies: " + ", ".join(cookie_names))

    surface.headers = {k: v for k, v in headers.items() if k != "set-cookie"}
    surface.dns = dns_lookup(host)

    status = resp.status_code
    raw = {
        "url": str(resp.url), "status": status,
        "request_headers": dict(resp.request.headers),
        "response_headers": dict(resp.headers),
        "body_snippet": body[:4000],
    }
    surface.notes.append(f"HTTP {status} via {resp.http_version}")
    return surface, raw
