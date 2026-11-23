"""Passive client-side checks over what the browser observed. Pure functions:
they read captured data and return issues — nothing is sent to the target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# library → (regex for its version in a script, first fixed version, CVE/advisory)
VULNERABLE_LIBS: tuple[tuple[str, re.Pattern, tuple[int, ...], str], ...] = (
    ("jQuery", re.compile(r"jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)"), (3, 5, 0),
     "CVE-2020-11022 / CVE-2020-11023 (XSS in htmlPrefilter)"),
    ("jQuery UI", re.compile(r"jQuery UI - v?(\d+\.\d+\.\d+)"), (1, 13, 2), "CVE-2021-41184 (XSS)"),
    ("AngularJS", re.compile(r"AngularJS v?(1\.\d+\.\d+)"), (1, 8, 3), "end-of-life; multiple XSS/ReDoS"),
    ("Bootstrap", re.compile(r"Bootstrap v?(\d+\.\d+\.\d+)"), (3, 4, 1), "CVE-2019-8331 (XSS in tooltip)"),
    ("Lodash", re.compile(r"lodash(?:\.js)? v?(\d+\.\d+\.\d+)|@license Lodash (\d+\.\d+\.\d+)"), (4, 17, 21),
     "CVE-2021-23337 (command injection in template)"),
    ("Moment.js", re.compile(r"moment\.js v?(\d+\.\d+\.\d+)|//! version : (\d+\.\d+\.\d+)"), (2, 29, 4),
     "CVE-2022-31129 (ReDoS)"),
    ("Handlebars", re.compile(r"handlebars v?(\d+\.\d+\.\d+)"), (4, 7, 7), "CVE-2021-23369 (RCE in compile)"),
    ("DOMPurify", re.compile(r"DOMPurify (\d+\.\d+\.\d+)"), (3, 1, 3), "CVE-2024-45801 (mXSS)"),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("OpenAI-style key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
)

JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
SENSITIVE_KEY = re.compile(r"token|jwt|auth|session|secret|password|passwd|api[_-]?key|credential|bearer", re.I)
ENDPOINT = re.compile(r"""["'`](/(?:api|v\d|graphql|rest|admin|internal|auth|oauth)[A-Za-z0-9_\-/.{}:?=&%]*)["'`]""")
STACK_TRACE = re.compile(r"(\bat [\w$.<>]+ \(|/[\w./-]+\.(?:js|ts|py|php|java|rb):\d+|Traceback \(most recent call last\))")


@dataclass
class Issue:
    class_id: str
    url: str
    note: str
    evidence: str = ""
    param: str = ""
    confidence: float = 0.9
    extra: dict = field(default_factory=dict)


def _version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def header_issues(url: str, headers: dict[str, str]) -> list[Issue]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[Issue] = []
    missing = [name for key, name in SECURITY_HEADERS.items()
               if key not in h and not (key == "strict-transport-security" and url.startswith("http://"))]
    if missing:
        out.append(Issue("security_misconfig", url, f"missing security headers: {', '.join(missing)}",
                         evidence="\n".join(f"{k}: {v}" for k, v in list(h.items())[:20])))
    csp = h.get("content-security-policy", "")
    if csp:
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'", " * ", "data:", "http:") if w in f" {csp} "]
        if "script-src" not in csp and "default-src" not in csp:
            weak.append("no script-src/default-src")
        if weak:
            out.append(Issue("weak_csp", url, f"CSP allows {', '.join(w.strip() for w in weak)}",
                             evidence=f"Content-Security-Policy: {csp}"))
    acao, acac = h.get("access-control-allow-origin", ""), h.get("access-control-allow-credentials", "")
    if acac.lower() == "true" and acao and acao != "null":
        out.append(Issue("cors_misconfig", url, f"credentials allowed for origin '{acao}'",
                         evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                         confidence=0.8))
    return out


def cookie_issues(url: str, cookies: list[dict]) -> list[Issue]:
    out = []
    for c in cookies:
        name = c.get("name", "")
        lacks = [flag for flag, ok in (("HttpOnly", c.get("httpOnly")), ("Secure", c.get("secure") or
                                       url.startswith("http://")), ("SameSite", c.get("sameSite") not in
                                       (None, "", "None"))) if not ok]
        if lacks and SENSITIVE_KEY.search(name):
            out.append(Issue("cookie_flags", url, f"cookie '{name}' lacks {', '.join(lacks)}", param=name,
                             evidence=f"Set-Cookie: {name}=…; domain={c.get('domain', '')}; path={c.get('path', '/')}"))
    return out


def storage_issues(url: str, storage: dict[str, dict[str, str]]) -> list[Issue]:
    """storage = {"localStorage": {k: v}, "sessionStorage": {k: v}} (real values, local only)."""
    out = []
    for area, items in storage.items():
        for key, value in (items or {}).items():
            v = str(value)
            if JWT.search(v) or (SENSITIVE_KEY.search(key) and len(v) >= 16):
                kind = "a JWT" if JWT.search(v) else "a credential-like value"
                out.append(Issue("sensitive_client_storage", url, f"{area}['{key}'] holds {kind}", param=key,
                                 evidence=f"{area}.getItem('{key}') → {v[:12]}… ({len(v)} chars)"))
    return out


def script_issues(url: str, script_url: str, body: str) -> list[Issue]:
    out = []
    for name, rx, fixed, advisory in VULNERABLE_LIBS:
        m = rx.search(body[:200_000])
        if not m:
            continue
        version = next(g for g in m.groups() if g)
        if _version(version) < fixed:
            out.append(Issue("vulnerable_js_library", url, f"{name} {version} (< {'.'.join(map(str, fixed))}): "
                             f"{advisory}", evidence=f"{script_url}: {m.group(0)}", param=name))
    for label, rx in SECRET_PATTERNS:
        m = rx.search(body)
        if m:
            secret = m.group(0)
            out.append(Issue("secret_in_client_code", url, f"{label} in {script_url}",
                             evidence=f"{script_url}: {secret[:6]}…{secret[-2:]} ({len(secret)} chars)",
                             param=label, confidence=0.8))
    return out


def endpoints_in(body: str) -> list[str]:
    return sorted({m.group(1).split("?")[0] for m in ENDPOINT.finditer(body)})


def source_map_ref(body: str) -> str:
    m = re.search(r"//[#@] sourceMappingURL=(\S+)", body[-2000:])
    return m.group(1) if m and not m.group(1).startswith("data:") else ""


def console_issues(url: str, messages: list[dict]) -> list[Issue]:
    leaks = [m for m in messages if m.get("type") in ("error", "warning", "pageerror")
             and STACK_TRACE.search(m.get("text", ""))]
    if not leaks:
        return []
    return [Issue("info_leak_console", url, f"{len(leaks)} console message(s) expose stack traces or "
                  "internal paths", evidence=leaks[0].get("text", "")[:400], confidence=0.85)]


def mixed_content_issues(url: str, requests: list[dict]) -> list[Issue]:
    if not url.startswith("https://"):
        return []
    insecure = sorted({r["url"] for r in requests if r.get("url", "").startswith("http://")})
    if not insecure:
        return []
    return [Issue("mixed_content", url, f"{len(insecure)} subresource(s) loaded over http",
                  evidence="\n".join(insecure[:10]))]
