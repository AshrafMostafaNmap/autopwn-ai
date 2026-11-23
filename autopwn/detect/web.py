"""Web detectors: light-touch probes that produce suspected findings."""
from __future__ import annotations

from urllib.parse import parse_qs, urljoin, urlparse

from ..recon.web import SECURITY_HEADERS, _normalize_url
from .model import Candidate
from .signatures import ADMIN_PANELS, SENSITIVE_FILES, SQL_ERRORS

_MARKER = "apxr3fl"


def _client(timeout: float = 15.0):
    import httpx
    return httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                        headers={"User-Agent": "AutoPwn-Detect/0.1 (+purple-team)"})


def _params_of(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query).keys())


def detect_all(url: str, *, params: list[str] | None = None) -> list[Candidate]:
    """Run every web detector against a URL. Returns suspected candidates."""
    url = _normalize_url(url)
    host = urlparse(url).hostname or url
    params = params or _params_of(url)
    out: list[Candidate] = []
    with _client() as client:
        try:
            base = client.get(url)
        except Exception:
            # Host is unreachable — do NOT fabricate a finding (a dead host is not
            # a misconfiguration). Return nothing; recon surfaces reachability.
            return []
        out += _headers(host, url, base)
        out += _cookies(host, url, base)
        out += _sensitive_files(host, url, client)
        out += _panels(host, url, client)
        for p in params:
            out += _reflected_xss(host, url, p, client)
            out += _sqli(host, url, p, client)
    return out


def _headers(host, url, resp) -> list[Candidate]:
    present = {k.lower() for k in resp.headers}
    missing = [h for h in SECURITY_HEADERS if h not in present]
    if not missing:
        return []
    return [Candidate("security_misconfig", host=host, url=url, confidence=0.9,
                      method="direct", note="missing: " + ", ".join(missing),
                      evidence_request=f"GET {url}",
                      evidence_response="response headers: " + ", ".join(sorted(present)),
                      steps=["fetch the page", "compare against expected security headers"])]


def _cookies(host, url, resp) -> list[Candidate]:
    out = []
    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    for sc in cookies:
        low = sc.lower()
        name = sc.split("=", 1)[0].strip()
        flaws = [f for f in ("httponly", "secure") if f not in low]
        if "samesite" not in low:
            flaws.append("samesite")
        if flaws:
            out.append(Candidate("cookie_flags", host=host, url=url, param=name, confidence=0.85,
                                 method="direct", note=f"cookie '{name}' missing: {', '.join(flaws)}",
                                 evidence_request=f"GET {url}",
                                 evidence_response=f"Set-Cookie: {name}=… ; (flags: {low.split(';',1)[-1].strip()})",
                                 steps=["read Set-Cookie attributes"]))
    return out


def _sensitive_files(host, url, client) -> list[Candidate]:
    origin = urlparse(url)._replace(path="", query="", fragment="").geturl()
    out = []
    for path, sig in SENSITIVE_FILES:
        target = urljoin(origin + "/", path.lstrip("/"))
        try:
            r = client.get(target)
        except Exception:
            continue
        if r.status_code == 200 and sig.search(r.text or ""):
            out.append(Candidate("sensitive_file", host=host, url=target, confidence=0.95,
                                 method="direct", note=f"exposed {path}",
                                 evidence_request=f"GET {target}",
                                 evidence_response=(r.text or "")[:200],
                                 steps=[f"request {path}", "content matches expected signature"]))
    return out


def _panels(host, url, client) -> list[Candidate]:
    origin = urlparse(url)._replace(path="", query="", fragment="").geturl()
    out = []
    for path, sig in ADMIN_PANELS:
        target = urljoin(origin + "/", path.lstrip("/"))
        try:
            r = client.get(target)
        except Exception:
            continue
        if r.status_code in (200, 401, 403) and sig.search(r.text or ""):
            out.append(Candidate("exposed_panel", host=host, url=target, confidence=0.6,
                                 method="direct", note=f"panel at {path} (HTTP {r.status_code})",
                                 evidence_request=f"GET {target}",
                                 evidence_response=(r.text or "")[:160],
                                 steps=[f"request {path}", "panel signature present"]))
    return out


def _reflected_xss(host, url, param, client) -> list[Candidate]:
    try:
        r = _get_override(client, url, param, _MARKER)
    except Exception:
        return []
    if _MARKER in (r.text or ""):
        return [Candidate("xss_reflected", host=host, url=url, param=param, confidence=0.5,
                          method="reflection", note=f"param '{param}' reflects input",
                          evidence_request=f"GET {url} [{param}={_MARKER}]",
                          steps=["inject a marker", "marker observed in response → verify encoding"])]
    return []


def _sqli(host, url, param, client) -> list[Candidate]:
    # surface a DB error with a single quote; the verifier confirms via boolean.
    try:
        base_val = (parse_qs(urlparse(url).query).get(param, ["1"])[0]) or "1"
        r = _get_override(client, url, param, base_val + "'")
    except Exception:
        return []
    body = r.text or ""
    engine = next((eng for rx, eng in SQL_ERRORS if rx.search(body)), None)
    if engine:
        return [Candidate("sqli", host=host, url=url, param=param, confidence=0.7,
                          method="boolean", vdata={"base_value": base_val},
                          note=f"{engine} error on quote in '{param}'",
                          evidence_request=f"GET {url} [{param}={base_val}']",
                          evidence_response=_first_error_line(body),
                          steps=["append a single quote", f"{engine} error surfaced → verify boolean"])]
    return []


def _get_override(client, url, param, value):
    from urllib.parse import urlencode
    parsed = urlparse(url)
    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    qs[param] = value
    return client.get(parsed._replace(query=urlencode(qs)).geturl())


def _first_error_line(body: str) -> str:
    for rx, _ in SQL_ERRORS:
        m = rx.search(body)
        if m:
            start = max(0, m.start() - 20)
            return body[start:m.end() + 60]
    return body[:120]
