"""Benchmark targets: a local planted-vulnerability app plus a catalogue of
external targets (need a reachable instance), each with ground truth.
"""
from __future__ import annotations

import html
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class BenchmarkTarget:
    name: str
    kind: str                                   # "local" | "external"
    ground_truth: frozenset[str]                # expected VULN_CLASSES ids
    domain: str = "web"
    base_url: str = ""                          # external only (or filled for local)
    probes: tuple[str, ...] = ()                # URL paths to run detect_all against
    requires_instance: bool = False             # external targets need a live host
    notes: str = ""

    def probe_urls(self, base: str | None = None) -> list[str]:
        root = (base or self.base_url).rstrip("/")
        return [root + p for p in self.probes]


class _PlantedHandler(BaseHTTPRequestHandler):
    """A deliberately-vulnerable web app. Each route plants exactly one class."""

    def log_message(self, *a):                  # keep the benchmark quiet
        pass

    def _send(self, body: str, code: int = 200, cookie: str | None = None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        if cookie:
            self.send_header("Set-Cookie", cookie)   # intentionally no HttpOnly/Secure
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(p.query).items()}
        path = p.path

        if path == "/.env":                                  # sensitive_file
            return self._send("SECRET_KEY=supersecret\nDB_PASS=hunter2\n")
        if path == "/search":                                # xss_reflected (unencoded)
            return self._send(f"<html><body>results for: {qs.get('q','')}</body></html>",
                              cookie="sid=abc123; Path=/")   # + cookie_flags, + missing headers
        if path == "/item":                                  # sqli (error + boolean)
            idv = qs.get("id", "1")
            low = idv.lower()
            if "'" in idv and "=" not in idv:
                return self._send("You have an error in your SQL syntax; near ''", code=500)
            if "1=1" in low or "'1'='1" in low:
                return self._send("<p>Item: Widget</p>")
            if "1=2" in low or "'1'='2" in low:
                return self._send("<p>No item found.</p>")
            return self._send("<p>Item: Widget</p>")
        if path == "/safe":                                  # NOT vulnerable (encoded)
            return self._send(f"<html><body>q: {html.escape(qs.get('q',''))}</body></html>")
        return self._send("not found", code=404)


class PlantedTarget:
    """Context manager that serves the planted app on 127.0.0.1:<ephemeral>."""

    GROUND_TRUTH = frozenset({
        "sqli", "xss_reflected", "security_misconfig", "sensitive_file", "cookie_flags",
    })
    PROBE_PATHS = ("/item?id=1", "/search?q=hi")

    def __init__(self):
        self._srv: ThreadingHTTPServer | None = None
        self.base_url = ""

    def __enter__(self) -> PlantedTarget:
        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _PlantedHandler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        host, port = self._srv.server_address
        self.base_url = f"http://127.0.0.1:{port}"
        return self

    def __exit__(self, *exc) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv = None

    def target(self) -> BenchmarkTarget:
        return BenchmarkTarget(
            name="planted-web (local)", kind="local",
            ground_truth=self.GROUND_TRUTH, base_url=self.base_url,
            probes=self.PROBE_PATHS,
            notes="in-process planted-vulnerability app; fully offline & deterministic",
        )

    def probe_urls(self) -> list[str]:
        return [self.base_url + p for p in self.PROBE_PATHS]


def _load_external() -> list[BenchmarkTarget]:
    path = Path(__file__).resolve().parents[2] / "benchmarks" / "external_targets.json"
    out: list[BenchmarkTarget] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return out
    for row in data.get("targets", []):
        out.append(BenchmarkTarget(
            name=row["name"], kind="external",
            ground_truth=frozenset(row.get("ground_truth", [])),
            domain=row.get("domain", "web"),
            base_url=row.get("base_url", ""),
            probes=tuple(row.get("probes", [])),
            requires_instance=True,
            notes=row.get("notes", ""),
        ))
    return out


EXTERNAL_TARGETS: list[BenchmarkTarget] = _load_external()


def external_by_name(name: str) -> BenchmarkTarget | None:
    for t in EXTERNAL_TARGETS:
        if t.name.lower() == name.lower():
            return t
    return None
