"""Phase-3 tests: detection + safe verification + pipeline + coverage.

A local, deliberately-vulnerable HTTP server (and a safe one on the same host)
lets us prove the DoD offline and deterministically:
  * detection yields SUSPECTED findings,
  * safe verification promotes the real ones to VERIFIED,
  * false positives (reflected-but-encoded) are filtered by verification,
  * CVSS is auto-scored and coverage signals completion.
"""
from __future__ import annotations

import html
import io
import socket
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from autopwn.core.findings import Severity, Status
from autopwn.detect import VULN_CLASSES, CoverageTracker, FindingsPipeline, SafeVerifier, make_finding
from autopwn.detect import mobile as dmob
from autopwn.detect import network as dnet
from autopwn.detect import server as dsrv
from autopwn.detect import web as dweb
from autopwn.detect.model import Candidate
from autopwn.recon.target_model import Service, Surface

FAKE_GOOGLE_KEY = "AIza" + "SyA" + "1234567890" * 3 + "1Z"     # shaped like a key, not one


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep tests quiet
        pass

    def _send(self, body: str, code=200, headers=None, cookie=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(p.query).items()}
        path = p.path

        if path == "/":                                   # missing headers + bad cookie
            return self._send("<h1>home</h1>", cookie="sid=abc123; Path=/")
        if path == "/.env":                               # sensitive file exposed
            return self._send("SECRET_KEY=supersecret\nDB_PASS=hunter2\n")
        if path == "/search":                             # reflected XSS (unencoded)
            q = qs.get("q", "")
            return self._send(f"<html><body>results for: {q}</body></html>")
        if path == "/safe":                               # reflected but ENCODED (not vuln)
            q = qs.get("q", "")
            return self._send(f"<html><body>results for: {html.escape(q)}</body></html>")
        if path == "/item":                               # error- + boolean-SQLi
            idv = qs.get("id", "1")
            low = idv.lower()
            if "'" in idv and "=" not in idv:
                return self._send("You have an error in your SQL syntax; near ''", code=500)
            if "1=1" in low or "'1'='1" in low:
                return self._send("<p>Item: Widget</p>")
            if "1=2" in low or "'1'='2" in low:
                return self._send("<p>No item found.</p>")
            return self._send("<p>Item: Widget</p>")      # baseline, no reflection
        if path == "/safeitem":                           # not injectable
            return self._send("<p>Item: Widget</p>")
        return self._send("not found", code=404)


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_web_detect_and_verify(server):
    pipe = FindingsPipeline()
    verifier = SafeVerifier()
    try:
        pipe.add_all(dweb.detect_all(f"{server}/search?q=x"))
        pipe.add_all(dweb.detect_all(f"{server}/item?id=1"))
        # everything starts SUSPECTED
        assert all(f.status is Status.SUSPECTED for f in pipe.all())
        classes_suspected = {f.title for f in pipe.suspected()}
        assert "Reflected Cross-Site Scripting" in classes_suspected
        assert "SQL Injection" in classes_suspected

        promoted = pipe.verify_all(verifier)
        verified_titles = {f.title for f in promoted}
        # the real ones get confirmed non-destructively
        assert "Reflected Cross-Site Scripting" in verified_titles
        assert "SQL Injection" in verified_titles
        assert "Sensitive File Exposure" in verified_titles
        assert "Security Misconfiguration (missing headers)" in verified_titles
        # only verified findings are reportable
        assert all(f.status is Status.VERIFIED for f in pipe.reportable())
        assert len(pipe.reportable()) == len(promoted)
    finally:
        verifier.close()


def test_false_positive_is_filtered(server):
    """Encoded reflection is detected as SUSPECTED but verification rejects it."""
    pipe = FindingsPipeline()
    verifier = SafeVerifier()
    try:
        pipe.add_all(dweb.detect_all(f"{server}/safe?q=x"))
        xss_suspected = [f for f in pipe.suspected() if f.title.startswith("Reflected")]
        assert xss_suspected                              # detector flagged the reflection
        pipe.verify_all(verifier)
        # ...but it never becomes a reportable finding (encoded → safe)
        xss_reportable = [f for f in pipe.reportable() if f.title.startswith("Reflected")]
        assert not xss_reportable
    finally:
        verifier.close()


def test_sqli_not_injectable_stays_suspected_or_absent(server):
    pipe = FindingsPipeline()
    verifier = SafeVerifier()
    try:
        pipe.add_all(dweb.detect_all(f"{server}/safeitem?id=1"))
        pipe.verify_all(verifier)
        assert not [f for f in pipe.reportable() if f.title == "SQL Injection"]
    finally:
        verifier.close()


def test_make_finding_scores_from_table():
    c = Candidate("sqli", host="h", url="http://h/x?id=1", param="id")
    f = make_finding(c)
    vc = VULN_CLASSES["sqli"]
    assert f.severity.cvss_score == vc.cvss_score
    assert f.severity.rating is Severity.CRITICAL
    assert f.cwe == "CWE-89"
    assert f.detection_guidance and f.remediation          # purple fields present

def test_pipeline_dedup():
    pipe = FindingsPipeline()
    c1 = Candidate("security_misconfig", host="h", url="http://h/a", confidence=0.5)
    c2 = Candidate("security_misconfig", host="h", url="http://h/a", confidence=0.9)
    f1 = pipe.add(c1)
    f2 = pipe.add(c2)
    assert f1.id == f2.id and len(pipe.all()) == 1         # same (class,host,path) → one
    assert pipe.all()[0].confidence == 0.9                 # keeps higher confidence


def test_network_cleartext_verifies_direct():
    surface = Surface(host="10.0.0.5", domain="network",
                      services=[Service(port=23, name="telnet")])
    pipe = FindingsPipeline(); verifier = SafeVerifier()
    pipe.add_all(dnet.detect_from_surface(surface))
    promoted = pipe.verify_all(verifier); verifier.close()
    assert any(f.title == "Cleartext Service Exposed" for f in promoted)

def test_network_unreachable_datastore_stays_suspected():
    # redis candidate but nothing is listening → protocol verify fails → suspected
    surface = Surface(host="127.0.0.1", domain="network",
                      services=[Service(port=6379, name="redis")])
    pipe = FindingsPipeline(); verifier = SafeVerifier()
    pipe.add_all(dnet.detect_from_surface(surface))
    pipe.verify_all(verifier); verifier.close()
    assert not pipe.reportable()
    assert pipe.suspected()

def test_server_weak_tls_verifies():
    surface = Surface(host="h", domain="server", server="nginx/1.10.3")
    surface.tls = {"protocol": "TLSv1", "cipher": "x", "issuer": "self",
                   "notes": ["weak TLS protocol negotiated: TLSv1", "certificate is self-signed"]}
    pipe = FindingsPipeline(); verifier = SafeVerifier()
    pipe.add_all(dsrv.detect_from_surface(surface))
    promoted = pipe.verify_all(verifier); verifier.close()
    assert any(f.title == "Weak / Invalid TLS" for f in promoted)

def _make_apk_with_flags() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    b"manifest android:usesCleartextTraffic true android:debuggable true "
                    b"android.permission.INTERNET")
        zf.writestr("classes.dex", b"dex key " + FAKE_GOOGLE_KEY.encode() + b" end")
    return buf.getvalue()

def test_mobile_detect_and_verify(tmp_path):
    apk = tmp_path / "x.apk"; apk.write_bytes(_make_apk_with_flags())
    from autopwn.recon import mobile as rmobile
    _s, raw = rmobile.apk_inventory(str(apk))
    pipe = FindingsPipeline(); verifier = SafeVerifier()
    pipe.add_all(dmob.detect_from_inventory(raw, "x.apk"))
    promoted = pipe.verify_all(verifier); verifier.close()
    titles = {f.title for f in promoted}
    assert "Hardcoded Secret in App" in titles
    assert "Cleartext Traffic Allowed" in titles


def test_protocol_verify_fake_redis():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    def serve():
        srv.settimeout(3)
        try:
            c, _ = srv.accept()
            c.recv(64)                                     # the INFO probe
            c.sendall(b"redis_version:7.2.0\r\n")
            c.close()
        except Exception:
            pass
    threading.Thread(target=serve, daemon=True).start()
    # the port isn't 6379 so wire the probe explicitly like the detector does
    cand = Candidate("exposed_service", host="127.0.0.1", param=str(port), method="protocol",
                     vdata={"port": port, "probe": b"INFO\r\n", "expect": "redis_version", "service": "redis"})
    pipe = FindingsPipeline(); verifier = SafeVerifier()
    pipe.add(cand)
    promoted = pipe.verify_all(verifier); verifier.close(); srv.close()
    assert any(f.title == "Unauthenticated Exposed Service" for f in promoted)


def test_coverage_complete_signal():
    cov = CoverageTracker(plateau=2, max_rounds=99)
    cov.expect_target("h", "web")
    assert not cov.is_complete()                           # checklist not done
    cov.mark_checked_many("h", "web")
    assert cov.checklist_done
    cov.record_round(1)                                    # a verified finding → resets plateau
    assert not cov.is_complete()
    cov.record_round(0); cov.record_round(0)               # two stale rounds → plateau
    assert cov.is_complete()

def test_coverage_budget_backstop():
    cov = CoverageTracker(plateau=99, max_rounds=2)
    cov.expect_target("h", "web")
    cov.record_round(0); cov.record_round(0)
    assert cov.is_complete()                               # budget hit regardless of checklist


def test_playbooks_load():
    from autopwn import playbooks
    assert "web" in playbooks.available()
    assert "SQL injection" in playbooks.load("web")
    assert playbooks.load("nonsense") == ""
