"""Phase-2 tests: data governance (vault + redaction), the recon runner, the
target model, and per-domain recon — centered on the DoD:

  * redaction unit tests pass
  * a captured cookie appears as a placeholder in LLM context; the real value is
    used only locally
  * recon produces a tech + surface map per domain
"""
from __future__ import annotations

import io
import socket
import threading
import zipfile

import pytest

from autopwn.agent.tools import ToolRegistry
from autopwn.govern import PLACEHOLDER_RE, Redactor, Vault
from autopwn.recon import mobile, network, server
from autopwn.recon.browser import ingest_cookies
from autopwn.recon.registry import register_recon_tools
from autopwn.recon.runner import ALLOWED_BINARIES, available, run, which
from autopwn.recon.target_model import Service, Surface, TargetModel


# ── vault / redaction ─────────────────────────────────────────────────────────
def test_vault_tokenize_idempotent_and_resolve():
    v = Vault.open()
    p1 = v.tokenize("supersecret", kind="cookie", hint="sess")
    p2 = v.tokenize("supersecret", kind="cookie")
    assert p1 == p2                               # same value → same placeholder
    assert PLACEHOLDER_RE.fullmatch(p1)
    assert v.resolve(p1) == "supersecret"         # local resolve returns the real value
    assert "supersecret" not in p1

def test_vault_redact_and_inject_roundtrip():
    v = Vault.open()
    ph = v.tokenize("TOPSECRET-TOKEN")
    text = "the auth token is TOPSECRET-TOKEN, use it"
    redacted = v.redact(text)
    assert "TOPSECRET-TOKEN" not in redacted
    assert ph in redacted
    # inject reverses it for LOCAL execution
    assert v.inject(redacted) == text

def test_vault_inject_args_deep():
    v = Vault.open()
    ph = v.tokenize("cookieval")
    args = {"headers": {"Cookie": f"session={ph}"}, "list": [ph, "plain"]}
    out = v.inject_args(args)
    assert out["headers"]["Cookie"] == "session=cookieval"
    assert out["list"][0] == "cookieval"

def test_vault_encrypted_at_rest():
    v = Vault.open()
    v.tokenize("secret-value-123")
    # the stored blob must not contain the plaintext
    entry = next(iter(v._entries.values()))
    assert b"secret-value-123" not in entry.blob

def test_redactor_patterns_tokenize_into_vault():
    v = Vault.open()
    r = Redactor(v)
    text = ("GET / HTTP/1.1\n"
            "Authorization: Bearer eyJhbGciOi.AAAAAAAA.BBBBBBBB\n"
            "Set-Cookie: session=abcdef123456; Path=/\n"
            "api_key=SECRETKEY123456\n")
    scrubbed = r.scrub(text)
    assert "eyJhbGciOi.AAAAAAAA.BBBBBBBB" not in scrubbed
    assert "abcdef123456" not in scrubbed
    assert "SECRETKEY123456" not in scrubbed
    assert len(v) >= 3                            # secrets captured into the vault
    # and they can be re-injected locally
    assert "SECRETKEY123456" in v.inject(scrubbed)


# ── cookie → placeholder (DoD) ────────────────────────────────────────────────
def test_cookie_becomes_placeholder_value_stays_local():
    v = Vault.open()
    raw_cookies = [{"name": "session", "value": "REAL-SESSION-VALUE", "domain": "app.lab"}]
    safe = ingest_cookies(raw_cookies, vault=v)
    # what the agent sees:
    assert safe[0]["value"] != "REAL-SESSION-VALUE"
    assert PLACEHOLDER_RE.fullmatch(safe[0]["value"])
    assert safe[0]["name"] == "session"
    # the real value is only recoverable locally via the vault
    assert v.resolve(safe[0]["value"]) == "REAL-SESSION-VALUE"


# ── runner (allowlist + availability) ─────────────────────────────────────────
def test_runner_refuses_non_allowlisted_binary():
    res = run("rm", ["-rf", "/"])
    assert res.ok is False and "allowlist" in res.error
    assert "rm" not in ALLOWED_BINARIES

def test_runner_skips_absent_binary():
    # pick an allowlisted binary that isn't installed here
    absent = next(b for b in ALLOWED_BINARIES if which(b) is None)
    res = run(absent, ["--version"])
    assert res.skipped is True and res.ok is False

@pytest.mark.skipif(not available("openssl"), reason="openssl not installed")
def test_runner_runs_present_binary_and_redacts_argv():
    v = Vault.open()
    res = run("openssl", ["version"], vault=v)
    assert res.ok and "OpenSSL" in res.stdout
    assert res.argv_redacted == ["openssl", "version"]


# ── target model (surface merge) ──────────────────────────────────────────────
def test_target_model_merges_surfaces():
    tm = TargetModel()
    tm.observe(Surface(host="h", domain="web", tech=["PHP"], server="nginx"))
    merged = tm.observe(Surface(host="h", domain="web", tech=["WordPress"],
                                services=[Service(port=443, name="https")]))
    assert set(merged.tech) == {"PHP", "WordPress"}
    assert merged.server == "nginx"
    assert merged.services[0].port == 443


# ── network recon (real, offline: scan a local listener) ──────────────────────
def test_network_connect_scan_finds_open_port():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    def accept_once():
        srv.settimeout(2.0)
        try:
            c, _ = srv.accept(); c.close()
        except Exception:
            pass
    t = threading.Thread(target=accept_once, daemon=True); t.start()
    try:
        surface, raw = network.scan_host("127.0.0.1", ports=[port], vault=Vault.open(),
                                         prefer_nmap=False)
    finally:
        srv.close()
    assert surface.domain == "network"
    assert any(s.port == port for s in surface.services)


# ── server recon (graceful on an unreachable port) ────────────────────────────
def test_tls_inspect_handles_unreachable():
    surface, tls = server.inspect("127.0.0.1", 1)       # nothing listening on :1
    assert "error" in tls
    assert surface.domain == "server"


# ── mobile intake (synthetic APK) ─────────────────────────────────────────────
def _make_apk() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    b"\x03\x00android.permission.INTERNET android.permission.CAMERA "
                    b"com.example.vulnerableapp")
        zf.writestr("classes.dex",
                    b"dex\n035\x00 some strings https://api.example.com/v1/login "
                    b"AIzaSyA1234567890123456789012345678901Z key here")
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF binary blob")
        zf.writestr("assets/config.json", b'{"endpoint":"https://backend.example.com"}')
    buf.seek(0)
    return buf

def test_apk_inventory(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(_make_apk().read())
    v = Vault.open()
    surface, raw = mobile.apk_inventory(str(apk), vault=v)
    assert surface.domain == "mobile"
    assert raw["dex"] == 1
    assert any("api.example.com" in u for u in surface.endpoints)
    assert "android.permission.INTERNET" in raw["permissions"]
    # the Google API key was captured into the vault, not surfaced raw
    assert len(v) >= 1
    assert "AIzaSyA1234567890123456789012345678901Z" not in str(raw)
    assert "AIzaSyA1234567890123456789012345678901Z" not in surface.summary()


# ── recon tool registration ───────────────────────────────────────────────────
def test_register_recon_tools():
    reg = ToolRegistry()
    v = Vault.open()
    register_recon_tools(reg, ctx=None, vault=v, redactor=Redactor(v), target_model=TargetModel())
    for name in ("web_recon", "dns_lookup", "network_scan", "tls_inspect",
                 "apk_inventory", "browser_capture"):
        assert name in reg
    # browser tool is gated (launches a browser)
    assert reg.get("browser_capture").requires_approval is True
    # missing required arg → clean structured failure
    from autopwn.llm.provider import ToolCall
    assert reg.dispatch(ToolCall("c", "web_recon", {})).ok is False
