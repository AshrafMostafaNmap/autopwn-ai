"""Scanner tools: argument safety, output parsing, scope, and findings flow —
with the external binaries simulated."""
from __future__ import annotations

import io
import json
import tarfile
import zipfile

import httpx
import pytest

import autopwn.recon.scanners as sc
from autopwn.llm.provider import ToolCall
from autopwn.recon import installer
from autopwn.recon.runner import CommandResult


@pytest.fixture
def fake_bins(monkeypatch):
    calls: list = []
    outputs: dict[str, str] = {}

    def fake_run(binary, args, **kw):
        calls.append((binary, args, kw.get("input_text")))
        return CommandResult(ok=True, binary=binary, argv_redacted=[binary, *args], returncode=0,
                             stdout=outputs.get(binary, ""))
    monkeypatch.setattr(sc, "run", fake_run)
    monkeypatch.setattr(sc, "available", lambda b: True)
    monkeypatch.setattr(installer, "template_count", lambda: 100)
    return calls, outputs


def _session(make_session):
    s = make_session(targets=["*.app.lab", "app.lab"])
    s.set_scope(authorized=True)
    return s


def _call(s, name, **args):
    return s.registry.dispatch(ToolCall("x", name, args), s.ctx)


def test_template_scan_is_safe_and_feeds_findings(make_session, fake_bins):
    calls, outputs = fake_bins
    outputs["nuclei"] = json.dumps({
        "template-id": "git-config", "matched-at": "http://app.lab/.git/config", "host": "app.lab",
        "info": {"name": "Git Config Exposure", "severity": "medium", "description": "repo exposed",
                 "remediation": "block /.git", "classification": {"cwe-id": ["cwe-200"]}},
        "request": "GET /.git/config HTTP/1.1", "response": "HTTP/1.1 200 OK\n[core]"}) + "\n"
    s = _session(make_session)
    r = _call(s, "template_scan", targets=["http://app.lab"])
    assert r.ok and r.data["matches"][0]["template"] == "git-config"
    argv = calls[-1][1]
    excluded = argv[argv.index("-etags") + 1].split(",")
    assert {"dos", "intrusive", "fuzz", "bruteforce", "rce"} <= set(excluded)
    assert "-rl" in argv
    f = s.findings()[0]
    assert f.title == "Git Config Exposure" and f.cwe == "CWE-200" and f.severity.rating.value == "medium"
    assert f.remediation == "block /.git" and f.status.value == "suspected"


def test_scanners_respect_scope(make_session, fake_bins):
    calls, _ = fake_bins
    s = _session(make_session)
    for name, args in (("template_scan", {"targets": ["http://evil.com"]}),
                       ("http_probe", {"targets": ["app.lab", "evil.com"]}),
                       ("crawl", {"url": "http://evil.com"}),
                       ("content_discovery", {"url": "http://evil.com"}),
                       ("subdomain_discovery", {"domain": "evil.com"})):
        r = _call(s, name, **args)
        assert not r.ok and "scope" in r.error, name
    assert calls == []                                       # nothing ever ran


def test_subdomains_split_by_scope(make_session, fake_bins):
    _, outputs = fake_bins
    outputs["subfinder"] = "\n".join(json.dumps({"host": h}) for h in ("www.app.lab", "api.app.lab")) + "\n"
    s = make_session(targets=["app.lab", "www.app.lab"])
    r = _call(s, "subdomain_discovery", domain="app.lab")
    assert r.data["in_scope"] == ["www.app.lab"] and r.data["out_of_scope"] == ["api.app.lab"]


def test_http_probe_and_crawl_update_the_target_model(make_session, fake_bins):
    calls, outputs = fake_bins
    outputs["httpx"] = json.dumps({"url": "https://app.lab", "status_code": 200, "title": "Shop",
                                   "webserver": "nginx", "tech": ["Express"]}) + "\n"
    outputs["katana"] = "\n".join(json.dumps({"request": {"endpoint": f"https://app.lab/{p}"}})
                                  for p in ("login", "search?q=1")) + "\n"
    s = _session(make_session)
    r = _call(s, "http_probe", targets=["app.lab"])
    assert r.data["live"][0]["server"] == "nginx" and calls[-1][2] == "app.lab\n"
    r = _call(s, "crawl", url="https://app.lab", depth=9)
    argv = calls[-1][1]
    assert argv[argv.index("-d") + 1] == "3"                  # depth is capped
    surf = s.target_model.get("app.lab")
    assert surf.server == "nginx" and "/login" in surf.endpoints


def test_content_discovery_uses_bundled_wordlist(make_session, fake_bins):
    calls, outputs = fake_bins
    outputs["ffuf"] = json.dumps({"input": {"FUZZ": ".git/HEAD"}, "status": 200, "length": 23}) + "\n"
    s = _session(make_session)
    r = _call(s, "content_discovery", url="http://app.lab/")
    argv = calls[-1][1]
    assert argv[argv.index("-u") + 1] == "http://app.lab/FUZZ"
    assert open(argv[argv.index("-w") + 1]).read().count("\n") > 50
    assert r.data["found"][0]["path"] == "/.git/HEAD"


def test_missing_scanner_says_how_to_install(make_session, monkeypatch):
    monkeypatch.setattr(sc, "available", lambda b: False)
    s = _session(make_session)
    r = _call(s, "template_scan", targets=["http://app.lab"])
    assert "autopwnai tools install nuclei" in r.error


# ── installer ─────────────────────────────────────────────────────────────────
def _zip(name, payload=b"#!/bin/sh\necho ok\n"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"../../evil/{name}", payload)            # hostile path is ignored
    return buf.getvalue()


def _mock(archive_name, blob, checksum):
    def handler(req: httpx.Request):
        url = str(req.url)
        if url.endswith("/releases/latest"):
            return httpx.Response(200, json={"tag_name": "v1.0.0", "assets": [
                {"name": archive_name, "browser_download_url": "https://dl/a"},
                {"name": "x_checksums.txt", "browser_download_url": "https://dl/sums"}]})
        if url == "https://dl/a":
            return httpx.Response(200, content=blob)
        return httpx.Response(200, text=f"{checksum}  {archive_name}\n")
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_installer_verifies_checksum_and_extracts_safely(monkeypatch, tmp_path):
    import hashlib
    monkeypatch.setattr(installer, "bin_dir", lambda: tmp_path / "bin")
    monkeypatch.setattr(installer, "platform_tags", lambda: (("linux",), ("amd64",)))
    blob = _zip("katana")
    good = installer.install("katana", client=_mock("katana_1.0.0_linux_amd64.zip", blob,
                                                    hashlib.sha256(blob).hexdigest()))
    assert good == tmp_path / "bin" / "katana" and good.read_bytes().startswith(b"#!/bin/sh")
    assert not (tmp_path / "evil").exists()
    with pytest.raises(installer.InstallError, match="checksum mismatch"):
        installer.install("katana", client=_mock("katana_1.0.0_linux_amd64.zip", blob, "0" * 64))
    with pytest.raises(installer.InstallError, match="system package"):
        installer.install("nmap")


def test_asset_selection():
    names = ["nuclei_3.1_linux_amd64.zip", "nuclei_3.1_linux_arm64.zip", "nuclei_3.1_macOS_arm64.zip",
             "naabu_2.7.0_linux_amd64_musl.zip", "nuclei_3.1_checksums.txt"]
    import autopwn.recon.installer as inst
    orig = inst.platform_tags
    try:
        inst.platform_tags = lambda: (("linux",), ("amd64", "x86_64"))
        assert inst.pick_asset(names, "nuclei") == ("nuclei_3.1_linux_amd64.zip", "nuclei_3.1_checksums.txt")
        inst.platform_tags = lambda: (("darwin", "macos"), ("arm64", "aarch64"))
        assert inst.pick_asset(names, "nuclei")[0] == "nuclei_3.1_macOS_arm64.zip"
    finally:
        inst.platform_tags = orig


def test_tar_extraction(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        data = b"bin"
        info = tarfile.TarInfo("ffuf")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    assert installer._extract(buf.getvalue(), "ffuf_2.3.0_linux_amd64.tar.gz", "ffuf") == b"bin"


def test_sarif_report(make_session, tmp_path):
    from autopwn.core.findings import Status
    from autopwn.detect.model import Candidate
    from autopwn.report import ReportBuilder, ReportMeta
    s = make_session(targets=["app.lab"])
    f = s.pipeline.add(Candidate("sqli", host="app.lab", url="http://app.lab/s?q=1", param="q"))
    f.status = Status.VERIFIED
    out = ReportBuilder(tmp_path).build([f], ReportMeta(run_id="r1", targets=["app.lab"]), formats=["sarif"])
    doc = json.loads(open(out["sarif"]["path"]).read())
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "AutoPwn AI"
    res = run["results"][0]
    assert res["level"] == "error" and "parameter q" in res["message"]["text"]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == res["ruleId"] and float(rule["properties"]["security-severity"]) >= 9.0


def test_ffuf_paths_are_decoded():
    assert sc._ffuf_input({"input": {"FUZZ": "LmVudg=="}}) == ".env"
    assert sc._ffuf_input({"input": {"FUZZ": "admin"}, "url": "http://x/admin"}) == "admin"


def test_template_scan_needs_templates(make_session, fake_bins, monkeypatch):
    monkeypatch.setattr(installer, "template_count", lambda: 0)
    s = _session(make_session)
    r = _call(s, "template_scan", targets=["http://app.lab"])
    assert "no templates" in r.error and "tools update" in r.error


def test_nuclei_groups_matchers_skips_info_and_uses_default_tags(make_session, fake_bins):
    calls, outputs = fake_bins
    rows = [{"template-id": "http-missing-security-headers", "matched-at": "http://app.lab", "matcher-name": h,
             "info": {"name": "HTTP Missing Security Headers", "severity": "info"}}
            for h in ("content-security-policy", "strict-transport-security", "content-security-policy")]
    rows.append({"template-id": "generic-env", "matched-at": "http://app.lab/.env",
                 "info": {"name": "Generic Env File Disclosure", "severity": "high"}})
    outputs["nuclei"] = "\n".join(json.dumps(r) for r in rows) + "\n"
    s = _session(make_session)
    r = _call(s, "template_scan", targets=["http://app.lab"])
    argv = calls[-1][1]
    assert argv[argv.index("-tags") + 1] == sc.NUCLEI_DEFAULT_TAGS and "-pt" in argv
    headers = next(m for m in r.data["matches"] if m["template"] == "http-missing-security-headers")
    assert headers["matchers"] == ["content-security-policy", "strict-transport-security"]
    assert len(r.data["matches"]) == 2
    assert [f.title for f in s.findings()] == ["Generic Env File Disclosure"]     # info stays out
    _call(s, "template_scan", targets=["http://app.lab"], full=True)
    assert "-tags" not in calls[-1][1]
