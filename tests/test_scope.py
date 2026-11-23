"""The hard scope gate: no native tool may touch a target outside scope, and
active tools need the operator's authorization."""
from __future__ import annotations

import pytest

from autopwn.govern.scope import ScopeGuard, host_of, matches
from autopwn.llm.provider import ToolCall


@pytest.mark.parametrize("host,entry,ok", [
    ("app.lab", "app.lab", True),
    ("app.lab", "http://app.lab:8080/x", True),
    ("api.app.lab", "app.lab", False),
    ("api.app.lab", "*.app.lab", True),
    ("app.lab", "*.app.lab", True),
    ("evilapp.lab", "*.app.lab", False),
    ("10.0.5.7", "10.0.5.0/24", True),
    ("10.0.6.7", "10.0.5.0/24", False),
    ("10.0.5.7", "10.0.5.7", True),
])
def test_matching(host, entry, ok):
    assert matches(host, entry) is ok


def test_host_extraction():
    assert host_of("https://App.Lab:8443/login?x=1") == "app.lab"
    assert host_of("app.lab:80") == "app.lab"
    assert host_of("10.0.0.1") == "10.0.0.1"
    assert host_of("") == ""


def _guard(scope, out=(), authorized=True):
    return ScopeGuard(lambda: list(scope), lambda: list(out), lambda: authorized)


def test_guard_decisions():
    g = _guard(["*.app.lab", "10.0.5.0/24"], out=["admin.app.lab"])
    assert g.check({"url": "https://www.app.lab/"}, active=True).allowed
    assert not g.check({"url": "https://admin.app.lab/"}, active=True).allowed
    assert "not in scope" in g.check({"host": "example.com"}, active=True).reason
    assert not g.check({"targets": ["www.app.lab", "evil.com"]}, active=True).allowed
    assert g.check({"note": "no target here"}, active=True).allowed
    assert "not authorized" in _guard(["app.lab"], authorized=False).check({"host": "app.lab"}, active=True).reason
    assert _guard(["app.lab"], authorized=False).check({"host": "app.lab"}, active=False).allowed
    assert "no targets are in scope" in _guard([]).check({"host": "app.lab"}, active=False).reason
    inside, outside = g.filter_hosts(["a.app.lab", "admin.app.lab", "x.com"])
    assert inside == ["a.app.lab"] and outside == ["admin.app.lab", "x.com"]


def test_session_blocks_out_of_scope_tool_calls(make_session):
    s = make_session(targets=["app.lab"])
    blocked = s.registry.dispatch(ToolCall("1", "web_recon", {"url": "http://app.lab"}), s.ctx)
    assert not blocked.ok and "not authorized" in blocked.error          # not authorized yet
    s.set_scope(authorized=True)
    out = s.registry.dispatch(ToolCall("2", "network_scan", {"host": "evil.example"}), s.ctx)
    assert not out.ok and "not in scope" in out.error and out.data["blocked"]
    s.set_scope(out_of_scope=["app.lab"])
    again = s.registry.dispatch(ToolCall("3", "web_recon", {"url": "http://app.lab"}), s.ctx)
    assert "OUT of scope" in again.error


def test_every_target_touching_tool_is_gated(make_session):
    s = make_session(targets=["app.lab"])
    touching = {"web_recon", "network_scan", "tls_inspect", "browser_open", "dns_lookup",
                "detect_web", "detect_network", "detect_server"}
    for name in touching:
        assert s.registry.get(name).scoped, name
