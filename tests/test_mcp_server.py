"""AutoPwn as an MCP server: a real MCP client lists and calls its tools over
stdio, and the scope gate still applies."""
from __future__ import annotations

import sys

from autopwn.mcp.client import MCPClient
from autopwn.mcp.config import MCPServerConfig


def _client(tmp_path, *args):
    cfg = MCPServerConfig(name="autopwn", command=sys.executable,
                          args=["-m", "autopwn", "mcp-serve", *args],
                          env={"AUTOPWN_HOME": str(tmp_path / "home")}, timeout=60)
    c = MCPClient(cfg, errlog_path=str(tmp_path / "err.log"))
    c.connect(timeout=60)
    return c


def test_mcp_server_exposes_tools_and_enforces_scope(tmp_path):
    from autopwn.eval.targets import PlantedTarget
    with PlantedTarget() as lab:
        c = _client(tmp_path, "-t", "127.0.0.1", "--authorize")
        try:
            names = {t["name"] for t in c.list_tools()}
            assert {"web_recon", "template_scan", "verify_findings", "generate_report"} <= names
            assert "finish" not in names and "advance_phase" not in names
            text, data = c.invoke("web_recon", {"url": lab.base_url})
            assert "127.0.0.1" in text
            try:
                c.invoke("web_recon", {"url": "http://example.com"})
                raise AssertionError("out-of-scope call was not refused")
            except Exception as e:
                assert "scope" in str(e)
        finally:
            c.close()


def test_mcp_server_without_authorization_blocks_active_tools(tmp_path):
    c = _client(tmp_path, "-t", "127.0.0.1")
    try:
        try:
            c.invoke("network_scan", {"host": "127.0.0.1"})
            raise AssertionError("active tool ran without authorization")
        except Exception as e:
            assert "not authorized" in str(e)
    finally:
        c.close()
