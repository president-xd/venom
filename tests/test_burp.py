"""Burp MCP integration — keyless, graceful degradation when not provisioned."""

import asyncio

from venom.integrations import burp_status
from venom.integrations.burp_mcp import BurpMcpClient, BurpMcpError, mcp_sdk_available


def test_status_is_non_fatal_and_keyless():
    # Whether or not the SDK/Burp is present, this must return a dict, never raise,
    # and must never require an API key.
    info = asyncio.run(burp_status("http://127.0.0.1:9876/sse", timeout=2.0))
    assert isinstance(info, dict)
    assert "ok" in info
    if not info["ok"]:
        assert "reason" in info


def test_client_requires_sdk_when_absent():
    if mcp_sdk_available():
        # SDK present: constructing the client must not raise (connection is lazy).
        c = BurpMcpClient("http://127.0.0.1:9876/sse")
        assert c.url.endswith("/sse")
    else:
        # SDK absent: clear, actionable error — and no API key anywhere.
        try:
            BurpMcpClient("http://127.0.0.1:9876/sse")
            assert False, "expected BurpMcpError"
        except BurpMcpError as e:
            assert "mcp" in str(e).lower()
