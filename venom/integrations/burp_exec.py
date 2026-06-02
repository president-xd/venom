"""
Burp execution adapter — routes selected operations through Burp's keyless local
MCP server (set up via scripts/setup_burp.*). Two capabilities:

  - send(): replay a request through Burp (so it lands in Burp's history/Repeater
    and is visible to the human analyst during hand-off).
  - oob_check(): poll Burp Collaborator for out-of-band interactions (SSRF/XXE/
    DNS-rebinding callbacks) triggered during a test.

This is best-effort and fully optional: if Burp / the MCP SDK is unavailable,
every method degrades to a no-op so engagements still run via httpx.
"""

from __future__ import annotations

import logging
from typing import Any

from .burp_mcp import BurpMcpClient, BurpMcpError, mcp_sdk_available

logger = logging.getLogger("venom.burp.exec")

# Tool names vary across MCP extension versions; we try a few aliases.
_SEND_TOOLS = ("send_http1_request", "send_http_request", "send_request", "repeater_send")
_OOB_TOOLS = ("collaborator_poll", "poll_collaborator", "get_collaborator_interactions")


class BurpExecutor:
    def __init__(self, url: str):
        self.url = url
        self.available = mcp_sdk_available()
        self._tool_names: set[str] = set()

    async def _tools(self, burp: BurpMcpClient) -> set[str]:
        if not self._tool_names:
            self._tool_names = {t["name"] for t in await burp.list_tools()}
        return self._tool_names

    async def send(self, method: str, url: str, headers: dict | None = None,
                   body: str | None = None) -> dict[str, Any] | None:
        if not self.available:
            return None
        try:
            async with BurpMcpClient(self.url) as burp:
                tools = await self._tools(burp)
                tool = next((t for t in _SEND_TOOLS if t in tools), None)
                if not tool:
                    return None
                return {"tool": tool,
                        "result": await burp.call_tool(tool, {
                            "method": method, "url": url,
                            "headers": headers or {}, "body": body or ""})}
        except BurpMcpError as exc:
            logger.debug("Burp send unavailable: %s", exc)
            return None

    async def oob_check(self) -> list[Any]:
        if not self.available:
            return []
        try:
            async with BurpMcpClient(self.url) as burp:
                tools = await self._tools(burp)
                tool = next((t for t in _OOB_TOOLS if t in tools), None)
                if not tool:
                    return []
                res = await burp.call_tool(tool, {})
                return [res] if res else []
        except BurpMcpError as exc:
            logger.debug("Burp OOB check unavailable: %s", exc)
            return []
