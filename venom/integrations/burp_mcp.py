"""
Burp Suite MCP integration — KEYLESS.

The PortSwigger "MCP Server" Burp extension exposes a local Model Context
Protocol endpoint (default SSE: http://127.0.0.1:9876/sse). It runs on the
analyst's own machine alongside Burp, so there is no API key and no cloud
service — VENOM just speaks MCP to it over loopback.

Provisioning Burp + the extension is handled by scripts/setup_burp.* and
scripts/run_burp_mcp.* so the endpoint is available before you run an engagement.

This client uses the official `mcp` Python SDK (optional dependency):
    pip install "venom-agent[burp]"      # installs `mcp`
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("venom.burp")

try:  # Official MCP SDK is an optional extra.
    from mcp import ClientSession  # type: ignore
    from mcp.client.sse import sse_client  # type: ignore

    _MCP_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    ClientSession = None  # type: ignore
    sse_client = None  # type: ignore
    _MCP_AVAILABLE = False


class BurpMcpError(RuntimeError):
    """Raised for any Burp MCP connectivity or protocol problem."""


def mcp_sdk_available() -> bool:
    return _MCP_AVAILABLE


class BurpMcpClient:
    """
    Thin async wrapper over an MCP ClientSession connected to Burp's local
    MCP SSE endpoint. No credentials: access control is loopback-only.

    Usage:
        async with BurpMcpClient("http://127.0.0.1:9876/sse") as burp:
            tools = await burp.list_tools()
            out = await burp.call_tool("send_http1_request", {...})
    """

    def __init__(self, url: str, *, timeout: float = 30.0):
        if not _MCP_AVAILABLE:
            raise BurpMcpError(
                "The MCP SDK is not installed. Install it with "
                "`pip install \"venom-agent[burp]\"` (or `pip install mcp`)."
            )
        self.url = url
        self.timeout = timeout
        self._session: "ClientSession | None" = None
        self._cm = None  # the sse_client context manager
        self._session_cm = None

    async def __aenter__(self) -> "BurpMcpClient":
        try:
            self._cm = sse_client(self.url)
            read, write = await self._cm.__aenter__()
            self._session_cm = ClientSession(read, write)
            self._session = await self._session_cm.__aenter__()
            await asyncio.wait_for(self._session.initialize(), timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            await self._safe_close()
            raise BurpMcpError(
                f"Could not connect to Burp MCP at {self.url}: {exc}. "
                "Is Burp running with the MCP Server extension? "
                "Start it with scripts/run_burp_mcp.ps1 (or .sh)."
            ) from exc
        return self

    async def __aexit__(self, *exc) -> None:
        await self._safe_close()

    async def _safe_close(self) -> None:
        try:
            if self._session_cm is not None:
                await self._session_cm.__aexit__(None, None, None)
        finally:
            self._session_cm = None
            self._session = None
            if self._cm is not None:
                await self._cm.__aexit__(None, None, None)
                self._cm = None

    async def list_tools(self) -> list[dict[str, Any]]:
        if self._session is None:
            raise BurpMcpError("Not connected — use `async with BurpMcpClient(...)`.")
        resp = await self._session.list_tools()
        return [{"name": t.name, "description": t.description} for t in resp.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        if self._session is None:
            raise BurpMcpError("Not connected — use `async with BurpMcpClient(...)`.")
        return await self._session.call_tool(name, arguments or {})


async def burp_status(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Non-fatal connectivity probe used by the CLI (`venom burp --status`)."""
    if not _MCP_AVAILABLE:
        return {"ok": False, "reason": "mcp SDK not installed (pip install \"venom-agent[burp]\")"}
    try:
        async with BurpMcpClient(url, timeout=timeout) as burp:
            tools = await burp.list_tools()
        return {"ok": True, "url": url, "tool_count": len(tools),
                "tools": [t["name"] for t in tools[:20]]}
    except BurpMcpError as exc:
        return {"ok": False, "url": url, "reason": str(exc)}
