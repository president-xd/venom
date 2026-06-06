"""
Redirect scope-guard regression tests.

The scope guard is the single chokepoint and its module docstring promises "there
is no code path to the network that bypasses the scope check". httpx follows 30x
redirects INTERNALLY, so before the event-hook guard a target could 302 VENOM to an
out-of-scope host and that off-scope request would be sent unchecked (leaking the
X-Pentest-ID / auth headers off the authorized surface). These tests prove the guard
now fires on every hop - blocking out-of-scope redirects BEFORE they leave the
process, while leaving legitimate in-scope redirects working and not double-charging
the destructive budget.
"""

from __future__ import annotations

import httpx
import pytest

from venom.core.scope import Scope, ScopeError
from venom.engine.http_client import ScopedClient


def _scope(**kw):
    base = dict(engagement_id="E", target_name="t",
                authorized_base_urls=["https://in-scope.example"],
                authorization_date="2026-01-01T00:00:00Z",
                expiry_date="2030-01-01T00:00:00Z")
    base.update(kw)
    return Scope.from_dict(base)


async def test_redirect_to_out_of_scope_host_is_blocked_before_egress():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "in-scope.example":
            # A compromised/misbehaving target bounces us off the authorized surface.
            return httpx.Response(302, headers={"Location": "https://evil.example/steal"})
        return httpx.Response(200, text="landed on evil")

    scope = _scope()
    client = ScopedClient(scope, "https://in-scope.example", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(ScopeError):
            await client.request("GET", "/start", follow_redirects=True)
        # The out-of-scope host must NEVER have been contacted (prevention, not detection).
        assert not any("evil.example" in u for u in seen), f"off-scope egress occurred: {seen}"
    finally:
        await client.aclose()


async def test_in_scope_relative_redirect_is_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(302, headers={"Location": "/dashboard"})
        return httpx.Response(200, text="DASHBOARD-OK")

    scope = _scope()
    client = ScopedClient(scope, "https://in-scope.example", transport=httpx.MockTransport(handler))
    try:
        resp = await client.request("GET", "/login", follow_redirects=True)
        assert resp is not None and resp.status_code == 200
        assert "DASHBOARD-OK" in resp.text
    finally:
        await client.aclose()


async def test_redirect_guard_does_not_double_count_destructive_budget():
    """A single DELETE that 30x-redirects to an in-scope path must consume exactly ONE
    destructive-budget slot, not one per hop."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/a":
            return httpx.Response(307, headers={"Location": "/b"})  # 307 preserves DELETE
        return httpx.Response(200, text="deleted")

    scope = _scope(allow_destructive=True, max_destructive_actions=1)
    client = ScopedClient(scope, "https://in-scope.example", transport=httpx.MockTransport(handler))
    try:
        resp = await client.request("DELETE", "/a", follow_redirects=True)
        assert resp is not None and resp.status_code == 200
        # exactly one slot consumed despite the extra redirect hop
        assert scope._destructive_used == 1
    finally:
        await client.aclose()
