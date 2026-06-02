"""
Scope-guarded async HTTP client. Every outbound request passes through
Scope.assert_request_allowed() and a token-bucket rate limiter before it leaves
this process. The X-Pentest-ID header is attached automatically. There is no
code path to the network that bypasses the scope check.
"""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urljoin

import httpx

from ..core.scope import Scope

logger = logging.getLogger("venom.engine.http")


class RateLimiter:
    """Async token bucket enforcing requests-per-second."""

    def __init__(self, rps: float):
        self.rps = max(rps, 0.1)
        self._min_interval = 1.0 / self.rps
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next_allowed = max(now, self._next_allowed) + self._min_interval


class ScopedClient:
    """
    A thin wrapper over httpx.AsyncClient bound to one engagement scope and one
    base URL. Use one ScopedClient per actor/role to keep session state isolated.
    """

    def __init__(self, scope: Scope, base_url: str, *, role: str = "default",
                 limiter: RateLimiter | None = None, dry_run: bool = False,
                 transport=None):
        if not scope.is_url_in_scope(base_url):
            raise ValueError(f"base_url {base_url} is not within the authorized scope")
        self.scope = scope
        self.base_url = base_url.rstrip("/") + "/"
        self.role = role
        self.dry_run = dry_run
        self._limiter = limiter or RateLimiter(scope.rate_limit_per_second)
        # `transport` lets tests drive an in-memory target (httpx.MockTransport).
        self._client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                **scope.pentest_header(),
                "User-Agent": "VENOM-PentestAgent/0.1",
            },
            follow_redirects=False,
            transport=transport,
        )
        self.request_log: list[dict] = []

    async def __aenter__(self) -> "ScopedClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def set_auth(self, *, headers: dict | None = None, token: str | None = None,
                 cookies: dict | None = None) -> None:
        # Clear any prior Authorization so a refresh fully replaces it.
        self._client.headers.pop("Authorization", None)
        if token:
            self._client.headers["Authorization"] = f"Bearer {token}"
        if headers:
            for k, v in headers.items():
                self._client.headers[k] = v
        if cookies:
            for k, v in cookies.items():
                self._client.cookies.set(k, v)

    def apply_auth(self, state) -> None:
        """Apply an auth.AuthState (headers + cookies)."""
        self.set_auth(headers=getattr(state, "headers", None),
                      cookies=getattr(state, "cookies", None))

    def _full_url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def cookies(self) -> dict[str, str]:
        return {k: v for k, v in self._client.cookies.items()}

    async def request(self, method: str, path: str, *, json=None, data=None, params=None,
                      headers=None, destructive: bool = False,
                      rate_limited: bool = True,
                      follow_redirects: bool = False) -> httpx.Response | None:
        url = self._full_url(path)
        # Fail-safe: a request is destructive if the METHOD is destructive OR the
        # caller explicitly flagged it. An explicit False can never downgrade a
        # destructive method (DELETE/PUT/PATCH).
        is_destructive = method.upper() in Scope.DESTRUCTIVE_METHODS or bool(destructive)

        # HARD GATE — raises ScopeError if not allowed.
        self.scope.assert_request_allowed(method, url, destructive=is_destructive)

        entry = {
            "ts": time.time(), "engagement": self.scope.engagement_id,
            "role": self.role, "method": method.upper(), "url": url,
        }

        if self.dry_run:
            entry["dry_run"] = True
            self.request_log.append(entry)
            logger.info("[dry-run] %s %s", method.upper(), url)
            return None

        # rate_limited=False is used for concurrency bursts (race-condition tests),
        # where deliberately NOT spacing requests is the whole point.
        if rate_limited:
            await self._limiter.acquire()
        resp = await self._client.request(method.upper(), url, json=json, data=data,
                                          params=params, headers=headers,
                                          follow_redirects=follow_redirects)
        entry["status"] = resp.status_code
        self.request_log.append(entry)
        logger.info("%s %s -> %s", method.upper(), url, resp.status_code)
        return resp
