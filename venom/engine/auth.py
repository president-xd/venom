"""
Authentication & identity management.

Business-logic testing is fundamentally multi-actor and authenticated. This
module turns the scope's `identities` into live, refreshable credentials applied
to per-identity HTTP sessions.

Supported auth types (the `auth` block of an identity):

    {"type": "bearer", "token": "..."}                     static bearer token
    {"type": "cookie", "cookies": {"session": "..."}}      static cookies
    {"type": "basic",  "username": "...", "password": "..."}
    {"type": "login",                                       login flow (recommended)
       "method": "POST", "path": "/api/v1/login",
       "body": {"username": "alice", "password": "pw"},
       "token_path": "$.access_token",                      where the token is in the response
       "place": "header", "header": "Authorization", "scheme": "Bearer",
       "cookie_from_response": false}                        (or place="cookie")

All login traffic goes through the scope guard like any other request.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ..core.scope import Scope, ScopeError
from ..utils import jsonpath

logger = logging.getLogger("venom.engine.auth")


@dataclass
class Identity:
    name: str
    role: str = ""
    auth: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Identity":
        if not d.get("name"):
            raise ScopeError("Each identity needs a 'name'.")
        return cls(name=d["name"], role=d.get("role", ""), auth=d.get("auth", {}))


@dataclass
class AuthState:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    obtained_at: float = 0.0
    is_login: bool = False  # whether it can be refreshed by re-running a flow


class AuthManager:
    """Resolves identities to AuthState, logging in lazily and refreshing on demand."""

    def __init__(self, scope: Scope, *, dry_run: bool = False, transport=None):
        self.scope = scope
        self.dry_run = dry_run
        self._transport = transport
        self.identities: dict[str, Identity] = {
            i.name: i for i in (Identity.from_dict(d) for d in scope.identities)
        }
        self._states: dict[str, AuthState] = {}

    def has(self, name: str | None) -> bool:
        return bool(name) and name in self.identities

    async def ensure(self, name: str) -> AuthState:
        if name in self._states:
            return self._states[name]
        state = await self._authenticate(self.identities[name])
        self._states[name] = state
        return state

    async def refresh(self, name: str) -> AuthState:
        self._states.pop(name, None)
        return await self.ensure(name)

    # ------------------------------------------------------------------ internals
    async def _authenticate(self, ident: Identity) -> AuthState:
        a = ident.auth or {}
        atype = a.get("type", "login")

        if atype == "bearer":
            tok = a.get("token", "")
            return AuthState(headers={"Authorization": f"Bearer {tok}"}, token=tok)

        if atype == "cookie":
            return AuthState(cookies=dict(a.get("cookies", {})))

        if atype == "basic":
            raw = f"{a.get('username','')}:{a.get('password','')}".encode()
            enc = base64.b64encode(raw).decode()
            return AuthState(headers={"Authorization": f"Basic {enc}"})

        if atype == "login":
            return await self._login_flow(ident)

        if atype == "form_login":
            return await self._form_login_flow(ident)

        if atype in ("none", ""):
            return AuthState()

        raise ScopeError(f"Unknown auth type '{atype}' for identity '{ident.name}'.")

    async def _login_flow(self, ident: Identity) -> AuthState:
        # Imported here to avoid a circular import (http_client imports nothing here).
        from .http_client import ScopedClient

        a = ident.auth
        method = a.get("method", "POST")
        path = a.get("path")
        if not path:
            raise ScopeError(f"Identity '{ident.name}' login needs a 'path'.")

        if self.dry_run:
            logger.info("[auth] (dry-run) would log in identity '%s' via %s %s",
                        ident.name, method, path)
            return AuthState(headers={"Authorization": "Bearer <dry-run>"}, is_login=True)

        async with ScopedClient(self.scope, self.scope.authorized_base_urls[0],
                                role=f"auth:{ident.name}", transport=self._transport) as client:
            resp = await client.request(method, path, json=a.get("body"), rate_limited=True)
        if resp is None or resp.status_code >= 400:
            code = getattr(resp, "status_code", "n/a")
            raise ScopeError(f"Login failed for identity '{ident.name}' (status {code}).")

        place = a.get("place", "header")
        state = AuthState(obtained_at=time.time(), is_login=True)

        if place == "cookie" or a.get("cookie_from_response"):
            state.cookies = {k: v for k, v in resp.cookies.items()}
            logger.info("[auth] logged in '%s' — captured %d cookie(s)", ident.name, len(state.cookies))
            return state

        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            data = {}
        token = jsonpath(data, a.get("token_path", "$.token")) or ""
        if not token:
            raise ScopeError(
                f"Login for '{ident.name}' returned no token at "
                f"{a.get('token_path', '$.token')}."
            )
        scheme = a.get("scheme", "Bearer")
        header = a.get("header", "Authorization")
        state.token = str(token)
        state.headers = {header: f"{scheme} {token}".strip()}
        logger.info("[auth] logged in '%s' — token captured", ident.name)
        return state

    async def _form_login_flow(self, ident: Identity) -> AuthState:
        """Classic web-app login: GET the login page, scrape a CSRF token, then
        form-POST credentials. The session cookie set by the server is captured
        and applied to the identity's session. (No JSON, no bearer token.)"""
        from .http_client import ScopedClient
        from ..utils import regex_extract

        a = ident.auth
        login_url = a.get("login_url") or a.get("path")
        if not login_url:
            raise ScopeError(f"Identity '{ident.name}' form_login needs 'login_url'.")
        if self.dry_run:
            logger.info("[auth] (dry-run) would form-login '%s' at %s", ident.name, login_url)
            return AuthState(is_login=True)

        async with ScopedClient(self.scope, self.scope.authorized_base_urls[0],
                                role=f"auth:{ident.name}", transport=self._transport) as client:
            # 1. Fetch the login page and scrape the CSRF token (if any).
            csrf = None
            csrf_field = a.get("csrf_field", "csrf")
            page = await client.request("GET", login_url, follow_redirects=True)
            if page is not None and page.status_code < 400:
                pattern = a.get("csrf_regex") or (
                    rf'name=["\']{csrf_field}["\'][^>]*value=["\']([^"\']+)["\']')
                csrf = regex_extract(page.text, pattern)

            # 2. Build the form body and POST it.
            form = {
                a.get("username_field", "username"): a.get("username", ""),
                a.get("password_field", "password"): a.get("password", ""),
            }
            if csrf:
                form[csrf_field] = csrf
            form.update(a.get("extra_fields", {}))
            resp = await client.request(a.get("method", "POST"), login_url, data=form,
                                        follow_redirects=False)
            cookies = client.cookies()

        if resp is None or resp.status_code >= 400 or not cookies:
            code = getattr(resp, "status_code", "n/a")
            raise ScopeError(
                f"Form login failed for '{ident.name}' (status {code}, "
                f"{len(cookies)} cookie(s)). Check creds/csrf_field/login_url.")
        logger.info("[auth] form-logged in '%s' — captured %d cookie(s)", ident.name, len(cookies))
        return AuthState(cookies=cookies, is_login=True, obtained_at=time.time())
