"""
Recon enrichment — turn a bare endpoint registry into a senior-tester's situational
picture, as the *current* (authenticated) user:

  - probe each discovered endpoint and record its baseline status + a text snippet,
  - classify every action as ACCESSIBLE-to-you vs DENIED-to-you (the "forbidden map").

For business-logic hunting the denied map is the gold: the objective is almost
always "perform an action you are currently NOT allowed to perform." Handing the
agent an explicit list of what it can and cannot do — instead of a flat endpoint
list — is what lets a model reason about *how to bridge that gap*.

State-changing endpoints are probed with an EMPTY/benign body so the server's
authorization gate fires before any effect — we read the gate, we don't trip it.
"""

from __future__ import annotations

import logging

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..llm.budget import compact_html

logger = logging.getLogger("venom.ingest.recon")

_DENY_STATUS = {401, 403}


def _is_login_redirect(resp) -> bool:
    if getattr(resp, "status_code", None) not in (301, 302, 303, 307, 308):
        return False
    loc = (dict(getattr(resp, "headers", {}) or {}).get("location") or "").lower()
    return "login" in loc or "signin" in loc or "auth" in loc


async def enrich_recon(scope: Scope, registry, *, transport=None, max_probes: int = 24) -> dict:
    """Probe the discovered surface as the current user; return a structured brief
    enrichment: per-endpoint baseline, plus accessible/denied action maps."""
    base = scope.authorized_base_urls[0]
    limiter = RateLimiter(scope.rate_limit_per_second)
    try:
        c = ScopedClient(scope, base, role="recon-enrich", limiter=limiter, transport=transport)
    except ValueError:
        return {}
    identity = scope.identities[0]["name"] if scope.identities else None
    if identity:
        try:
            c.apply_auth(await AuthManager(scope, transport=transport).ensure(identity))
        except Exception as exc:  # noqa: BLE001
            logger.info("recon enrichment unauthenticated (%s)", exc)

    probed: list[dict] = []
    accessible: list[str] = []
    denied: list[str] = []
    seen: set[tuple[str, str]] = set()
    try:
        for e in registry.by_risk()[:max_probes]:
            method = e.method.upper()
            key = (method, e.path)
            if key in seen:
                continue
            seen.add(key)
            try:
                if method == "GET":
                    resp = await c.request("GET", e.path, follow_redirects=False)
                else:
                    # empty body: the authz gate answers before any state change
                    resp = await c.request(method, e.path, data={}, follow_redirects=False)
            except ScopeError:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.debug("probe %s %s failed: %s", method, e.path, exc)
                continue
            status = getattr(resp, "status_code", None)
            snippet = compact_html(resp.text if resp is not None else "").get("text", "")[:140]
            entry = {"method": method, "path": e.path, "status": status}
            if snippet:
                entry["snippet"] = snippet
            probed.append(entry)
            label = f"{method} {e.path}"
            if status in _DENY_STATUS or _is_login_redirect(resp):
                denied.append(label)
            elif status is not None and 200 <= status < 400:
                accessible.append(label)
        return {"probed": probed,
                "accessible_to_you": sorted(set(accessible)),
                "denied_to_you": sorted(set(denied)),
                "authenticated_as": identity}
    finally:
        await c.aclose()
