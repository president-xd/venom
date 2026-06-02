"""Verify gift-card redemption increments store credit."""
import asyncio, re, sys
from venom.core.scope import Scope
from venom.engine.auth import AuthManager
from venom.engine.http_client import RateLimiter, ScopedClient

SCOPE = sys.argv[1]
CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
CREDIT = re.compile(r'Store credit:\s*\$([\d.,]+)', re.I)
def csrf(t): m = CSRF.search(t or ""); return m.group(1) if m else None
def credit(t): m = CREDIT.search(t or ""); return m.group(1) if m else None


async def main():
    scope = Scope.from_file(SCOPE)
    base = scope.authorized_base_urls[0]
    c = ScopedClient(scope, base, role="recon", limiter=RateLimiter(scope.rate_limit_per_second))
    c.apply_auth(await AuthManager(scope).ensure("wiener"))
    h = (await c.request("GET", "/", follow_redirects=True)).text
    await c.request("POST", "/sign-up", data={"csrf": csrf(h), "email": "w@x.net"}, follow_redirects=True)
    await c.request("POST", "/cart", data={"productId": "2", "redir": "PRODUCT", "quantity": "1"}, follow_redirects=True)
    ct = (await c.request("GET", "/cart", follow_redirects=True)).text
    await c.request("POST", "/cart/coupon", data={"csrf": csrf(ct), "coupon": "SIGNUP30"}, follow_redirects=True)
    ct2 = (await c.request("GET", "/cart", follow_redirects=True)).text
    cot = (await c.request("POST", "/cart/checkout", data={"csrf": csrf(ct2)}, follow_redirects=True)).text
    i = cot.lower().find("gift cards")
    region = cot[i:] if i >= 0 else cot
    code = re.findall(r'<td>([A-Za-z0-9]{8,})</td>', region)[0]
    acct_before = (await c.request("GET", "/my-account", follow_redirects=True)).text
    print("credit before redeem:", credit(acct_before), "code:", code)
    await c.request("POST", "/gift-card", data={"csrf": csrf(acct_before), "gift-card": code}, follow_redirects=True)
    acct_after = (await c.request("GET", "/my-account", follow_redirects=True)).text
    print("credit after redeem :", credit(acct_after))
    await c.aclose()

asyncio.run(main())
