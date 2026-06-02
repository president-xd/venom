"""Recon the purchasing workflow: prices in add-to-cart? coupon codes? store credit?"""
import asyncio, re, sys
from venom.core.scope import Scope
from venom.engine.auth import AuthManager
from venom.engine.http_client import RateLimiter, ScopedClient

SCOPE = sys.argv[1]
CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')


def snip(t, n=240):
    return re.sub(r"\s+", " ", t or "")[:n]


def forms(html):
    for f in re.finditer(r"<form[^>]*>(.*?)</form>", html or "", re.S | re.I):
        b = f.group(0)
        a = (re.search(r'action=["\']?([^"\' >]+)', b) or [None, "(self)"])[1]
        m = (re.search(r'method=["\']?([^"\' >]+)', b) or [None, "GET"])[1]
        n = re.findall(r'name=["\']?([^"\' >]+)', b)
        print(f"  FORM {m.upper()} {a} fields={n}")


async def main():
    scope = Scope.from_file(SCOPE)
    base = scope.authorized_base_urls[0]
    c = ScopedClient(scope, base, role="recon", limiter=RateLimiter(scope.rate_limit_per_second))
    c.apply_auth(await AuthManager(scope).ensure("wiener"))

    home = await c.request("GET", "/", follow_redirects=True)
    h = home.text if home else ""
    print("=== HOME hints ===")
    for kw in ("coupon", "code", "NEWCUSTOMER", "SIGNUP", "discount", "newsletter", "%"):
        for m in re.finditer(rf'.{{0,30}}{kw}.{{0,40}}', h, re.I):
            print(f"  ~{kw}: {m.group(0).strip()[:80]}"); break
    print("store credit:", (re.search(r'store credit[^<]{0,30}', h, re.I) or [None,"?"])[0] if h else "?")

    acct = await c.request("GET", "/my-account", follow_redirects=True)
    print("=== /my-account ===", snip(acct.text if acct else "", 120))
    forms(acct.text if acct else "")

    p1 = await c.request("GET", "/product?productId=1", follow_redirects=True)
    print("=== product page form ===")
    forms(p1.text if p1 else "")

    # add item, view cart + coupon form
    await c.request("POST", "/cart", data={"productId": "1", "redir": "PRODUCT", "quantity": "1"},
                    follow_redirects=True)
    cart = await c.request("GET", "/cart", follow_redirects=True)
    print("=== /cart ===")
    forms(cart.text if cart else "")
    print("cart text:", snip(cart.text if cart else "", 300))
    await c.aclose()

asyncio.run(main())
