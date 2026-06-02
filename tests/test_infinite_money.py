"""
Proof for the infinite-money flow (PortSwigger "Infinite money logic flaw"): a
reusable coupon makes a $10 gift card cost $7, but redeeming returns $10 store
credit (+$3/card). VENOM grows credit until it can buy the jacket, then buys it.
"""

import asyncio
import json
import re
import secrets
from urllib.parse import parse_qs

import httpx

from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry
from venom.engine.auth import AuthManager
from venom.ingest.crawler import crawl
from venom.flows import infinite_money
from venom.testing.schema import VulnClass, Verdict

BASE = "https://money.example.net"
PRICES = {"1": 133700, "2": 1000, "3": 89900}    # jacket + gift card ($10) + unaffordable other
START_CREDIT = 10000                              # only the gift-card arbitrage can reach the jacket
COUPON = "SIGNUP30"


def make_shop():
    sessions, carts, coupons, credit = {}, {}, {}, {}
    cards, state = {}, {"n": 0, "solved": False, "signed": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def credit_html(user):
        return f"<p><strong>Store credit: ${credit.get(user,0)/100:.2f}</strong></p>"

    def handler(request):
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}
        user = who(request)

        if path == "/" and method == "GET":
            banner = "<div class='is-solved'>solved the lab!</div>" if state["solved"] else ""
            alert = ("<script>alert('Use coupon SIGNUP30 at checkout!')</script>"
                     if state["signed"] else "")
            links = " ".join(f'<a href="/product?productId={i}">P{i}</a>' for i in PRICES)
            return page(banner + alert + "<form action=/sign-up method=POST>"
                        "<input type=hidden name=csrf value=TOK><input name=email></form>" + links)
        if path == "/sign-up" and method == "POST":
            state["signed"] = True
            return page("Thanks for signing up! <script>alert('Use coupon SIGNUP30 at checkout!')</script>")
        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            state["n"] += 1
            sid = f"s{state['n']}"
            u = form.get("username", "u")
            sessions[sid] = u
            credit.setdefault(u, START_CREDIT)
            return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/"})
        if path == "/my-account" and method == "GET":
            return page("<form action=/gift-card method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=gift-card></form>" + credit_html(user))
        if path == "/product" and method == "GET":
            pid = request.url.params.get("productId", "1")
            name = "Gift Card" if pid == "2" else f"Product {pid}"
            return page(f"<h3>{name}</h3><div id=price>${PRICES.get(pid,0)/100:.2f}</div>"
                        f"<form action=/cart method=POST><input type=hidden name=productId value={pid}>"
                        f"<input type=hidden name=redir value=PRODUCT>"
                        f"<input type=number name=quantity value=1></form>")
        if path == "/cart" and method == "POST":
            try:
                q = int(form.get("quantity", "1") or 1)
            except ValueError:
                q = 1
            if q >= 1:                                       # reject non-positive (no negative-qty shortcut)
                carts.setdefault(user, []).append((form.get("productId"), q))
            return httpx.Response(302, headers={"location": "/cart"})
        if path == "/cart/coupon" and method == "POST":
            if form.get("coupon") == COUPON:
                coupons[user] = True
            return httpx.Response(302, headers={"location": "/cart"})
        if path == "/cart" and method == "GET":
            total = sum(PRICES.get(p, 0) * q for p, q in carts.get(user, []))
            if coupons.get(user):
                total = int(total * 0.7)
            return page(f"<table><tr><th>Total:</th></tr><tr><th>${total/100:.2f}</th></tr></table>"
                        "<form action=/cart/coupon method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=coupon></form>"
                        "<form action=/cart/checkout method=POST><input type=hidden name=csrf value=TOK></form>")
        if path == "/cart/checkout" and method == "POST":
            items = carts.get(user, [])
            total = sum(PRICES.get(p, 0) * q for p, q in items)
            if coupons.get(user):
                total = int(total * 0.7)
            if credit.get(user, 0) < total:
                return httpx.Response(303, headers={"location": "/cart?err=INSUFFICIENT_FUNDS"})
            credit[user] -= total
            issued = []
            bought_jacket = False
            for p, q in items:
                if p == "2":                                   # gift card → issue codes
                    for _ in range(q):
                        code = secrets.token_hex(5)
                        cards[code] = ("unused", user)
                        issued.append(code)
                if p == "1":
                    bought_jacket = True
            carts[user] = []
            coupons.pop(user, None)
            if bought_jacket:
                state["solved"] = True
            rows = "".join(f"<tr><td>{code}</td></tr>" for code in issued)
            body = (("<p><strong>You have bought the following gift cards:</strong></p>"
                     f"<table><tr><th>Code</th></tr>{rows}</table>") if issued else "Order placed")
            return page(body + credit_html(user))
        if path == "/gift-card" and method == "POST":
            code = form.get("gift-card")
            entry = cards.get(code)
            if entry and entry[0] == "unused" and entry[1] == user:
                cards[code] = ("used", user)
                credit[user] += 1000                            # face value $10
            return httpx.Response(302, headers={"location": "/my-account"})
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-MNY", "target_name": "MoneyShop",
        "authorized_base_urls": [BASE],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "username_field": "username",
            "password_field": "password", "username": "wiener", "password": "pw", "csrf_field": "csrf"}}],
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": False},
        "allow_destructive": True,
        "rate_limit_per_second": 5000,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_infinite_money_solves():
    """Drive the flow directly: crawl to build the catalog, then run infinite_money.
    (The full pipeline's other flows share and drain the same store credit, so the
    flow is exercised in isolation here — exactly as it runs as the purchase fallback.)"""
    transport = make_shop()
    scope = Scope.from_dict(_scope())

    async def go():
        registry = EndpointRegistry()
        auth = await AuthManager(scope, transport=transport).ensure("wiener")
        await crawl(scope, registry, seeds=["/"], auth_state=auth, transport=transport,
                    max_pages=30, forced_browse=False)
        return await infinite_money(scope, registry, transport=transport)

    cases = asyncio.run(go())
    mny = [c for c in cases
           if c.test_id == "MNY-001" and c.vulnerability_class == VulnClass.ECONOMIC_ABUSE
           and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert mny, "infinite-money flow did not confirm"
    assert any("SOLVED" in n for c in mny for n in c.notes)
