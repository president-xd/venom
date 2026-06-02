"""
Proof for the coupon-stacking flow (PortSwigger "Flawed enforcement of business
rules"): two discount codes (one revealed by newsletter sign-up) can be stacked
by ALTERNATING them, dropping the jacket's price within store credit.
"""

import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

LAB = "https://coupon.example.net"
JACKET, CREDIT = 133700, 10000   # pence


def make_shop():
    sessions, state = {}, {"n": 0, "solved": False}
    carts = {}   # user -> {"total":int,"last":str|None,"jacket":bool}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def handler(request):
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}
        user = who(request)

        if path == "/" and method == "GET":
            banner = "<div class='is-solved'>Congratulations, you solved the lab!</div>" if state["solved"] else ""
            return page(banner + "New customers use code at checkout: NEWCUST5 "
                        "<a href=/product?productId=1>jacket</a> <a href=/cart>cart</a> "
                        "<form action=/sign-up method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=email></form>")
        if path == "/sign-up" and method == "POST":
            return page("Thanks! Use SIGNUP30 for 30% off.")
        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            state["n"] += 1
            sid = f"s{state['n']}"
            sessions[sid] = form.get("username", "u")
            return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/"})
        if path == "/my-account" and method == "GET":
            return page("Store credit: $100.00")
        if path == "/product" and method == "GET":
            return page("Jacket $1337.00 <form action=/cart method=POST>"
                        "<input type=hidden name=productId value=1><input type=hidden name=redir value=PRODUCT>"
                        "<input type=number name=quantity value=1></form>")
        if path == "/cart" and method == "POST":
            carts[user] = {"total": JACKET, "last": None, "jacket": True}
            return httpx.Response(302, headers={"location": "/cart"})
        if path == "/cart" and method == "GET":
            cart = carts.get(user, {"total": 0})
            return page(f"Total: ${cart['total']/100:.2f} "
                        "<form action=/cart/coupon method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=coupon></form>"
                        "<form action=/cart/checkout method=POST><input type=hidden name=csrf value=TOK></form>")
        if path == "/cart/coupon" and method == "POST":
            cart = carts.get(user)
            code = form.get("coupon")
            if cart and code and code != cart["last"]:        # flaw: only blocks consecutive repeats
                if code == "SIGNUP30":
                    cart["total"] = int(cart["total"] * 0.7)
                elif code == "NEWCUST5":
                    cart["total"] = max(0, cart["total"] - 500)
                cart["last"] = code
            return httpx.Response(302, headers={"location": "/cart"})
        if path == "/cart/checkout" and method == "POST":
            cart = carts.get(user)
            if cart and cart["jacket"] and 0 < cart["total"] <= CREDIT:
                state["solved"] = True
                return page("Order placed! Thank you.")
            return page("Insufficient funds.")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-CPN", "target_name": "CouponShop",
        "authorized_base_urls": [LAB],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "username_field": "username",
            "password_field": "password", "username": "wiener", "password": "peter", "csrf_field": "csrf"}}],
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_coupon_stacking_solves(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_shop()))
    cpn = [c for c in result.cases
           if c.vulnerability_class == VulnClass.ECONOMIC_ABUSE
           and c.verdict == Verdict.CONFIRMED_EXPLOIT and c.origin == "flow"]
    assert cpn, "coupon-stacking flow did not confirm"
    assert any("SOLVED" in n for c in cpn for n in c.notes)
