"""
Proof for the multi-item cart-balancing tactic (PortSwigger "High-level logic
vulnerability" shape): the cart trusts a client `quantity` (NO client price), so
the expensive jacket is bought by offsetting the total with a large NEGATIVE
quantity of a cheap product, landing the order total within store credit.
"""

import asyncio
import json
import re
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

BASE = "https://hlshop.example.net"
PRICES = {"1": 133700, "2": 1000, "3": 3000}   # jacket + two cheap items (pence)
CREDIT = 10000                                  # £100.00


def make_shop():
    sessions, carts, state = {}, {}, {"n": 0, "solved": False}

    def page(title, body):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><head><title>{title}</title></head><body>{body}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}
        user = who(request)

        if path == "/" and method == "GET":
            banner = ("<div class='widgetcontainer-lab-status is-solved'>Congratulations, "
                      "you solved the lab!</div>" if state["solved"] else "")
            links = " ".join(f'<a href="/product?productId={i}">P{i}</a>' for i in PRICES)
            return page("High-level logic vulnerability",
                        banner + f'<a href="/login">Login</a> <a href="/my-account">Account</a> '
                        f'<a href="/cart">Cart</a> {links}')

        if path == "/login" and method == "GET":
            return page("Login", '<form action="/login" method="POST">'
                                  '<input type="hidden" name="csrf" value="TOK">'
                                  '<input name="username"><input name="password" type="password"></form>')
        if path == "/login" and method == "POST":
            if form.get("csrf") != "TOK":
                return httpx.Response(400, text="bad csrf")
            state["n"] += 1
            sid = f"s{state['n']}"
            sessions[sid] = form.get("username", "anon")
            return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/"})

        if path == "/my-account" and method == "GET":
            return page("Account", "<div>Store credit: $100.00</div>")

        if path == "/product" and method == "GET":
            pid = request.url.params.get("productId", "1")
            price = PRICES.get(pid, 0)
            # NOTE: no client-side price field — only quantity (the logic flaw).
            return page("Product", f'<h2>Product {pid} — ${price/100:.2f}</h2>'
                                   f'<form action="/cart" method="POST">'
                                   f'<input type="hidden" name="productId" value="{pid}">'
                                   f'<input type="hidden" name="redir" value="PRODUCT">'
                                   f'<input type="number" name="quantity" value="1"></form>')

        if path == "/cart" and method == "POST":
            pid = form.get("productId", "1")
            try:
                qty = int(form.get("quantity", "1"))            # server trusts client quantity (incl. negative)
            except ValueError:
                qty = 1
            carts.setdefault(user, []).append((pid, qty))
            return httpx.Response(302, headers={"location": "/cart"})

        if path == "/cart" and method == "GET":
            total = sum(PRICES.get(pid, 0) * qty for pid, qty in carts.get(user, []))
            return page("Cart", f'<div>Total: ${total/100:.2f}</div>'
                                f'<form action="/cart/checkout" method="POST">'
                                f'<input type="hidden" name="csrf" value="CK"></form>')

        if path == "/cart/checkout" and method == "POST":
            if form.get("csrf") != "CK":
                return httpx.Response(400, text="missing csrf")
            total = sum(PRICES.get(pid, 0) * qty for pid, qty in carts.get(user, []))
            has_jacket = any(pid == "1" and qty >= 1 for pid, qty in carts.get(user, []))
            if 0 < total <= CREDIT and has_jacket:              # affordable AND jacket bought
                state["solved"] = True
                carts[user] = []
                return page("Order", "<div>Order placed. Thank you!</div>")
            return page("Order", f"<div>Cannot place order (total ${total/100:.2f}).</div>")

        return httpx.Response(404, headers={"content-type": "text/html"}, text="not found")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-HL", "target_name": "HLShop",
        "authorized_base_urls": [BASE],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "username_field": "username",
            "password_field": "password", "username": "wiener", "password": "pw", "csrf_field": "csrf"}}],
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 40, "forced_browse": False},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_cart_balancing_solves_high_level_logic(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_shop()))
    # Prices + credit were captured during discovery.
    assert result.registry.catalog.get("1") == 133700
    assert result.registry.store_credit == 10000
    # The cart-balancing chain confirmed the exploit (jacket bought within credit).
    confirmed = [c for c in result.cases
                 if c.vulnerability_class == VulnClass.PARAM_POLLUTION
                 and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert confirmed, "cart-balancing did not confirm"
