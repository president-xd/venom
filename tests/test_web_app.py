"""
End-to-end proof for WEB-APP mode (HTML/form/cookie targets — like a PortSwigger
Web Security Academy lab, NOT a JSON API).

An in-memory vulnerable HTML shop is served via httpx.MockTransport. VENOM must:
  1. form-login with a CSRF token + session cookie,
  2. DISCOVER the surface by crawling (no artifacts handed in),
  3. confirm three classic web business-logic flaws from HTML:
       - client-side price tampering, web IDOR, broken access control.
"""

import asyncio
import json
import re
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

BASE = "https://shop.example.net"


def make_vulnerable_shop():
    sessions = {}            # cookie -> username
    carts = {}               # username -> list of submitted prices (pence)
    state = {"n": 0, "solved": False}
    CREDIT = 10000           # £100.00 store credit, in pence
    JACKET = 133700          # £1337.00

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
            acct = f'/my-account?id={user}' if user else '/my-account'
            banner = ("<div class='widgetcontainer-lab-status is-solved'>"
                      "Congratulations, you solved the lab!</div>" if state["solved"] else "")
            return page("Home", banner + f'<a href="/login">Login</a> <a href="{acct}">Account</a> '
                                '<a href="/product?id=1">Product</a> <a href="/admin">Admin</a> '
                                '<a href="/cart">Cart</a>')

        if path == "/login" and method == "GET":
            return page("Login", '<form action="/login" method="POST">'
                                  '<input type="hidden" name="csrf" value="TOKEN123">'
                                  '<input name="username"><input name="password" type="password"></form>')
        if path == "/login" and method == "POST":
            if form.get("csrf") != "TOKEN123":
                return httpx.Response(400, text="bad csrf")
            state["n"] += 1
            sid = f"sess{state['n']}"
            sessions[sid] = form.get("username", "anon")
            return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/"})

        # IDOR: ?id lets you view ANY user's account; no ownership check.
        if path == "/my-account" and method == "GET":
            target = request.url.params.get("id") or user or "guest"
            return page("Account", f'<div>Account page for <b>{target}</b>, {target}@example.net</div>')

        # Product page exposes the add-to-cart form WITH a client-side price (no CSRF).
        if path == "/product" and method == "GET":
            return page("Product", f'<h1>Lightweight l33t Leather Jacket — £1337</h1>'
                                   f'<form id=addToCartForm action="/cart" method="POST">'
                                   f'<input type="hidden" name="productId" value="1">'
                                   f'<input type="hidden" name="redir" value="PRODUCT">'
                                   f'<input type="hidden" name="price" value="{JACKET}">'
                                   f'<input type="number" name="quantity" value="1"></form>')

        # Client-side trust: the server stores whatever price the client submitted.
        if path == "/cart" and method == "POST":
            carts.setdefault(user, []).append(int(form.get("price", JACKET)))
            return httpx.Response(302, headers={"location": "/cart"})

        if path == "/cart" and method == "GET":
            total = sum(carts.get(user, []))
            return page("Cart", f'<div>Cart total: £{total/100:.2f}</div>'
                                f'<form action="/cart/checkout" method="POST">'
                                f'<input type="hidden" name="csrf" value="CKTOKEN"></form>')

        if path == "/cart/checkout" and method == "POST":
            if form.get("csrf") != "CKTOKEN":
                return httpx.Response(400, text="missing csrf")
            total = sum(carts.get(user, []))
            if total <= CREDIT:                       # tampered price slips under store credit
                state["solved"] = True
                carts[user] = []
                return page("Order", "<div>Order placed. Thank you for your purchase!</div>")
            return page("Order", "<div>Insufficient store credit.</div>")

        # Broken access control: /admin served to ANY logged-in user.
        if path == "/admin" and method == "GET":
            if not user:
                return httpx.Response(302, headers={"location": "/login"})
            return page("Admin", '<h1>Admin Panel</h1><ul><li>Delete user</li>'
                                 '<li>Manage all users</li></ul>')

        return httpx.Response(404, headers={"content-type": "text/html"}, text="not found")

    return httpx.MockTransport(handler)


def _scope() -> dict:
    def ident(name):
        return {"name": name, "role": "user", "auth": {
            "type": "form_login", "login_url": "/login",
            "username_field": "username", "password_field": "password",
            "username": name, "password": "pw", "csrf_field": "csrf"}}
    return {
        "engagement_id": "ENG-WEB-TEST",
        "target_name": "VulnShop",
        "authorized_base_urls": [BASE],
        "identities": [ident("wiener"), ident("carlos")],
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z",
        "expiry_date": "2030-01-01T00:00:00Z",
    }


def _run(tmp_path: Path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    return asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json",
        artifact_paths=[],          # NO artifacts — discovery must find the surface
        out_dir=tmp_path / "out",
        dry_run=False, use_llm=False,
        transport=make_vulnerable_shop(),
    ))


def _confirmed(result, vclass):
    return [c for c in result.cases
            if c.vulnerability_class == vclass and c.verdict == Verdict.CONFIRMED_EXPLOIT]


def test_discovery_finds_surface_without_artifacts(tmp_path):
    result = _run(tmp_path)
    keys = {e.key for e in result.registry}
    assert any("/login" in k for k in keys)
    assert any("/cart" in k for k in keys)     # discovered the purchase form
    assert any("/admin" in k for k in keys)    # forced-browse found the admin page


def test_confirms_price_tampering(tmp_path):
    assert _confirmed(_run(tmp_path), VulnClass.PARAM_POLLUTION)


def test_confirms_web_idor(tmp_path):
    assert _confirmed(_run(tmp_path), VulnClass.BOLA_IDOR)


def test_confirms_broken_access_control(tmp_path):
    assert _confirmed(_run(tmp_path), VulnClass.PRIV_ESCALATION)


def test_web_findings_reported(tmp_path):
    result = _run(tmp_path)
    confirmed = [c for c in result.cases if c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert len(confirmed) >= 3
    sarif = json.loads((result.artifacts["sarif"]).read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"]
