"""
Proof for the integer-overflow flow (PortSwigger "Low-level logic flaw"): the
cart total is a signed 32-bit int in cents; adding items in bulk overflows it,
and VENOM lands the final total within store credit with the jacket in the cart.
The mock rejects negative quantity (min=0, like the real lab) so the cheaper
flows can't shortcut it — the overflow flow is the only thing that solves it.
"""

import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

BASE = "https://ovf.example.net"
PRICES = {"1": 133700, "2": 7115, "3": 1423, "20": 534}   # jacket + cheaper items (cents)
CREDIT = 10000
M, SMAX = 2 ** 32, 2 ** 31


def signed(x):
    x %= M
    return x - M if x >= SMAX else x


def make_shop():
    sessions, carts, state = {}, {}, {"n": 0, "solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def total_cents(user):
        return sum(PRICES.get(pid, 0) * qty for pid, qty in carts.get(user, []))

    def handler(request):
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}
        user = who(request)

        if path == "/" and method == "GET":
            banner = "<div class='is-solved'>Congratulations, you solved the lab!</div>" if state["solved"] else ""
            links = " ".join(f'<a href="/product?productId={i}">P{i}</a>' for i in PRICES)
            return page(banner + f'<a href=/login>Login</a> <a href=/my-account>Account</a> '
                        f'<a href=/cart>Cart</a> {links}')
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
            pid = request.url.params.get("productId", "1")
            return page(f"Product ${PRICES.get(pid, 0)/100:.2f} <form action=/cart method=POST>"
                        f"<input type=hidden name=productId value={pid}>"
                        f"<input type=hidden name=redir value=PRODUCT>"
                        f"<input type=number min=0 max=99 name=quantity value=1></form>")
        if path == "/cart" and method == "POST":
            pid = form.get("productId", "1")
            try:
                qty = int(form.get("quantity", "1"))
            except ValueError:
                qty = 1
            if 0 <= qty <= 99:                       # server enforces bounds (no negatives)
                carts.setdefault(user, []).append((pid, qty))
            return httpx.Response(302, headers={"location": "/cart"})
        if path == "/cart" and method == "GET":
            t = signed(total_cents(user))
            return page(f"Total: ${t/100:.2f} <form action=/cart/checkout method=POST>"
                        "<input type=hidden name=csrf value=CK></form>")
        if path == "/cart/checkout" and method == "POST":
            t = signed(total_cents(user))
            has_jacket = any(pid == "1" and qty >= 1 for pid, qty in carts.get(user, []))
            if 0 < t <= CREDIT and has_jacket:
                state["solved"] = True
                return page("Order placed! Thank you.")
            return page(f"Cannot place order (total {t}).")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-OVF", "target_name": "OvfShop",
        "authorized_base_urls": [BASE],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "username_field": "username",
            "password_field": "password", "username": "wiener", "password": "pw", "csrf_field": "csrf"}}],
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": False},
        "rate_limit_per_second": 5000,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_integer_overflow_solves(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_shop()))
    ovf = [c for c in result.cases
           if c.test_id.startswith("OVF") and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert ovf, "integer-overflow flow did not confirm"
    assert any("SOLVED" in n for c in ovf for n in c.notes)
