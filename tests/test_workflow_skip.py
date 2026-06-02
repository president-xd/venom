"""
Proof for the workflow-skip flow (PortSwigger "insufficient workflow validation"):
the order-confirmation endpoint finalizes the cart on its own when called with
?order-confirmed=true, so VENOM adds the unaffordable jacket and jumps straight
to confirmation, skipping the payment/funds check.
"""

import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

BASE = "https://wf.example.net"
PRICES = {"1": 133700, "2": 119900, "3": 109900}   # jacket (id 1) + others, all unaffordable
CREDIT = 10000                                       # store credit < every item: only the skip works


def make_shop():
    sessions, carts, state = {}, {}, {"n": 0, "solved": False}

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
            banner = ("<div class='is-solved'>Congratulations, you solved the lab!</div>"
                      if state["solved"] else "")
            links = " ".join(f'<a href="/product?productId={i}">P{i}</a>' for i in PRICES)
            return page(banner + f"<a href=/login>Login</a> <a href=/cart>Cart</a> {links}")
        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            state["n"] += 1
            sid = f"s{state['n']}"
            sessions[sid] = form.get("username", "u")
            return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/"})
        if path == "/product" and method == "GET":
            pid = request.url.params.get("productId", "1")
            return page(f"Lightweight l33t leather jacket ${PRICES.get(pid, 0)/100:.2f} "
                        f"<form action=/cart method=POST>"
                        f"<input type=hidden name=productId value={pid}>"
                        f"<input type=hidden name=redir value=PRODUCT>"
                        f"<input type=number name=quantity value=1></form>")
        if path == "/cart" and method == "POST":
            carts.setdefault(user, []).append((form.get("productId", "1"),
                                               int(form.get("quantity", "1") or 1)))
            return httpx.Response(302, headers={"location": "/cart"})
        if path == "/cart" and method == "GET":
            total = sum(PRICES.get(p, 0) * q for p, q in carts.get(user, []))
            return page(f"Total: ${total/100:.2f} <form action=/cart/checkout method=POST>"
                        "<input type=hidden name=csrf value=CK></form>")
        if path == "/cart/checkout" and method == "POST":
            total = sum(PRICES.get(p, 0) * q for p, q in carts.get(user, []))
            if total > CREDIT:                       # can't afford → normal path blocks
                return httpx.Response(303, headers={"location": "/cart?err=INSUFFICIENT_FUNDS"})
            return httpx.Response(303, headers={"location": "/cart/order-confirmation?order-confirmed=true"})
        if path == "/cart/order-confirmation" and method == "GET":
            if request.url.params.get("order-confirmed") != "true":
                return httpx.Response(400, text="You have not checked out")
            # FLAW: finalizes whatever is in the cart with no payment check.
            if any(p == "1" for p, _ in carts.get(user, [])):
                state["solved"] = True
            return page("Order placed! Thank you for your purchase.")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-WFS", "target_name": "WFShop",
        "authorized_base_urls": [BASE],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "username_field": "username",
            "password_field": "password", "username": "wiener", "password": "pw", "csrf_field": "csrf"}}],
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": False},
        "allow_destructive": True,
        "rate_limit_per_second": 5000,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_workflow_skip_solves(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_shop()))
    wfs = [c for c in result.cases
           if c.test_id == "WFS-001" and c.vulnerability_class == VulnClass.SEQUENCE_VIOLATION
           and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert wfs, "workflow-skip flow did not confirm"
    assert any("SOLVED" in n for c in wfs for n in c.notes)
