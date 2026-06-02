"""
Proof for the account-lifecycle flow (PortSwigger "Inconsistent security controls"
shape): register → confirm via a cross-host email client → log in → change email to
the company domain (trusted as staff) → reach /admin → delete the target user.
"""

import asyncio
import json
import re
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

LAB = "https://lab.example.net"
MAILH = "mail.example.net"
MAIL = f"https://{MAILH}"
COMPANY = "megacorp.example"   # staff domain (scraped from the register hint)


def make_infra():
    users, sessions, inbox, state = {}, {}, [], {"n": 0, "solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def handler(request: httpx.Request) -> httpx.Response:
        host, path, method = request.url.host, request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}

        # ---- email client (different host) ----
        if host == MAILH and path == "/email":
            rows = "".join(f"<tr><td>{e['to']}</td><td>"
                           f"<a href='{e['link']}'>confirm</a></td></tr>" for e in inbox)
            return page(f"<table>{rows}</table>")

        # ---- lab ----
        if path == "/register" and method == "GET":
            if request.url.params.get("token"):       # confirmation link
                tok = request.url.params.get("token")
                for u in users.values():
                    if u["token"] == tok:
                        u["confirmed"] = True
                return page("Account confirmed")
            return page("If you work for MegaCorp use your @megacorp.example address"
                        "<form action=/register method=POST>"
                        "<input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=email><input name=password></form>")
        if path == "/register" and method == "POST":
            state["n"] += 1
            tok = f"tok{state['n']}"
            uname = form.get("username")
            users[uname] = {"email": form.get("email"), "password": form.get("password"),
                            "token": tok, "confirmed": False, "staff": False}
            inbox.append({"to": form.get("email"),
                          "link": f"{LAB}/register?token={tok}"})
            return page("Please check your email")

        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            u = users.get(form.get("username"))
            if u and u["confirmed"] and u["password"] == form.get("password"):
                state["n"] += 1
                sid = f"s{state['n']}"
                sessions[sid] = form.get("username")
                return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/",
                                                    "location": "/my-account"})
            return page("login failed")

        if path == "/my-account" and method == "GET":
            if not who(request):
                return httpx.Response(302, headers={"location": "/login"})
            return page("<form action=/my-account/change-email method=POST>"
                        "<input type=hidden name=csrf value=TOK><input name=email></form>")
        if path == "/my-account/change-email" and method == "POST":
            u = users.get(who(request))
            if u:
                u["email"] = form.get("email", "")
                u["staff"] = u["email"].endswith("@" + COMPANY)   # inconsistent: no re-validation
            return httpx.Response(302, headers={"location": "/my-account"})

        if path == "/admin" and method == "GET":
            u = users.get(who(request))
            if not (u and u["staff"]):
                return httpx.Response(401, headers={"content-type": "text/html"}, text="admins only")
            rows = "".join(f"<a href='/admin/delete?username={n}'>delete {n}</a>"
                           for n in ["wiener", "carlos"])
            return page(f"<h1>Admin</h1>{rows}")
        if path == "/admin/delete" and method == "GET":
            u = users.get(who(request))
            if u and u["staff"]:
                victim = request.url.params.get("username")
                if victim == "carlos":
                    state["solved"] = True
                return page(f"deleted {victim}")
            return httpx.Response(401, text="nope")

        if path == "/" and method == "GET":
            banner = "<div class='is-solved'>Congratulations, you solved the lab!</div>" if state["solved"] else ""
            return page(banner + "<a href=/register>Register</a> <a href=/login>Login</a> <a href=/admin>Admin</a>")

        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-ATO", "target_name": "ATOShop",
        "authorized_base_urls": [LAB, MAIL],          # email host explicitly authorized
        "email_client_url": f"{MAIL}/email",
        "objective_delete_user": "carlos",
        "allow_destructive": True,
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_account_takeover_solves_inconsistent_controls(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_infra()))
    ato = [c for c in result.cases
           if c.vulnerability_class == VulnClass.PRIV_ESCALATION
           and c.verdict == Verdict.CONFIRMED_EXPLOIT and c.origin == "flow"]
    assert ato, "account-takeover flow did not confirm admin access"
    assert any("SOLVED" in n for c in ato for n in c.notes), "objective (delete carlos) not completed"
