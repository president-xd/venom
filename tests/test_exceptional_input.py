"""
Proof for the exceptional-input flow (PortSwigger "Inconsistent handling of
exceptional input"): the lab stores the registration email in a fixed-width field
(truncated to N chars) but mails the confirmation to the full address. VENOM
registers a padded email that truncates to '<pad>@<company>' yet is delivered to
its own inbox subdomain, confirms, logs in as staff, reaches /admin, deletes carlos.
"""

import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.flows.exceptional_input import craft_truncation_email
from venom.testing.schema import VulnClass, Verdict

LAB = "https://lab.example.net"
MAILH = "mail.example.net"
MAIL = f"https://{MAILH}"
COMPANY = "megacorp.example"     # privileged staff domain (scraped from the register hint)
LIMIT = 255                      # storage column width the app truncates to


def craft_unit_test():
    email = craft_truncation_email(COMPANY, MAILH, LIMIT)
    assert email is not None
    assert email[:LIMIT] == "a" * (LIMIT - len("@" + COMPANY)) + "@" + COMPANY
    assert email.endswith("." + MAILH)            # deliverable to our inbox subdomain


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

        # ---- email client: shows mail delivered to the mail host or any subdomain ----
        if host == MAILH and path == "/email":
            rows = "".join(f"<tr><td>{e['to']}</td><td>"
                           f"<a href='{e['link']}'>confirm</a></td></tr>" for e in inbox)
            return page(f"<table>{rows}</table>")

        # ---- lab ----
        if path == "/register" and method == "GET":
            if request.url.params.get("token"):
                tok = request.url.params.get("token")
                for u in users.values():
                    if u["token"] == tok:
                        u["confirmed"] = True
                return page("Account confirmed")
            return page(f"Employees: register with your @{COMPANY} email."
                        "<form action=/register method=POST>"
                        "<input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=email><input name=password></form>")
        if path == "/register" and method == "POST":
            state["n"] += 1
            tok = f"tok{state['n']}"
            uname = form.get("username")
            full = form.get("email", "")
            stored = full[:LIMIT]                          # silent truncation
            staff = stored.endswith("@" + COMPANY)          # privilege gated on stored domain
            users[uname] = {"stored": stored, "password": form.get("password"),
                            "token": tok, "confirmed": False, "staff": staff}
            # Mailer uses the FULL (untruncated) address: delivered if it's our (sub)domain.
            dom = full.split("@")[-1]
            if dom == MAILH or dom.endswith("." + MAILH):
                inbox.append({"to": full, "link": f"{LAB}/register?token={tok}"})
            return page("Please check your email to confirm")

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
            return page("<p>Your account</p>")

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
                if request.url.params.get("username") == "carlos":
                    state["solved"] = True
                return page("deleted")
            return httpx.Response(401, text="nope")

        if path == "/" and method == "GET":
            banner = ("<div class='is-solved'>Congratulations, you solved the lab!</div>"
                      if state["solved"] else "")
            return page(banner + "<a href=/register>Register</a> <a href=/login>Login</a> "
                                 "<a href=/admin>Admin</a>")

        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-XIN", "target_name": "XInputShop",
        "authorized_base_urls": [LAB, MAIL],
        "email_client_url": f"{MAIL}/email",
        "privileged_email_domain": COMPANY,
        "email_truncation_limit": LIMIT,
        "objective_delete_user": "carlos",
        "allow_destructive": True,
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 30, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_craft_truncation_email():
    craft_unit_test()


def test_exceptional_input_solves_truncation(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_infra()))
    xin = [c for c in result.cases
           if c.vulnerability_class == VulnClass.PRIV_ESCALATION
           and c.verdict == Verdict.CONFIRMED_EXPLOIT and c.test_id == "XIN-001"]
    assert xin, "exceptional-input flow did not confirm admin access"
    assert any("SOLVED" in n for c in xin for n in c.notes), "objective (delete carlos) not completed"
