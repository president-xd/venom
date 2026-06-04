"""
Proof for the email-parser flow (PortSwigger "email address parsing
discrepancies" / Splitting the email atom): the validator reads the literal
domain (@company) while the mailer decodes a UTF-7 encoded-word and delivers to
the attacker's inbox. VENOM registers a privileged-domain account it controls,
confirms, logs in, reaches /admin, and deletes carlos.
"""

import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

LAB = "https://lab.example.net"
MAILH = "mail.example.net"
MAIL = f"https://{MAILH}"
COMPANY = "ginandjuice.shop"


def _decode_utf7_word(email: str):
    """Minimal mailer: decode =?utf-7?q?...?= local part (&AEA-=@, &ACA-=space),
    re-parse, and return the delivery address (local@domain before any space)."""
    m = re.match(r"=\?utf-7\?q\?(.*?)\?=@(.+)$", email)
    if not m:
        return email   # mailer uses literal address
    decoded = m.group(1).replace("&AEA-", "@").replace("&ACA-", " ").replace("&AAo-", "\n")
    full = f"{decoded}@{m.group(2)}"
    return full.split(" ")[0].split("\n")[0]   # delivery stops at the first space/newline


def _validator_domain(email: str):
    """Validator reads the literal domain after the last '@' (no decoding)."""
    return email.rsplit("@", 1)[-1] if "@" in email else ""


def make_infra():
    users, sessions, inbox, state = {}, {}, [], {"n": 0, "solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{b}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def handler(request: httpx.Request) -> httpx.Response:
        host, path, method = request.url.host, request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}

        if host == MAILH and path == "/email":
            rows = "".join(f"<tr><td>{e['to']}</td><td><a href='{e['link']}'>confirm</a></td></tr>" for e in inbox)
            return page(f"<table>{rows}</table>")

        if path == "/register" and method == "GET":
            if request.url.params.get("token"):
                tok = request.url.params.get("token")
                for u in users.values():
                    if u["token"] == tok:
                        u["confirmed"] = True
                return page("Account confirmed")
            return page(f"If you work for GinAndJuice, please use your @{COMPANY} email address."
                        "<form action=/register method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=email><input name=password></form>")
        if path == "/register" and method == "POST":
            email = form.get("email", "")
            if _validator_domain(email) != COMPANY:
                return page("Only emails with the ginandjuice.shop domain are allowed")
            delivery = _decode_utf7_word(email)
            state["n"] += 1
            tok = f"tok{state['n']}"
            users[form.get("username")] = {"password": form.get("password"), "token": tok,
                                           "confirmed": False, "domain": COMPANY}
            dom = delivery.split("@")[-1]
            if dom == MAILH or dom.endswith("." + MAILH):    # delivered to our inbox
                inbox.append({"to": delivery, "link": f"{LAB}/register?token={tok}"})
            return page("Please check your emails for your account registration link")

        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            u = users.get(form.get("username"))
            if u and u["confirmed"] and u["password"] == form.get("password"):
                state["n"] += 1
                sid = f"s{state['n']}"
                sessions[sid] = form.get("username")
                return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/my-account"})
            return page("login failed")

        if path == "/admin" and method == "GET":
            u = users.get(who(request))
            if not (u and u["domain"] == COMPANY):        # company-domain accounts are staff
                return httpx.Response(401, headers={"content-type": "text/html"}, text="admins only")
            rows = "".join(f"<a href='/admin/delete?username={n}'>delete {n}</a>" for n in ["wiener", "carlos"])
            return page(f"<h1>Admin</h1>{rows}")
        if path == "/admin/delete" and method == "GET":
            u = users.get(who(request))
            if u and u["domain"] == COMPANY:
                if request.url.params.get("username") == "carlos":
                    state["solved"] = True
                return page("deleted")
            return httpx.Response(401, text="nope")

        if path == "/my-account" and method == "GET":
            return httpx.Response(302, headers={"location": "/login"}) if not who(request) else page("acct")
        if path == "/" and method == "GET":
            banner = "<div class='is-solved'>solved the lab!</div>" if state["solved"] else ""
            return page(banner + "<a href=/register>Register</a> <a href=/login>Login</a> <a href=/admin>Admin</a>")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-EMP", "target_name": "EmpShop",
        "authorized_base_urls": [LAB, MAIL],
        "email_client_url": f"{MAIL}/email",
        "privileged_email_domain": COMPANY,
        "objective_delete_user": "carlos",
        "allow_destructive": True,
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 25, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_email_parser_solves(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_infra()))
    emp = [c for c in result.cases
           if c.test_id == "EMP-001" and c.vulnerability_class == VulnClass.PRIV_ESCALATION
           and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert emp, "email-parser flow did not confirm admin access"
    assert any("SOLVED" in n for c in emp for n in c.notes), "objective (delete carlos) not completed"
