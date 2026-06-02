"""
Proof for the account-privilege flow (PortSwigger "flawed privilege assumption"
account-management shape): the change-password endpoint trusts a client-supplied
`username` and skips verification when `current-password` is omitted. VENOM logs
in as wiener, overwrites the administrator's password, logs in as administrator,
reaches /admin, and deletes carlos.
"""

import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

LAB = "https://lab.example.net"


def make_lab():
    users = {"wiener": {"password": "peter", "admin": False},
             "administrator": {"password": "s3cret-admin", "admin": True}}
    sessions, state = {}, {"n": 0, "solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def who(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return sessions.get(m.group(1)) if m else None

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}

        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            u = users.get(form.get("username"))
            if u and u["password"] == form.get("password"):
                state["n"] += 1
                sid = f"s{state['n']}"
                sessions[sid] = form.get("username")
                return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/",
                                                    "location": "/my-account"})
            return page("Invalid username or password")

        if path == "/my-account" and method == "GET":
            me = who(request)
            if not me:
                return httpx.Response(302, headers={"location": "/login"})
            return page(f"<p>Your username is: {me}</p>"
                        "<form action=/my-account/change-password method=POST>"
                        "<input type=hidden name=csrf value=TOK>"
                        f"<input type=hidden name=username value={me}>"
                        "<input name=current-password><input name=new-password-1>"
                        "<input name=new-password-2></form>")
        if path == "/my-account/change-password" and method == "POST":
            if not who(request):
                return httpx.Response(302, headers={"location": "/login"})
            target = users.get(form.get("username"))
            if not target:
                return page("invalid user")
            p1, p2 = form.get("new-password-1"), form.get("new-password-2")
            if p1 != p2:
                return page("New passwords do not match")
            # FLAW: current-password only checked when present; username is trusted.
            cur = form.get("current-password")
            if cur is not None and cur != target["password"]:
                return page("Current password is incorrect")
            target["password"] = p1
            return page("Password changed successfully")

        if path == "/admin" and method == "GET":
            u = users.get(who(request))
            if not (u and u["admin"]):
                return httpx.Response(401, headers={"content-type": "text/html"},
                                      text="Admin interface only available if logged in as an administrator")
            rows = "".join(f"<a href='/admin/delete?username={n}'>delete {n}</a>"
                           for n in ["wiener", "carlos"])
            return page(f"<h1>Admin</h1>{rows}")
        if path == "/admin/delete" and method == "GET":
            u = users.get(who(request))
            if u and u["admin"]:
                if request.url.params.get("username") == "carlos":
                    state["solved"] = True
                return page("deleted")
            return httpx.Response(401, text="nope")

        if path == "/" and method == "GET":
            banner = ("<div class='is-solved'>Congratulations, you solved the lab!</div>"
                      if state["solved"] else "")
            return page(banner + "<a href=/login>Login</a> <a href=/my-account>Account</a> "
                                 "<a href=/admin>Admin</a>")

        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-ACP", "target_name": "ACPShop",
        "authorized_base_urls": [LAB],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": "wiener", "password": "peter", "csrf_field": "csrf"}}],
        "privileged_account": "administrator",
        "objective_delete_user": "carlos",
        "allow_destructive": True,
        "discovery": {"enabled": True, "seeds": ["/", "/my-account"], "max_pages": 30, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_account_privilege_solves_change_password_takeover(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_lab()))
    acp = [c for c in result.cases
           if c.vulnerability_class == VulnClass.PRIV_ESCALATION
           and c.verdict == Verdict.CONFIRMED_EXPLOIT and c.test_id == "ACP-001"]
    assert acp, "account-privilege flow did not confirm admin takeover"
    assert any("SOLVED" in n for c in acp for n in c.notes), "objective (delete carlos) not completed"
