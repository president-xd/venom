"""
Proof for the login-state-machine flow (PortSwigger "Authentication bypass via
flawed state machine"): the session's default role after login step 1 is admin;
visiting the role-selector downgrades it. VENOM logs in and goes straight to
/admin (skipping role selection), then deletes carlos.
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
    # session -> {"role": ...}; default role after step 1 is "admin" until role-selector runs.
    sessions, state = {}, {"n": 0, "solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def sess(req):
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        return m.group(1) if m and m.group(1) in sessions else None

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}

        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            if form.get("username") == "wiener" and form.get("password") == "peter":
                state["n"] += 1
                sid = f"s{state['n']}"
                sessions[sid] = {"role": "admin"}          # FLAW: privileged default before step 2
                return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/",
                                                    "location": "/role-selector"})
            return page("Invalid")
        if path == "/role-selector":
            sid = sess(request)
            if method == "GET":
                return page("<form action=/role-selector method=POST>"
                            "<input type=hidden name=csrf value=TOK><select name=role>"
                            "<option>user</option></select></form>")
            if method == "POST" and sid:
                sessions[sid]["role"] = "user"             # completing step 2 downgrades to real role
                return httpx.Response(302, headers={"location": "/my-account"})

        if path == "/admin" and method == "GET":
            sid = sess(request)
            if not (sid and sessions[sid]["role"] == "admin"):
                return httpx.Response(401, headers={"content-type": "text/html"}, text="Admins only")
            rows = "".join(f"<a href='/admin/delete?username={n}'>delete {n}</a>"
                           for n in ["wiener", "carlos"])
            return page(f"<h1>Admin</h1>{rows}")
        if path == "/admin/delete" and method == "GET":
            sid = sess(request)
            if sid and sessions[sid]["role"] == "admin":
                if request.url.params.get("username") == "carlos":
                    state["solved"] = True
                return page("deleted")
            return httpx.Response(401, text="nope")

        if path == "/my-account" and method == "GET":
            return httpx.Response(302, headers={"location": "/login"}) if not sess(request) else page("acct")
        if path == "/" and method == "GET":
            banner = ("<div class='is-solved'>Congratulations, you solved the lab!</div>"
                      if state["solved"] else "")
            return page(banner + "<a href=/login>Login</a> <a href=/admin>Admin</a>")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-LSM", "target_name": "LSMApp",
        "authorized_base_urls": [LAB],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": "wiener", "password": "peter", "csrf_field": "csrf"}}],
        "objective_delete_user": "carlos",
        "allow_destructive": True,
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 20, "forced_browse": True},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_login_statemachine_solves(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_lab()))
    lsm = [c for c in result.cases
           if c.test_id == "LSM-001" and c.vulnerability_class == VulnClass.SEQUENCE_VIOLATION
           and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert lsm, "login-state-machine flow did not confirm admin bypass"
    assert any("SOLVED" in n for c in lsm for n in c.notes), "objective (delete carlos) not completed"
