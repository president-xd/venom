"""
Live autonomy integration test (opt-in): drive the FULL agent loop with a REAL
LLM against in-memory apps whose flaws are covered by NO hand-written flow. Proves
the agent solves DIFFERENT classes cold by reasoning (recon -> hypothesis ->
exploit -> verify) — i.e. breadth, not a one-off.

Classes covered: mass-assignment privilege escalation, and IDOR-to-admin.

Skipped unless VENOM_LIVE_LLM=1 (needs a configured provider key); the dispatch /
backtracking / replay / budget mechanics are covered deterministically in
test_autonomy_features.py and test_toolbox_dispatch.py.
"""

import asyncio
import os
import re
from urllib.parse import parse_qs

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("VENOM_LIVE_LLM") != "1",
    reason="set VENOM_LIVE_LLM=1 (and provider keys) to run the live autonomy test")

BASE = "https://auto.example.net"


def _page(b):
    return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{b}</body></html>")


def _sess(req, sessions):
    m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
    return sessions.get(m.group(1)) if m else None


# --------------------------- class 1: mass assignment ------------------------
def make_mass_assignment_app():
    sessions, state = {}, {"n": 0, "solved": False}

    def is_admin(u):
        return bool(u) and (str(u.get("role", "")).lower() in ("admin", "administrator")
                            or str(u.get("is_admin", "")).lower() in ("true", "1"))

    def handler(req):
        path, method = req.url.path, req.method
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        u = _sess(req, sessions)
        if path == "/" and method == "GET":
            return _page("<div class='is-solved'>solved!</div>" if state["solved"] else "<a href=/login>login</a>")
        if path == "/login" and method == "GET":
            return _page("<form action=/login method=POST><input type=hidden name=csrf value=LTOK>"
                         "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            if form.get("username") == "wiener" and form.get("password") == "peter":
                state["n"] += 1; sid = f"s{state['n']}"; sessions[sid] = {"role": "user"}
                return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/my-account"})
            return _page("Invalid credentials")
        if path == "/my-account" and method == "GET":
            if not u:
                return httpx.Response(302, headers={"location": "/login"})
            return _page("<form action=/my-account/update method=POST><input type=hidden name=csrf value=UTOK>"
                         "<input name=name value=wiener><input name=email value=wiener@x.net></form>")
        if path == "/my-account/update" and method == "POST":
            if not u:
                return httpx.Response(401, text="login first")
            for k in ("name", "email", "role", "is_admin", "isAdmin"):
                if k in form:
                    u["is_admin" if k.lower() == "isadmin" else k] = form[k]
            return _page("Account updated")
        if path == "/admin" and method == "GET":
            if not is_admin(u):
                return httpx.Response(401, headers={"content-type": "text/html"}, text="Admin only")
            return _page("<form action=/admin/delete method=POST><input type=hidden name=csrf value=ATOK>"
                         "<input name=username></form>")
        if path == "/admin/delete" and method == "POST":
            if not is_admin(u):
                return httpx.Response(401, text="nope")
            if form.get("username") == "carlos":
                state["solved"] = True
            return _page("deleted")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def mass_assignment_registry():
    from venom.core.registry import EndpointRegistry, Endpoint
    reg = EndpointRegistry()
    for p, m in [("/login", "POST"), ("/my-account", "GET"), ("/my-account/update", "POST"),
                 ("/admin", "GET"), ("/admin/delete", "POST")]:
        reg.add(Endpoint(path=p, method=m, source=["crawl"]))
    return reg


# --------------------------- class 2: IDOR to admin --------------------------
def make_idor_app():
    sessions, state = {}, {"n": 0, "solved": False}

    def handler(req):
        path, method = req.url.path, req.method
        params = dict(req.url.params)
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        u = _sess(req, sessions)
        if path == "/" and method == "GET":
            return _page("<div class='is-solved'>solved!</div>" if state["solved"] else "<a href=/login>login</a>")
        if path == "/login" and method == "GET":
            return _page("<form action=/login method=POST><input type=hidden name=csrf value=LTOK>"
                         "<input name=username><input name=password></form>")
        if path == "/login" and method == "POST":
            if form.get("username") == "wiener" and form.get("password") == "peter":
                state["n"] += 1; sid = f"s{state['n']}"; sessions[sid] = "wiener"
                return httpx.Response(302, headers={"set-cookie": f"session={sid}; Path=/", "location": "/my-account"})
            return _page("Invalid credentials")
        if path == "/my-account" and method == "GET":
            if not u:
                return httpx.Response(302, headers={"location": "/login"})
            # Leaks that admin functions are keyed by a user PARAMETER (IDOR lever).
            return _page("Your account (wiener). The admin panel is at /admin?user=YOUR_USERNAME. "
                         "Known users: wiener, administrator, carlos.")
        if path == "/admin" and method == "GET":
            if not u:
                return httpx.Response(302, headers={"location": "/login"})
            if params.get("user") != "administrator":      # IDOR: trusts the user param
                return httpx.Response(401, headers={"content-type": "text/html"}, text="Admin only")
            return _page("<form action=/admin/delete method=POST><input type=hidden name=csrf value=ATOK>"
                         "<input type=hidden name=user value=administrator><input name=username></form>")
        if path == "/admin/delete" and method == "POST":
            if form.get("user") != "administrator":
                return httpx.Response(401, text="nope")
            if form.get("username") == "carlos":
                state["solved"] = True
            return _page("deleted")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def idor_registry():
    from venom.core.registry import EndpointRegistry, Endpoint
    reg = EndpointRegistry()
    for p, m in [("/login", "POST"), ("/my-account", "GET"), ("/admin", "GET"), ("/admin/delete", "POST")]:
        reg.add(Endpoint(path=p, method=m, source=["crawl"]))
    return reg


SCENARIOS = {
    "mass_assignment": (make_mass_assignment_app, mass_assignment_registry,
                        "Log in (wiener:peter via POST /login with the csrf from the login page), escalate "
                        "your own privileges to administrator, then use /admin to delete the user 'carlos'."),
    "idor": (make_idor_app, idor_registry,
             "Log in (wiener:peter via POST /login with the csrf from the login page), then gain admin access "
             "and delete the user 'carlos'. Inspect /my-account for how admin access is determined."),
}


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_autonomous_agent_solves_cold(scenario):
    from venom.core.scope import Scope
    from venom.llm import LLMRouter
    from venom.agents import build_orchestrator, AgentRole
    from venom.cognition import Agent, Objective
    from venom.cognition.agent_brain import make_agent_brain
    from venom.memory import SkillLibrary

    make_app, make_reg, goal = SCENARIOS[scenario]
    scope = Scope.from_dict({
        "engagement_id": f"ENG-{scenario}", "target_name": scenario,
        "authorized_base_urls": [BASE], "allow_destructive": True, "rate_limit_per_second": 50,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z"})
    router = LLMRouter.from_env(air_gap=False, mode="default")
    assert router.any_enabled(), "no LLM provider enabled"
    orch = build_orchestrator(router)
    brain = make_agent_brain(orch.agent(AgentRole.CODEGEN))
    agent = Agent(scope, brain, transport=make_app(), skills=SkillLibrary(), max_steps=20,
                  deadline_seconds=240)
    objective = Objective(description=goal, win_url="/", win_signals=("is-solved", "congratulations"))
    findings = asyncio.run(agent.run(make_reg(), objective))
    assert findings, f"agent did not solve '{scenario}' cold"
    assert any("OBJECTIVE MET" in n for f in findings for n in f.notes)
