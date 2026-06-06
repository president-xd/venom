"""Toolbox: scope-guarded composable tools."""

import asyncio
from urllib.parse import parse_qs

import httpx

from venom.core.scope import Scope
from venom.memory import Notebook
from venom.tools import Toolbox
from venom.cognition.objective import Objective

BASE = "https://tools.example.net"


def _mock():
    state = {"bought": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def handler(req):
        path, method = req.url.path, req.method
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        if path == "/" and method == "GET":
            return page("<div class='is-solved'>solved</div>" if state["bought"] else
                        "<form action=/buy method=POST><input name=price value=1337>"
                        "<input name=csrf value=ABC></form>")
        if path == "/buy" and method == "POST":
            if int(form.get("price", "1337")) < 100 and form.get("csrf") == "ABC":
                state["bought"] = True
            return page("ok")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return Scope.from_dict({"engagement_id": "E", "target_name": "T",
                            "authorized_base_urls": [BASE], "rate_limit_per_second": 500,
                            "authorization_date": "2026-01-01T00:00:00Z",
                            "expiry_date": "2030-01-01T00:00:00Z"})


def test_tools_compose():
    async def go():
        tb = Toolbox(_scope(), Notebook(), transport=_mock())
        try:
            r = await tb.http_get("/")
            assert r.ok and r.data["forms"]                 # form discovered
            f = tb.forms().data["forms"][0]["fields"]
            csrf = next(x["value"] for x in f if x["name"] == "csrf")
            assert csrf == "ABC"                            # unquoted attr captured
            assert tb.find(r"name=csrf value=([A-Z]+)").data["match"] == "ABC"
            assert tb.calc("1337 - 1336").data["value"] == 1
            tb.note_set("csrf", csrf)
            assert tb.note_get("csrf").data["value"] == "ABC"
            return tb
        finally:
            await tb.aclose()
    asyncio.run(go())


def test_tool_objective_and_scope_guard():
    async def go():
        obj = Objective(win_url="/", win_signals=("is-solved",))
        tb = Toolbox(_scope(), Notebook(), transport=_mock(), objective=obj)
        try:
            assert (await tb.check_objective()).data["met"] is False
            await tb.http_post_form("/buy", {"price": "1", "csrf": "ABC"})
            assert (await tb.check_objective()).data["met"] is True   # objective reached via tools
            # Out-of-scope host is blocked.
            blocked = await tb.read_email_inbox("https://evil.example.com/email")
            assert blocked.ok is False
        finally:
            await tb.aclose()
    asyncio.run(go())


def test_calc_rejects_exponentiation():
    """`**` is a CPU/RAM bomb (unbounded big-integer) - calc must refuse it while
    still doing the ordinary pricing arithmetic it exists for."""
    async def go():
        tb = Toolbox(_scope(), Notebook(), transport=_mock())
        try:
            assert tb.calc("2 * 3 + 1").data["value"] == 7
            r = tb.calc("9**9**9")
            assert r.ok is False and "exponentiation" in r.summary
        finally:
            await tb.aclose()
    asyncio.run(go())


def test_exploit_sync_infinite_loop_is_killed(monkeypatch):
    """A no-await `while True: pass` cannot be cancelled by asyncio.wait_for (it never
    yields to the loop); the settrace wall-clock guard must still terminate it within
    the budget - and an `except Exception` inside the exploit must NOT swallow it."""
    import time as _t
    monkeypatch.setattr("venom.tools.base._EXPLOIT_TIMEOUT", 1.0)

    async def go():
        import sys
        before = sys.gettrace()        # whatever the harness had installed (usually None)
        tb = Toolbox(_scope(), Notebook(), transport=_mock())
        try:
            code = ("async def exploit(http):\n"
                    "    while True:\n"
                    "        try:\n"
                    "            pass\n"
                    "        except Exception:\n"
                    "            pass\n")
            t0 = _t.monotonic()
            res = await tb.run_exploit_code(code)
            elapsed = _t.monotonic() - t0
            assert res.ok is False and "timed out" in res.summary
            assert elapsed < 10, f"sync loop not interrupted promptly ({elapsed:.1f}s)"
            # The guard must be torn down afterwards (the prior trace is restored).
            assert sys.gettrace() is before
        finally:
            await tb.aclose()
    asyncio.run(go())


def test_objective_does_not_rely_on_baked_in_lab_strings():
    """Enterprise oracle: with NO operator-defined win (no win_action, no signals),
    the objective is never auto-confirmed — even on a page literally containing the
    PortSwigger 'is-solved' banner. Success must be differential or operator-defined."""
    def _mock_solved():
        def handler(req):
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text="<html><body><div class='is-solved'>Congratulations, "
                                       "you solved the lab!</div></body></html>")
        return httpx.MockTransport(handler)

    async def go():
        # Default Objective: no win_action, no win_signals -> cannot confirm.
        tb = Toolbox(_scope(), Notebook(), transport=_mock_solved(), objective=Objective(win_url="/"))
        try:
            assert (await tb.check_objective()).data["met"] is False, \
                "objective wrongly confirmed from a baked-in lab banner"
        finally:
            await tb.aclose()
        # Only when the operator EXPLICITLY defines the marker does it confirm.
        tb2 = Toolbox(_scope(), Notebook(), transport=_mock_solved(),
                      objective=Objective(win_url="/", win_signals=("is-solved",)))
        try:
            assert (await tb2.check_objective()).data["met"] is True
        finally:
            await tb2.aclose()
    asyncio.run(go())


def test_oracle_honors_non_post_win_action_method():
    """Differential oracle must replay an operator-defined win_action with its REAL
    verb. A RESTful DELETE win action was previously DOWNGRADED to POST (only GET vs
    else->POST existed), making it un-verifiable. Now DELETE is issued as DELETE:
    denied (403) at baseline, succeeds (200) after escalation."""
    def _mock_delete():
        state = {"escalated": False}

        def handler(req):
            path, method = req.url.path, req.method
            if path == "/escalate" and method == "POST":
                state["escalated"] = True
                return httpx.Response(200, text="ok")
            if path == "/users/carlos" and method == "DELETE":
                return httpx.Response(200 if state["escalated"] else 403, text="done")
            return httpx.Response(404, text="nf")
        return httpx.MockTransport(handler)

    async def go():
        # DELETE is destructive -> the scope must authorize destructive actions, which
        # is exactly the right precondition for verifying a "can delete X" objective.
        scope = Scope.from_dict({"engagement_id": "E", "target_name": "T",
                                 "authorized_base_urls": [BASE], "rate_limit_per_second": 500,
                                 "allow_destructive": True,
                                 "authorization_date": "2026-01-01T00:00:00Z",
                                 "expiry_date": "2030-01-01T00:00:00Z"})
        obj = Objective(win_action={"method": "DELETE", "path": "/users/carlos"})
        tb = Toolbox(scope, Notebook(), transport=_mock_delete(), objective=obj)
        tb.known_paths = {"/escalate", "/users/carlos"}
        try:
            assert (await obj.baseline(tb)) is False           # DELETE denied (403) un-escalated
            await tb.http_post_form("/escalate", {})
            assert (await tb.check_objective()).data["met"] is True   # DELETE now 200
        finally:
            await tb.aclose()
    asyncio.run(go())
