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
