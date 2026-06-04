"""
Deterministic tests for the agent Toolbox dispatch robustness — the brittleness
that blocked the autonomy loop: LLMs emit `http_post` with a `body` (dict OR
'a=b&c=d' string) and stray kwargs (headers, expect_status). The dispatcher must
alias the name, normalise the body, and tolerate unknown kwargs.
"""

import asyncio
from urllib.parse import parse_qs

import httpx

from venom.core.scope import Scope
from venom.memory import Notebook
from venom.tools import Toolbox

BASE = "https://disp.example.net"


def make_transport(seen):
    def handler(req):
        if req.method == "POST":
            seen.append({k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()})
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>ok</html>")
    return httpx.MockTransport(handler)


def _scope():
    return Scope.from_dict({
        "engagement_id": "E", "target_name": "T", "authorized_base_urls": [BASE],
        "rate_limit_per_second": 1000,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z"})


def _box(seen):
    return Toolbox(_scope(), Notebook(), transport=make_transport(seen))


def test_http_post_alias_with_dict_body_and_stray_kwargs():
    seen = []
    box = _box(seen)
    res = asyncio.run(box.call("http_post", {
        "path": "/login", "body": {"csrf": "T", "username": "wiener", "password": "peter"},
        "headers": {"Content-Type": "x"}, "expect_status": 302}))   # stray kwargs must not break it
    asyncio.run(box.aclose())
    assert res.ok and "POST" in res.summary
    assert seen == [{"csrf": "T", "username": "wiener", "password": "peter"}]


def test_http_post_with_urlencoded_string_body():
    seen = []
    box = _box(seen)
    res = asyncio.run(box.call("http_post", {"path": "/x", "body": "a=1&b=two"}))
    asyncio.run(box.aclose())
    assert res.ok
    assert seen == [{"a": "1", "b": "two"}]


def test_post_form_fields_and_get_alias():
    seen = []
    box = _box(seen)
    asyncio.run(box.call("post", {"path": "/y", "fields": {"k": "v"}}))   # alias + fields
    g = asyncio.run(box.call("get", {"path": "/y"}))                        # GET alias
    asyncio.run(box.aclose())
    assert seen == [{"k": "v"}]
    assert g.ok


def test_unknown_tool_lists_valid_names():
    box = _box([])
    res = asyncio.run(box.call("frobnicate", {}))
    asyncio.run(box.aclose())
    assert not res.ok and "http_post" in res.summary
