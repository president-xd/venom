"""
Proof for the encryption-oracle flow (PortSwigger "encryption oracle"): the
comment 'invalid email' error encrypts attacker input and the page reflects the
decryption. VENOM decrypts the stay-logged-in cookie, forges 'administrator:<ts>'
by block-aligned prefix removal, authenticates as admin, and deletes carlos.

The mock uses a position-independent (ECB-style) block cipher so the block
cut-and-paste is genuinely exercised.
"""

import asyncio
import base64
import json
import re
from urllib.parse import parse_qs, unquote

import httpx

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

LAB = "https://enc.example.net"
PREFIX = "Invalid email address: "
BS = 16
KEY = bytes((i * 37 + 11) & 0xFF for i in range(BS))   # fixed per-position key (ECB-like)
TS = "1780417187524"


def _pad(b):
    n = BS - (len(b) % BS)
    return b + bytes([n]) * n


def _unpad(b):
    n = b[-1]
    if n < 1 or n > BS or b[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return b[:-n]


def _enc(text: str) -> bytes:
    data = _pad(text.encode())
    out = bytearray()
    for i in range(0, len(data), BS):
        out += bytes(x ^ KEY[j] for j, x in enumerate(data[i:i + BS]))
    return bytes(out)


def _dec(ct: bytes) -> str:
    out = bytearray()
    for i in range(0, len(ct), BS):
        out += bytes(x ^ KEY[j] for j, x in enumerate(ct[i:i + BS]))
    return _unpad(bytes(out)).decode(errors="replace")


def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(unquote(s))


def make_lab():
    state = {"solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{b}</body></html>")

    def cookie(req, name):
        m = re.search(rf"{name}=([^;]+)", req.headers.get("cookie", ""))
        return m.group(1) if m else None

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        form = {k: v[0] for k, v in parse_qs(request.content.decode() if request.content else "").items()}

        if path == "/" and method == "GET":
            banner = "<div class='is-solved'>solved the lab!</div>" if state["solved"] else ""
            return page(banner + '<a href="/post?postId=1">post</a> <a href=/login>login</a>')
        if path == "/login" and method == "GET":
            return page("<form action=/login method=POST><input type=hidden name=csrf value=TOK>"
                        "<input name=username><input name=password>"
                        "<input type=checkbox name=stay-logged-in></form>")
        if path == "/login" and method == "POST":
            headers = {"set-cookie": "session=sess1; Path=/", "location": "/"}
            if form.get("stay-logged-in") and form.get("username") == "wiener" and form.get("password") == "peter":
                sl = b64e(_enc(f"wiener:{TS}"))
                headers["set-cookie"] = f"stay-logged-in={sl}; Path=/"
            return httpx.Response(302, headers=headers)
        if path == "/post" and method == "GET":
            note = cookie(request, "notification")
            shown = ""
            if note:
                try:
                    shown = f"<div class=notification-header>{_dec(b64d(note))}</div>"
                except Exception:
                    shown = "<div class=notification-header>Last unit does not have enough valid bits</div>"
            return page(shown + "<form action=/post/comment method=POST>"
                        "<input type=hidden name=csrf value=TOK><input type=hidden name=postId value=1>"
                        "<input name=comment><input name=name><input name=email><input name=website></form>")
        if path == "/post/comment" and method == "POST":
            note = b64e(_enc(PREFIX + form.get("email", "")))
            return httpx.Response(302, headers={"set-cookie": f"notification={note}; Path=/",
                                                "location": "/post?postId=1"})
        if path == "/admin" and method == "GET":
            sl = cookie(request, "stay-logged-in")
            ok = False
            if sl:
                try:
                    ok = _dec(b64d(sl)).startswith("administrator:")
                except Exception:
                    ok = False
            if not ok:
                return httpx.Response(401, headers={"content-type": "text/html"}, text="Admins only")
            rows = "".join(f"<a href='/admin/delete?username={n}'>delete {n}</a>" for n in ["wiener", "carlos"])
            return page(f"<h1>Admin</h1>{rows}")
        if path == "/admin/delete" and method == "GET":
            sl = cookie(request, "stay-logged-in")
            try:
                ok = sl and _dec(b64d(sl)).startswith("administrator:")
            except Exception:
                ok = False
            if ok:
                if request.url.params.get("username") == "carlos":
                    state["solved"] = True
                return page("deleted")
            return httpx.Response(401, text="nope")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _scope():
    return {
        "engagement_id": "ENG-ENC", "target_name": "EncShop",
        "authorized_base_urls": [LAB],
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": "wiener", "password": "peter", "csrf_field": "csrf"}}],
        "privileged_account": "administrator",
        "objective_delete_user": "carlos",
        "allow_destructive": True,
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": 20, "forced_browse": False},
        "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    }


def test_encryption_oracle_solves(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    result = asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json", artifact_paths=[], out_dir=tmp_path / "out",
        dry_run=False, use_llm=False, transport=make_lab()))
    enc = [c for c in result.cases
           if c.test_id == "ENC-001" and c.vulnerability_class == VulnClass.FAITH_BASED_RULE
           and c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert enc, "encryption-oracle flow did not confirm admin takeover"
    assert any("SOLVED" in n for c in enc for n in c.notes), "objective (delete carlos) not completed"
