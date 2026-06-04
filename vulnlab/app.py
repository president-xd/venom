"""
VulnLab — a deliberately vulnerable app for exercising VENOM's autonomous agent.

ONE app, many independent business-logic flaw classes (see vulnlab/labs.py), each
a REAL exploitable bug whose `solved` flag flips only on the genuine exploit. The
same pure `handle()` core is exposed two ways:
  - as an httpx.MockTransport (in-process, deterministic tests, no network), and
  - as a real http.server (for `docker compose up vulnlab` / live hunts).

Labs (easy -> hard):
  price coupon idor | pin mass negqty workflow | trustid io money reg
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from .labs import (LABS, SOLVED_KEYS, PIN, ADMIN_TOKEN, default_users,
                   index_body, _page)

__all__ = ["handle", "new_state", "make_transport", "serve", "PIN", "ADMIN_TOKEN", "LABS"]


def new_state() -> dict:
    return {"sessions": {}, "n": 0, "users": default_users(),
            "solved": {k: False for k in SOLVED_KEYS}}


def handle(state: dict, method: str, path: str, query: str, cookies: dict, form: dict,
           headers: dict | None = None):
    """Pure request handler -> (status:int, body:str, set_cookie:str|None).

    `headers` carries request headers (lower-cased keys) so labs can authenticate
    via Authorization/X-API-Key, like real APIs. Optional for backward compatibility.
    """
    sid = cookies.get("session")
    sess = state["sessions"].get(sid)

    # ---- shared auth (multi-user table; supports account-takeover labs) ----
    if path == "/login" and method == "GET":
        return 200, _page("<form action=/login method=POST>"
                          "<input type=hidden name=csrf value=LTOK>"
                          "<input name=username><input name=password></form>"), None
    if path == "/login" and method == "POST":
        rec = state["users"].get(form.get("username"))
        if rec and rec["password"] == form.get("password"):
            state["n"] += 1
            new_sid = f"s{state['n']}"
            state["sessions"][new_sid] = {"user": form["username"], "role": rec["role"], "pin_ok": False}
            return 302, _page("ok"), f"session={new_sid}; Path=/"
        return 200, _page("Invalid credentials"), None

    # ---- index ----
    if path == "/" and method == "GET":
        return 200, _page(index_body()), None

    # ---- per-lab dispatch ----
    for lab in LABS:
        resp = lab.handler(state, method, path, query, cookies, sess, form, headers or {})
        if resp is not None:
            return resp

    return 404, _page("not found"), None


# --------------------------------------------------------------------- adapters
def make_transport(state: dict | None = None):
    """httpx.MockTransport over the pure handler (in-process tests)."""
    import httpx
    st = state if state is not None else new_state()

    def _handler(req):
        cookies = {}
        m = re.search(r"session=([^;]+)", req.headers.get("cookie", ""))
        if m:
            cookies["session"] = m.group(1)
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        headers = {k.lower(): v for k, v in req.headers.items()}
        status, body, set_cookie = handle(
            st, req.method, urlparse(str(req.url)).path,
            req.url.query.decode() if isinstance(req.url.query, bytes) else req.url.query,
            cookies, form, headers)
        headers = {"content-type": "text/html"}
        if set_cookie:
            headers["set-cookie"] = set_cookie
        return httpx.Response(status, headers=headers, text=body)

    return httpx.MockTransport(_handler), st


def serve(host: str = "0.0.0.0", port: int = 8000):  # pragma: no cover - runtime only
    """Run as a real HTTP server (for Docker / live hunts)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    state = new_state()

    class H(BaseHTTPRequestHandler):
        def _cookies(self):
            c = {}
            m = re.search(r"session=([^;]+)", self.headers.get("Cookie", "") or "")
            if m:
                c["session"] = m.group(1)
            return c

        def _do(self, method):
            u = urlparse(self.path)
            form = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length", 0) or 0)
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
            headers = {k.lower(): v for k, v in self.headers.items()}
            status, body, set_cookie = handle(state, method, u.path, u.query, self._cookies(), form, headers)
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.end_headers()
            self.wfile.write(body.encode())

        def do_GET(self):
            self._do("GET")

        def do_POST(self):
            self._do("POST")

        def log_message(self, *a):
            pass

    print(f"VulnLab serving on {host}:{port} — labs: {', '.join(SOLVED_KEYS)}")
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":  # pragma: no cover
    import os
    serve(port=int(os.getenv("PORT", "8000")))
