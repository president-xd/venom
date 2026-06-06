"""
Pure request router - maps (method, path, query, body) to a response tuple
``(status, body, content_type)`` with no socket I/O, so the whole API surface is
unit-testable (the same separation ``vulnlab/app.py::handle`` uses).

``body`` is the parsed JSON dict (``{}`` for GET). ``body`` of the response is a
dict (the server JSON-encodes it) or a ``str``/``bytes`` for raw artifacts.

The ``/api/runs/<id>/stream`` SSE endpoint is handled directly by the server
(it needs the live socket), not here.
"""

from __future__ import annotations

import re

from . import api, auth
from .runs import MANAGER, _data_dir

_JSON = "application/json"
_ART = {"report": ("report.md", "text/markdown; charset=utf-8"),
        "report.md": ("report.md", "text/markdown; charset=utf-8"),
        "findings.json": ("findings.json", _JSON),
        "findings.sarif": ("findings.sarif", _JSON),
        "business_model.json": ("business_model.json", _JSON)}

_RUN_RE = re.compile(r"^/api/runs/([^/]+)(/.*)?$")
# A run id is "ENG-WEB-<hex>" - strictly [A-Za-z0-9_-]. We validate it BEFORE it is
# ever used to build a filesystem path, because the per-run handlers read
# `_data_dir()/<run_id>/<fixed-file>`: a run id of ".." (which [^/]+ happily matches)
# would escape the per-run directory (e.g. GET /api/runs/../report.md reads the parent
# dir's report.md). Excluding '.' and path separators makes traversal impossible.
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]+$")

def _ok(obj, status: int = 200, headers: dict | None = None):
    return status, obj, _JSON, (headers or {})


def _is_protected(method: str, path: str) -> bool:
    """Per-user data and mutating endpoints require a session; read-only config
    (status, vuln-classes, agents, providers, scope/validate) stays public so the
    login screen and health checks work. The whole UI is still gated client-side."""
    return (path == "/api/engagements"
            or path.startswith("/api/runs")
            or (method == "POST" and path == "/api/knowledge"))


def handle(method: str, path: str, query: dict, body: dict, cookie: str = ""):
    """Return (status, body, content_type, extra_headers). `cookie` is the request
    Cookie header; the current operator is resolved from its signed session token."""
    path = path.rstrip("/") or "/"
    user = auth.user_from_cookie(cookie)

    # ---- auth endpoints (no session required) ----
    if method == "POST" and path == "/api/login":
        acct = auth.authenticate((body or {}).get("username", ""), (body or {}).get("password", ""))
        if not acct:
            return _ok({"error": "invalid credentials"}, 401)
        token = auth.make_session(acct["username"])
        return _ok({"ok": True, "user": acct}, 200, {"Set-Cookie": auth.session_cookie(token)})
    if method == "POST" and path == "/api/logout":
        return _ok({"ok": True}, 200, {"Set-Cookie": auth.clear_cookie()})
    if method == "GET" and path == "/api/me":
        prof = auth.user_profile(user) if user else None
        return _ok({"authenticated": bool(prof), "user": prof})

    # ---- per-user / mutating endpoints require a valid session ----
    if _is_protected(method, path) and not user:
        return _ok({"error": "authentication required"}, 401)

    # ---- collection / singleton GETs ----
    if method == "GET" and path == "/api/status":
        return _ok(api.api_status())
    if method == "GET" and path == "/api/vuln-classes":
        return _ok(api.api_vuln_classes())
    if method == "GET" and path == "/api/agents":
        return _ok(api.api_agents())
    if method == "GET" and path == "/api/providers":
        return _ok(api.api_providers())
    if method == "GET" and path == "/api/engagements":
        return _ok(api.api_engagements(user))

    # ---- POSTs ----
    if method == "POST" and path == "/api/scope/validate":
        return _ok(api.api_scope_validate(body or {}))
    if method == "POST" and path == "/api/knowledge":
        res = api.api_add_knowledge(body or {})
        return _ok(res, 400 if not res.get("ok") else 201)
    if method == "POST" and path == "/api/runs":
        res = api.api_start_run(body or {}, user)
        return _ok(res, 503 if res.get("error") else 201)

    # ---- per-run (owner-gated: a user only sees their own / shared runs) ----
    m = _RUN_RE.match(path)
    if m:
        run_id, sub = m.group(1), (m.group(2) or "").lstrip("/")
        # Reject path-traversal / malformed ids before any filesystem use (see _SAFE_RUN_ID).
        if not _SAFE_RUN_ID.match(run_id):
            return _ok({"error": "not found"}, 404)
        if not api.run_visible_to(run_id, user):
            return _ok({"error": "not found"}, 404)
        if method == "GET" and sub == "":
            s = api.api_run_status(run_id)
            return _ok(s, 404 if s.get("error") else 200)
        if method == "GET" and sub == "findings":
            f = api.api_run_findings(run_id)
            return _ok(f, 404 if f.get("error") else 200)
        if method == "GET" and sub in _ART:
            fname, ctype = _ART[sub]
            fpath = _data_dir() / run_id / fname
            if not fpath.exists():
                return _ok({"error": f"{fname} not ready"}, 404)
            return 200, fpath.read_text(encoding="utf-8"), ctype, {}

    return _ok({"error": "not found", "path": path}, 404)
