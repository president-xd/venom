"""
Pure request router — maps (method, path, query, body) to a response tuple
``(status, body, content_type)`` with no socket I/O, so the whole API surface is
unit-testable (the same separation ``vulnlab/app.py::handle`` uses).

``body`` is the parsed JSON dict (``{}`` for GET). ``body`` of the response is a
dict (the server JSON-encodes it) or a ``str``/``bytes`` for raw artifacts.

The ``/api/runs/<id>/stream`` SSE endpoint is handled directly by the server
(it needs the live socket), not here.
"""

from __future__ import annotations

import re

from . import api
from .runs import MANAGER, _data_dir

_JSON = "application/json"
_ART = {"report": ("report.md", "text/markdown; charset=utf-8"),
        "report.md": ("report.md", "text/markdown; charset=utf-8"),
        "findings.json": ("findings.json", _JSON),
        "findings.sarif": ("findings.sarif", _JSON),
        "business_model.json": ("business_model.json", _JSON)}

_RUN_RE = re.compile(r"^/api/runs/([^/]+)(/.*)?$")


def _ok(obj, status: int = 200):
    return status, obj, _JSON


def handle(method: str, path: str, query: dict, body: dict):
    path = path.rstrip("/") or "/"

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
        return _ok(api.api_engagements())

    # ---- POSTs ----
    if method == "POST" and path == "/api/scope/validate":
        return _ok(api.api_scope_validate(body or {}))
    if method == "POST" and path == "/api/knowledge":
        res = api.api_add_knowledge(body or {})
        return _ok(res, 400 if not res.get("ok") else 201)
    if method == "POST" and path == "/api/runs":
        res = api.api_start_run(body or {})
        return _ok(res, 503 if res.get("error") else 201)

    # ---- per-run (resolved from memory or persisted trace on disk) ----
    m = _RUN_RE.match(path)
    if m:
        run_id, sub = m.group(1), (m.group(2) or "").lstrip("/")
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
            return 200, fpath.read_text(encoding="utf-8"), ctype

    return _ok({"error": "not found", "path": path}, 404)
