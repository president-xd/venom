"""
VENOM web console server - std-lib ``http.server`` (no runtime dependency).

Serves the React UI (``venom/web/ui``) and the JSON API, plus a Server-Sent
Events stream of a live engagement's trace. Threaded so a long-lived SSE
connection never blocks other requests.
"""

from __future__ import annotations

import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import routes
from .runs import MANAGER

logger = logging.getLogger("venom.web")

UI_DIR = (Path(__file__).parent / "ui").resolve()

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".jsx": "text/babel; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
}

_STREAM_RE = re.compile(r"^/api/runs/([^/]+)/stream$")


class _Handler(BaseHTTPRequestHandler):
    server_version = "VENOM-web/0.1"
    protocol_version = "HTTP/1.1"

    # -- low-level send -------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Baseline hardening for the operator console (MIME-sniffing, clickjacking,
        # referrer leakage). Cheap and side-effect-free for a localhost SPA + JSON API.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _api(self, method: str, path: str, query: dict, body: dict) -> None:
        cookie = self.headers.get("Cookie", "") or ""
        extra: dict = {}
        try:
            result = routes.handle(method, path, query, body, cookie)
            if len(result) == 4:        # (status, payload, ctype, extra_headers)
                status, payload, ctype, extra = result
            else:
                status, payload, ctype = result
        except Exception as exc:  # noqa: BLE001 - never 500 the whole server silently
            logger.exception("API error on %s %s", method, path)
            status, payload, ctype = 500, {"error": str(exc)}, "application/json"
        if isinstance(payload, (dict, list)):
            data = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, str):
            data = payload.encode("utf-8")
        else:
            data = payload or b""
        self._send(status, data, ctype, extra or None)

    # -- SSE ------------------------------------------------------------------
    def _sse(self, run_id: str) -> None:
        run = MANAGER.get(run_id)
        if not run:
            self._send(404, b'{"error":"run not found"}', "application/json")
            return
        # Streamed body of unknown length: under HTTP/1.1 we frame it as
        # "read until the server closes" (Connection: close), which EventSource
        # and plain HTTP clients both handle. Without this the client blocks
        # waiting for a Content-Length / chunked framing we never send.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")  # disable proxy buffering
        self.end_headers()
        try:
            self.wfile.write(b": stream open\n\n")
            self.wfile.flush()
            for ev in run.iter_events():
                self.wfile.write(b"data: " + json.dumps(ev).encode("utf-8") + b"\n\n")
                self.wfile.flush()
            self.wfile.write(b"event: end\ndata: {}\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- static ---------------------------------------------------------------
    def _serve_static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        target = (UI_DIR / rel).resolve()
        if not target.is_relative_to(UI_DIR) or not target.is_file():
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        ctype = _CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # -- verbs ----------------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            m = _STREAM_RE.match(path)
            if m:
                self._sse(m.group(1))
                return
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            self._api("GET", path, query, {})
            return
        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except (ValueError, json.JSONDecodeError):
            body = {}
        if path.startswith("/api/"):
            self._api("POST", path, {}, body)
            return
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def log_message(self, *args) -> None:  # quiet by default
        pass


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:  # pragma: no cover - runtime
    from . import auth
    seeded = auth.ensure_seed_user()
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"VENOM console serving on http://{host}:{port}  (UI: {UI_DIR})")
    print("  Launch an engagement from the UI - it runs in-process against the bundled VulnLab.")
    if seeded:
        print(f"  Login created -> user: {seeded['username']}   password: {seeded['password']}")
        print("  (set VENOM_WEB_USER / VENOM_WEB_PASSWORD to choose; add more via the API.)")
    else:
        print("  Login required. Use your existing operator account (users.json).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
    finally:
        httpd.server_close()
