"""
The Toolbox: a session-bound set of scope-guarded tools with a machine-readable
catalog (for LLM tool-calling) and a single `call(name, args)` dispatcher.

Every tool returns a compact `ToolResult` (never raw HTML) so the agent's context
stays within free-tier budgets. All HTTP goes through the scope guard + rate limiter.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import builtins
import contextlib
import inspect
import io
import json as _json
import logging
import re
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote, quote_plus

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..llm.budget import compact_html
from ..utils import regex_extract, redact, redact_secrets
from .exploit_kit import KIT as _KIT

logger = logging.getLogger("venom.tools")


@dataclass
class ToolResult:
    ok: bool
    summary: str                       # short, human/LLM-readable
    data: dict = field(default_factory=dict)   # compact structured payload

    def to_dict(self) -> dict:
        return {"ok": self.ok, "summary": self.summary, "data": self.data}


# Tool catalog advertised to the planner (name -> description + arg hints).
CATALOG = [
    {"name": "http_get", "desc": "GET a path. args: path, identity?", },
    {"name": "http_post", "desc": "POST a path (form-encoded by default). args: path, "
                          "fields{} (or body{}), identity?, follow_redirects?. For JSON add json:true."},
    {"name": "http_post_form", "desc": "POST form-encoded. args: path, fields{}, identity?, follow_redirects?"},
    {"name": "http_post_json", "desc": "POST JSON. args: path, body{}, identity?"},
    {"name": "find", "desc": "Regex-extract from the LAST response. args: regex (group 1)"},
    {"name": "forms", "desc": "Return forms (action/method/fields+values) from the LAST response."},
    {"name": "calc", "desc": "Evaluate arithmetic safely. args: expr"},
    {"name": "read_email_inbox", "desc": "GET an inbox URL and return confirmation links. args: url, recipient?"},
    {"name": "note_set", "desc": "Write a fact to working memory. args: key, value"},
    {"name": "note_get", "desc": "Read a fact from working memory. args: key"},
    {"name": "check_objective", "desc": "Check whether the engagement objective is met."},
    {"name": "run_exploit_code", "desc": "Write & run your OWN exploit as Python. args: code "
                                "(a string defining `async def exploit(http):` where "
                                "`await http(method, path, data={}, params={}, json={})` returns "
                                "{status,text,headers}; return a result). Pre-imported helpers (no "
                                "import): `await login(user, pass)` re-auths in-session (cookies "
                                "persist); extract(text, pattern)/extract_all; find_overflow_qty; "
                                "modinv; brute; b64e/b64d (url-safe base64 for cookies/tokens); "
                                "jwt_none(claims) forges an UNSIGNED admin JWT, jwt_hs256(claims, "
                                "secret) signs with a known key. Use for loops/brute-force/computation/multi-step "
                                "chains. stdout, return value, a per-request `trace` and any "
                                "traceback come back so you can FIX and re-run. identity? optional."},
]

# Pure-stdlib, computation/encoding-only modules an exploit may import. The match
# is EXACT (full dotted name): we deliberately do NOT admit a submodule just because
# its package root is listed.
#
# `urllib` is INTENTIONALLY ABSENT. A root-based check previously admitted
# `import urllib.request` (root 'urllib' was whitelisted for `urllib.parse`), which
# handed exploit code `urllib.request.urlopen(...)` -> arbitrary network egress AND
# local `file://` reads, bypassing the scope guard (the single safety chokepoint).
# Even `import urllib.parse` binds the `urllib` PACKAGE object, from which a
# pre-imported `urllib.request` is reachable by attribute. So urllib is excluded
# entirely; the pure URL helpers an exploit might want (urlencode/quote/unquote/
# urlparse/parse_qs) are injected directly into the sandbox namespace instead - no
# package object is ever exposed.
_SAFE_IMPORTS = frozenset({
    "json", "re", "base64", "binascii", "hashlib", "hmac", "math", "random",
    "secrets", "itertools", "functools", "string", "datetime", "uuid", "decimal",
    "collections", "struct", "time", "html", "textwrap",
})


def _import_ok(module: str) -> bool:
    """Allow ONLY exact pure-stdlib module names. No submodule is auto-admitted via
    its package root - that root-based logic is exactly what let `urllib.request`
    (network egress + file read) through, bypassing the scope guard."""
    return bool(module) and module in _SAFE_IMPORTS


class _SafeTime:
    """`time` shim handed to the sandbox: forwards every real attribute EXCEPT
    `sleep`, which is capped to <=1s. A raw `time.sleep(99999)` is a C-level blocking
    call that neither `asyncio.wait_for` (it never hits an await point) nor the
    per-line deadline trace can interrupt - it would wedge the shared event loop.
    Capping neutralises that DoS while keeping time.time()/monotonic()/etc. usable
    (e.g. for JWT `exp` claims)."""
    _SLEEP_CAP = 1.0

    def __getattr__(self, k):
        return getattr(time, k)

    def sleep(self, seconds=0):
        try:
            s = min(max(float(seconds), 0.0), self._SLEEP_CAP)
        except (TypeError, ValueError):
            s = 0.0
        time.sleep(s)


_TIME_SHIM = _SafeTime()


def _safe_import(name, _globals=None, _locals=None, fromlist=(), level=0):
    """A whitelisted __import__ for exploit code: only the exact pure-stdlib modules
    in _SAFE_IMPORTS. `time` is handed back as the sleep-capped shim. Relative
    imports (level>0) are always refused."""
    if level == 0 and _import_ok(name):
        if name == "time":
            return _TIME_SHIM
        return builtins.__import__(name, _globals, _locals, fromlist, level)
    raise ImportError(f"import of {name!r} is not allowed in exploit code")


# Safe builtins exposed to agent-authored exploit code (no open/eval/exec; imports
# go through the whitelist-guarded _safe_import only).
_SAFE_BUILTINS = {k: getattr(builtins, k) for k in (
    "range", "len", "str", "int", "float", "bool", "dict", "list", "tuple", "set",
    "enumerate", "zip", "min", "max", "sum", "sorted", "abs", "any", "all", "print",
    "repr", "reversed", "map", "filter", "format", "bytes", "chr", "ord", "hex",
    "isinstance", "Exception", "ValueError", "KeyError", "IndexError", "True", "False", "None",
) if hasattr(builtins, k)}
_SAFE_BUILTINS["__import__"] = _safe_import

# Names that enable sandbox escape / host access - refused before execution.
_BANNED_NAMES = {"eval", "exec", "compile", "open", "__import__", "globals", "locals", "vars",
                 "getattr", "setattr", "delattr", "input", "breakpoint", "memoryview", "help",
                 "dir", "globals", "exit", "quit", "__builtins__"}
_EXPLOIT_TIMEOUT = 180.0   # wall-clock cap on agent-authored code (headroom for
                           # legitimate brute-force loops, e.g. a 4-digit PIN)


class _ExploitTimeout(BaseException):
    """Raised by the deadline trace to kill runaway synchronous exploit code.
    Subclasses BaseException (NOT Exception) on purpose, so the exploit's own
    `except Exception:` cannot swallow its timeout and keep the loop spinning."""


def _install_deadline_trace(deadline: float):
    """Bound *synchronous* agent code that never awaits.

    `asyncio.wait_for` can only cancel a coroutine at an `await` point, so an
    LLM-authored `while True: pass` (no await) would spin the event loop forever and
    the timeout would NEVER fire - a real liveness/DoS bug. This installs a per-thread
    trace that fires on each line of the exploit's OWN frames (filename '<exploit>')
    and raises once the wall-clock deadline passes. Library/httpx/asyncio frames
    return None -> they run untraced, so there is no per-line overhead on the hot I/O
    path. Returns the previous trace function so the caller can restore it.

    CPython-specific (sys.settrace). It is a guardrail for an authorized operator, not
    a hard sandbox; for fully untrusted models also run the agent inside a container.
    """
    def _tracer(frame, event, arg):
        if frame.f_code.co_filename != "<exploit>":
            return None                      # don't trace library internals
        if time.monotonic() > deadline:
            raise _ExploitTimeout(f"exploit exceeded {_EXPLOIT_TIMEOUT:.0f}s wall-clock budget")
        return _tracer
    prev = sys.gettrace()
    sys.settrace(_tracer)
    return prev


# A str.format / format_map template can reach object internals WITHOUT any AST
# Attribute node - the dunder traversal lives inside a string literal, e.g.
#   "{0.__class__.__init__.__globals__[breakpoint]}".format(obj)
# We therefore also reject string LITERALS that contain a format replacement field
# using attribute/index access (`{0.__class__...}`, `{0[__x__]}`) or a direct dotted
# dunder traversal (`.__globals__`). Normal formatting ({}, {0}, {name}, {:.2f}) is
# unaffected because it has no `.`/`[` in the field-name part.
_FMT_FIELD_ATTR_RE = re.compile(r"\{[^{}:!]*[.\[][^{}]*\}")
_DOTTED_DUNDER_RE = re.compile(r"\.\s*__\w+__")

# Non-dunder attributes that hand back a frame / code / globals / traceback object -
# the rungs of a frame-walk to the host namespace. The dunder filter
# (startswith("__")) does NOT catch these because they do not start with "__"
# (e.g. `gen.gi_frame.f_back.f_globals`). Reaching the real builtins through them is
# not currently possible (no way to obtain an out-of-sandbox frame: there is no
# sys/inspect import, and generator/coroutine frames created in-sandbox carry the
# sandbox globals with f_back=None while suspended). This denylist is defense-in-
# depth so the guarantee survives any future change to the safe-import set or helpers.
_DANGEROUS_ATTRS = frozenset({
    "gi_frame", "gi_code", "gi_yieldfrom", "cr_frame", "cr_code", "cr_await",
    "ag_frame", "ag_code", "f_back", "f_globals", "f_builtins", "f_locals",
    "f_code", "f_trace", "tb_frame", "tb_next", "tb_lasti",
    "func_globals", "func_code", "func_builtins", "func_dict",
})


def _validate_exploit_ast(code: str) -> str | None:
    """Static check on agent-authored code. Blocks the realistic in-process escape
    vectors (host/process/fs imports, dunder traversal incl. format-string tricks,
    eval/exec/open). Pure-stdlib imports (see _SAFE_IMPORTS) are permitted.
    Defense-in-depth - for fully untrusted models run the agent inside a container too."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"syntax error: {exc}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _import_ok(alias.name):
                    return f"import of '{alias.name}' is not allowed in exploit code"
            continue
        if isinstance(node, ast.ImportFrom):
            if node.level != 0 or not _import_ok(node.module or ""):
                return f"import from '{node.module or ''}' is not allowed in exploit code"
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.attr, str):
            if node.attr.startswith("__"):
                return f"dunder attribute access '{node.attr}' is not allowed"
            if node.attr in _DANGEROUS_ATTRS:
                return (f"attribute access '{node.attr}' (frame/code/traceback internals) "
                        "is not allowed")
        if isinstance(node, ast.Name) and node.id in _BANNED_NAMES:
            return f"use of '{node.id}' is not allowed"
        # Block the format-string escape (dunders hidden inside a string literal).
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            if _DOTTED_DUNDER_RE.search(s) or _FMT_FIELD_ATTR_RE.search(s):
                return ("string contains a format/attribute traversal that could reach "
                        "object internals (e.g. '{0.__class__...}') - not allowed")
    return None


class Toolbox:
    def __init__(self, scope: Scope, notebook, *, transport=None, objective=None):
        self.scope = scope
        self.notebook = notebook
        self.objective = objective
        self._transport = transport
        self._limiter = RateLimiter(scope.rate_limit_per_second)
        self._auth = AuthManager(scope, dry_run=False, transport=transport)
        self._clients: dict[str, ScopedClient] = {}
        self.last_text = ""            # raw text of last response (for find/forms)
        self.last_status: int | None = None
        self.requests: list[dict] = []  # audit of tool HTTP calls
        self.known_paths: set[str] | None = None   # action grounding (set from the recon registry)
        # The identity every tool/exploit/oracle call uses unless one is passed
        # explicitly. Set to the engagement's primary low-priv user so exploits run
        # FROM an authenticated baseline session (the senior-tester premise) AND the
        # success oracle shares that same session (so an in-exploit privilege
        # escalation, e.g. login() as admin, is visible to the win check).
        self.default_identity: str | None = None

    # ------------------------------------------------------------- sessions
    async def _client(self, base: str, identity: str | None) -> ScopedClient:
        if identity is None:
            identity = self.default_identity
        key = f"{base}|{identity or 'anon'}"
        if key not in self._clients:
            c = ScopedClient(self.scope, base, role=f"agent:{identity or 'anon'}",
                             limiter=self._limiter, transport=self._transport)
            if self._auth.has(identity):
                c.apply_auth(await self._auth.ensure(identity))  # type: ignore[arg-type]
            self._clients[key] = c
        return self._clients[key]

    def _compact(self, resp) -> dict:
        text = resp.text if resp is not None else ""
        self.last_text = text
        self.last_status = getattr(resp, "status_code", None)
        view = compact_html(text)
        return {"status": self.last_status, **view}

    # ------------------------------------------------------------- tools
    def _ground(self, path: str) -> "ToolResult | None":
        """Action grounding: refuse a path not seen during recon, with the real list."""
        if self.known_paths is None:
            return None
        bp = (path or "").split("?")[0].rstrip("/") or "/"
        if bp in self.known_paths:
            return None
        known = ", ".join(sorted(self.known_paths)[:20])
        return ToolResult(False, f"UNKNOWN_ENDPOINT {path!r} - not found during recon. "
                          f"Use ONLY discovered endpoints: {known}", {"status": 0, "unknown": True})

    async def http_get(self, path: str, identity: str | None = None) -> ToolResult:
        g = self._ground(path)
        if g:
            return g
        base = self.scope.authorized_base_urls[0]
        c = await self._client(base, identity)
        resp = await c.request("GET", path, follow_redirects=True)
        self.requests.append({"method": "GET", "path": path, "status": getattr(resp, "status_code", None)})
        d = self._compact(resp)
        return ToolResult(True, f"GET {path} -> {d['status']}", d)

    async def http_post_form(self, path: str, fields: dict | None = None,
                             identity: str | None = None, follow_redirects: bool = True) -> ToolResult:
        g = self._ground(path)
        if g:
            return g
        base = self.scope.authorized_base_urls[0]
        c = await self._client(base, identity)
        resp = await c.request("POST", path, data=fields or {}, follow_redirects=follow_redirects)
        self.requests.append({"method": "POST", "path": path, "status": getattr(resp, "status_code", None)})
        d = self._compact(resp)
        return ToolResult(True, f"POST(form) {path} -> {d['status']}", d)

    async def http_request(self, method: str, path: str, fields: dict | None = None,
                           identity: str | None = None, follow_redirects: bool = True) -> ToolResult:
        """Issue an arbitrary HTTP verb (DELETE/PUT/PATCH/...) form-encoded, through the
        scope guard + grounding. Exists so the differential oracle can replay an
        operator-defined RESTful win_action (e.g. {method:'DELETE', path:'/users/123'})
        with its REAL method instead of silently downgrading it to POST. DELETE/PUT/PATCH
        are auto-flagged destructive by ScopedClient, so they still require the scope's
        destructive permission - correct enterprise behavior."""
        g = self._ground(path)
        if g:
            return g
        base = self.scope.authorized_base_urls[0]
        c = await self._client(base, identity)
        m = (method or "GET").upper()
        resp = await c.request(m, path, data=fields or {}, follow_redirects=follow_redirects)
        self.requests.append({"method": m, "path": path, "status": getattr(resp, "status_code", None)})
        d = self._compact(resp)
        return ToolResult(True, f"{m} {path} -> {d['status']}", d)

    async def http_post_json(self, path: str, body: dict | None = None,
                             identity: str | None = None) -> ToolResult:
        g = self._ground(path)
        if g:
            return g
        base = self.scope.authorized_base_urls[0]
        c = await self._client(base, identity)
        resp = await c.request("POST", path, json=body or {}, follow_redirects=True)
        self.requests.append({"method": "POST", "path": path, "status": getattr(resp, "status_code", None)})
        try:
            j = resp.json() if resp is not None else {}
        except Exception:  # noqa: BLE001
            j = {}
        self.last_text = resp.text if resp is not None else ""
        self.last_status = getattr(resp, "status_code", None)
        return ToolResult(True, f"POST(json) {path} -> {self.last_status}",
                          {"status": self.last_status, "json": j})

    def find(self, regex: str) -> ToolResult:
        val = regex_extract(self.last_text, regex)
        return ToolResult(val is not None, f"find({regex!r}) -> {val!r}", {"match": val})

    def forms(self) -> ToolResult:
        view = compact_html(self.last_text)
        return ToolResult(bool(view.get("forms")), f"{len(view.get('forms', []))} form(s)",
                          {"forms": view.get("forms", []), "links": view.get("links", [])})

    def calc(self, expr: str) -> ToolResult:
        # Arithmetic only - no names, no calls.
        if not re.fullmatch(r"[-+*/%().\d\s]*", expr or ""):
            return ToolResult(False, "calc: only arithmetic allowed", {})
        # Reject exponentiation: the char-class above permits `**`, and a single
        # `9**9**9` is a CPU/RAM bomb (an unbounded big-integer) - a real DoS in a
        # shared console. Multiplication is enough for the pricing math calc is for.
        if "**" in expr:
            return ToolResult(False, "calc: exponentiation (**) is not allowed", {})
        try:
            val = eval(expr, {"__builtins__": {}}, {})  # noqa: S307 - sanitized above
            return ToolResult(True, f"calc({expr}) = {val}", {"value": val})
        except Exception as exc:  # noqa: BLE001
            return ToolResult(False, f"calc error: {exc}", {})

    async def read_email_inbox(self, url: str, recipient: str = "") -> ToolResult:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        try:
            c = await self._client(base, None)
        except ValueError:
            return ToolResult(False, "inbox host not in scope (add it to authorized_base_urls)", {})
        resp = await c.request("GET", p.path or "/", follow_redirects=True)
        html = resp.text if resp is not None else ""
        seg = html
        if recipient:
            i = html.find(recipient)
            if i >= 0:
                seg = html[i:i + 5000]
        links = re.findall(r'https?://[^\s"\'<>]+', seg)
        confirm = [l for l in links if ("token" in l or "confirm" in l)]
        return ToolResult(bool(confirm), f"inbox: {len(confirm)} confirmation link(s)",
                          {"confirmation_links": confirm[:5]})

    def note_set(self, key: str, value: Any) -> ToolResult:
        self.notebook.set(key, value)
        return ToolResult(True, f"noted {key}", {})

    def note_get(self, key: str) -> ToolResult:
        v = self.notebook.get(key)
        return ToolResult(v is not None, f"{key}={v!r}", {"value": v})

    async def run_exploit_code(self, code: str, identity: str | None = None) -> ToolResult:
        """Execute agent-authored async exploit code against a scope-guarded client.

        The code defines `async def exploit(http): ...`. `http` performs in-scope
        requests only (the scope guard still applies). stdout, the return value and
        any traceback are returned so the agent can iterate on its own code. This is
        a guardrail for an authorized operator, not a hard security sandbox.
        """
        if not isinstance(code, str) or "def exploit" not in code:
            return ToolResult(False, "code must define `async def exploit(http):`", {})
        ast_err = _validate_exploit_ast(code)
        if ast_err:
            return ToolResult(False, f"exploit code rejected (sandbox policy): {ast_err}",
                              {"error": ast_err})
        base = self.scope.authorized_base_urls[0]
        client = await self._client(base, identity)
        unknown_hits: list[str] = []
        trace: list[dict] = []   # real per-request observation fed back on failure

        def _record(method: str, path: str, status, text: str, *, note: str = "") -> None:
            self.requests.append({"method": method, "path": path, "status": status})
            self.last_text = text or ""
            self.last_status = status
            item = {"method": method, "path": path, "status": status,
                    "snippet": (text or "")[:200]}
            if note:
                item["note"] = note
            trace.append(item)

        async def http(method, path, data=None, params=None, json=None, headers=None,
                       cookies=None, follow_redirects=True):
            # Action grounding: only let the agent act on the DISCOVERED surface.
            # An invented path (a common LLM failure) is refused with the real list,
            # so the agent re-grounds on actual recon instead of hallucinating.
            if self.known_paths is not None:
                base_path = (path or "").split("?")[0].rstrip("/") or "/"
                if base_path not in self.known_paths:
                    unknown_hits.append(base_path)
                    known = ", ".join(sorted(self.known_paths)[:20])
                    return {"status": 0, "text": f"UNKNOWN_ENDPOINT {path!r} - this path was NOT "
                            f"found during recon. Use ONLY discovered endpoints: {known}", "headers": {}}
            # `cookies=` lets the agent forge a client-trusted identity cookie (e.g.
            # cookies={'auth': b64e('administrator:administrator')}) cleanly, instead
            # of fighting the cookie jar with a raw Cookie header. Set on the jar
            # (persisted, non-deprecated) so it carries into the win-oracle re-check too.
            if cookies:
                try:
                    client.set_cookies(cookies)
                except Exception:  # noqa: BLE001 - best effort
                    pass
            resp = await client.request(method.upper(), path, data=data, params=params,
                                        json=json, headers=headers,
                                        follow_redirects=follow_redirects)
            _record(method.upper(), path, getattr(resp, "status_code", None),
                    resp.text if resp is not None else "")
            return {"status": self.last_status, "text": self.last_text,
                    "headers": dict(getattr(resp, "headers", {}) or {})}

        async def login(username, password, *, path="/login",
                        username_field="username", password_field="password",
                        csrf_field="csrf", extra=None):
            """Authenticate as another identity IN THIS SESSION (cookies persist on the
            same client). Auto-carries a hidden CSRF token if the login form exposes
            one. This is what account-takeover chains need after changing a victim's
            credentials. Auth is infrastructure, so it bypasses action-grounding."""
            form = {username_field: username, password_field: password}
            # Drop the baseline identity's (domain-less) cookie first so the fresh
            # session this login establishes isn't shadowed by it.
            try:
                client.clear_cookies()
            except Exception:  # noqa: BLE001 - best effort
                pass
            try:
                page = await client.request("GET", path, follow_redirects=True)
                ptext = page.text if page is not None else ""
                m = re.search(rf'name=["\']?{re.escape(csrf_field)}["\']?[^>]*?value=["\']?([^"\'>\s]+)', ptext) \
                    or re.search(rf'value=["\']?([^"\'>\s]+)["\']?[^>]*?name=["\']?{re.escape(csrf_field)}', ptext)
                if m:
                    form[csrf_field] = m.group(1)
            except Exception:  # noqa: BLE001 - csrf is best-effort; many apps don't need it
                pass
            if extra:
                form.update(extra)
            resp = await client.request("POST", path, data=form, follow_redirects=True)
            _record("POST", path, getattr(resp, "status_code", None),
                    resp.text if resp is not None else "", note=f"login as {username!r}")
            return {"status": self.last_status, "text": self.last_text,
                    "headers": dict(getattr(resp, "headers", {}) or {})}

        ns: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS,
                              "re": re, "json": _json, "base64": base64,
                              # URL helpers injected directly (urllib import is denied -
                              # see _SAFE_IMPORTS) so no urllib package object is exposed.
                              "urlencode": urlencode, "quote": quote, "unquote": unquote,
                              "quote_plus": quote_plus, "urlparse": urlparse, "parse_qs": parse_qs,
                              "login": login, **_KIT}
        buf = io.StringIO()
        # Wall-clock guard for SYNCHRONOUS runaway code: asyncio.wait_for below only
        # cancels at await points, so a no-await `while True: pass` is killed by this
        # per-thread trace instead (it would otherwise wedge the event loop forever).
        deadline = time.monotonic() + _EXPLOIT_TIMEOUT
        prev_trace = _install_deadline_trace(deadline)
        try:
            with contextlib.redirect_stdout(buf):
                exec(compile(code, "<exploit>", "exec"), ns)   # noqa: S102 - sandboxed builtins
                fn = ns.get("exploit")
                if not callable(fn):
                    return ToolResult(False, "no `exploit` function defined", {"output": buf.getvalue()[-600:]})
                # Signature-tolerant dispatch: the prompt asks for `exploit(http)`, but
                # models often DECLARE the injected helpers as extra params
                # (`exploit(http, login)`) - which would otherwise crash with a missing-arg
                # TypeError. Bind `http` first, fill any further positional params from the
                # helper namespace by name, and default anything unknown to None so an arity
                # mismatch never aborts an otherwise-correct exploit.
                try:
                    pos_kinds = (inspect.Parameter.POSITIONAL_ONLY,
                                 inspect.Parameter.POSITIONAL_OR_KEYWORD)
                    pos = [p.name for p in inspect.signature(fn).parameters.values()
                           if p.kind in pos_kinds]
                    call_args = [http] + [ns.get(name) for name in pos[1:]]
                except (TypeError, ValueError):
                    call_args = [http]
                ret = fn(*call_args)
                if hasattr(ret, "__await__"):
                    ret = await asyncio.wait_for(ret, timeout=_EXPLOIT_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError, _ExploitTimeout):
            # asyncio.TimeoutError = an await that overran; _ExploitTimeout = the
            # sync-loop deadline trace fired. Both mean "took too long" - report once.
            return ToolResult(False, f"exploit code timed out (> {_EXPLOIT_TIMEOUT:.0f}s)",
                              {"error": "timeout", "output": buf.getvalue()[-600:],
                               "trace": trace, "unknown_endpoints": sorted(set(unknown_hits))})
        except ScopeError as exc:
            return ToolResult(False, f"BLOCKED by scope: {exc}",
                              {"output": buf.getvalue()[-600:], "trace": trace})
        except Exception:  # noqa: BLE001 - surface the traceback so the agent can fix its code
            return ToolResult(False, "exploit code raised - fix and re-run",
                              {"error": traceback.format_exc()[-700:], "output": buf.getvalue()[-600:],
                               "trace": trace, "unknown_endpoints": sorted(set(unknown_hits))})
        finally:
            sys.settrace(prev_trace)        # always restore the prior trace function
        return ToolResult(True, f"exploit code ran -> {str(ret)[:140]}",
                          {"return": ret, "output": buf.getvalue()[-600:],
                           "trace": trace, "unknown_endpoints": sorted(set(unknown_hits))})

    async def check_objective(self) -> ToolResult:
        if self.objective is None:
            return ToolResult(False, "no objective set", {"met": False})
        met = await self.objective.check(self)
        return ToolResult(met, f"objective met: {met}", {"met": met})

    # ------------------------------------------------------------- dispatch
    # Aliases so the planner can use the natural names LLMs emit.
    _ALIASES = {
        "http_post": "http_post_form", "post": "http_post_form", "post_form": "http_post_form",
        "post_json": "http_post_json", "get": "http_get", "http": "http_get",
        "read_inbox": "read_email_inbox", "inbox": "read_email_inbox",
        "exploit": "run_exploit_code", "run_code": "run_exploit_code",
        "write_exploit": "run_exploit_code", "code": "run_exploit_code",
    }

    @staticmethod
    def _as_fields(v):
        """Coerce a form body that may arrive as a dict or an 'a=b&c=d' string."""
        if isinstance(v, str):
            return {k: vals[0] for k, vals in parse_qs(v, keep_blank_values=True).items()}
        return v if isinstance(v, dict) else {}

    def _normalize(self, name: str, args: dict) -> tuple[str, dict]:
        """Map aliases and reconcile the loose arg names LLMs produce
        (body/data/fields, json flag) onto the concrete handler signatures."""
        name = self._ALIASES.get(name, name)
        a = dict(args)
        body = a.pop("body", None)
        data = a.pop("data", None)
        # A POST asking for JSON (json:true, or a 'json' dict) routes to the JSON tool.
        wants_json = a.pop("json", None)
        if name == "http_post_form" and (wants_json is True or isinstance(wants_json, dict)):
            name = "http_post_json"
        if name == "http_post_form":
            a["fields"] = self._as_fields(a.get("fields", body if body is not None else data) or {})
        elif name == "http_post_json":
            a["body"] = wants_json if isinstance(wants_json, dict) else (body or data or {})
        return name, a

    async def call(self, name: str, args: dict | None = None) -> ToolResult:
        name, args = self._normalize(name, args or {})
        handler = {
            "http_get": self.http_get, "http_post_form": self.http_post_form,
            "http_post_json": self.http_post_json, "find": self.find, "forms": self.forms,
            "calc": self.calc, "read_email_inbox": self.read_email_inbox,
            "note_set": self.note_set, "note_get": self.note_get,
            "check_objective": self.check_objective, "run_exploit_code": self.run_exploit_code,
        }.get(name)
        if handler is None:
            return ToolResult(False, f"unknown tool {name!r} (valid: {', '.join(t['name'] for t in CATALOG)})", {})
        # Drop unknown kwargs (e.g. headers, expect_status) so a stray field never
        # turns a correct action into a hard failure.
        accepted = set(inspect.signature(handler).parameters)
        clean = {k: v for k, v in args.items() if k in accepted}
        try:
            res = handler(**clean)
            if hasattr(res, "__await__"):
                res = await res
            return res
        except ScopeError as exc:
            return ToolResult(False, f"BLOCKED by scope: {exc}", {})
        except TypeError as exc:
            return ToolResult(False, f"bad args for {name}: {exc}", {})
        except Exception as exc:  # noqa: BLE001
            return ToolResult(False, f"{name} error: {exc}", {})

    def catalog(self) -> list[dict]:
        return CATALOG

    def audit(self) -> list[dict]:
        # redact() honors allow_pii_capture (operator opt-in); redact_secrets() is
        # ALWAYS on - a provider API key / bearer token embedded in a URL must never
        # reach the (signed, persisted) audit trail regardless of the PII setting.
        return [{**r, "path": redact_secrets(redact(r.get("path"), allow=self.scope.allow_pii_capture))}
                for r in self.requests]

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
