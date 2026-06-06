"""
Multi-user auth for the web console: password hashing, signed sessions, the
login/logout/me route flow, endpoint gating, and per-user engagement isolation.
Uses an isolated VENOM_DATA_DIR so it never touches a real users.json.
"""

import importlib

import pytest


@pytest.fixture()
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VENOM_WEB_SECRET", "test-secret-key")
    from venom.web import auth, routes, api, runs
    for m in (auth, runs, api, routes):
        importlib.reload(m)
    return auth, routes


# --------------------------------------------------------------- primitives
def test_password_hash_roundtrip(web):
    auth, _ = web
    h = auth.hash_password("hunter2")
    assert h.startswith("pbkdf2_sha256$") and "hunter2" not in h
    assert auth.verify_password("hunter2", h)
    assert not auth.verify_password("wrong", h)


def test_session_sign_verify_tamper_expiry(web):
    auth, _ = web
    tok = auth.make_session("alice")
    assert auth.read_session(tok) == "alice"
    # tampered signature
    assert auth.read_session(tok[:-2] + ("00" if tok[-2:] != "00" else "11")) is None
    # forged username keeps old sig
    user, exp, sig = tok.rsplit(".", 2)
    assert auth.read_session(f"bob.{exp}.{sig}") is None
    # expired
    assert auth.read_session(auth.make_session("alice", ttl=-1)) is None


# --------------------------------------------------------------- route flow
def test_login_me_logout_and_gating(web):
    auth, routes = web
    auth.add_user("alice", "pw-alice", name="Alice", role="lead")

    # unauthenticated: /api/me anon, protected endpoint 401
    st, body, _, _ = routes.handle("GET", "/api/me", {}, {}, "")
    assert body == {"authenticated": False, "user": None}
    st, body, _, _ = routes.handle("GET", "/api/engagements", {}, {}, "")
    assert st == 401

    # bad creds
    st, _, _, _ = routes.handle("POST", "/api/login", {}, {"username": "alice", "password": "no"}, "")
    assert st == 401

    # good creds -> Set-Cookie
    st, body, _, hdr = routes.handle("POST", "/api/login", {}, {"username": "alice", "password": "pw-alice"}, "")
    assert st == 200 and body["user"]["username"] == "alice"
    cookie = hdr["Set-Cookie"].split(";")[0]

    # /api/me + protected endpoint now work
    _, me, _, _ = routes.handle("GET", "/api/me", {}, {}, cookie)
    assert me["authenticated"] and me["user"]["name"] == "Alice"
    st, _, _, _ = routes.handle("GET", "/api/engagements", {}, {}, cookie)
    assert st == 200

    # logout clears the cookie
    _, _, _, hdr = routes.handle("POST", "/api/logout", {}, {}, cookie)
    assert "Max-Age=0" in hdr["Set-Cookie"]


def test_seed_user_has_no_weak_default(web, monkeypatch):
    """First-run seed must use a STRONG RANDOM password (surfaced once), never the
    old built-in 'admin/venom' - this console can launch authenticated attacks."""
    auth, _ = web
    monkeypatch.delenv("VENOM_WEB_PASSWORD", raising=False)
    seeded = auth.ensure_seed_user()
    assert seeded and seeded["username"] == "admin"
    assert seeded["password"] != "venom" and len(seeded["password"]) >= 12
    assert auth.authenticate("admin", "venom") is None              # old default is dead
    assert auth.authenticate("admin", seeded["password"]) is not None


def test_login_lockout_after_repeated_failures(web, monkeypatch):
    """Brute-force throttle: after N failures the account is locked and even the
    correct password is refused for the cooldown window."""
    auth, _ = web
    monkeypatch.setattr(auth, "_MAX_FAILS", 3)
    auth.add_user("dave", "correct-horse")
    for _ in range(3):
        assert auth.authenticate("dave", "wrong") is None
    assert auth._is_locked("dave") is True
    assert auth.authenticate("dave", "correct-horse") is None       # locked out
    # A different account is unaffected by dave's failures.
    auth.add_user("erin", "pw-erin")
    assert auth.authenticate("erin", "pw-erin") is not None


def test_cookie_secure_flag_opt_in(web, monkeypatch):
    auth, _ = web
    monkeypatch.delenv("VENOM_WEB_SECURE", raising=False)
    assert "Secure" not in auth.session_cookie("tok")               # localhost/http default
    monkeypatch.setenv("VENOM_WEB_SECURE", "1")
    assert "; Secure" in auth.session_cookie("tok")
    assert "; Secure" in auth.clear_cookie()


def test_runs_module_imports_settings():
    """Regression: runs.py used SETTINGS without importing it (NameError swallowed by a
    broad except, silently disabling per-lab coverage). It must resolve."""
    from venom.web import runs
    assert isinstance(runs.SETTINGS.campaign_per_target_calls, int)


def test_engagements_isolated_per_user(web):
    auth, routes = web
    auth.add_user("alice", "pw", role="lead")
    auth.add_user("bob", "pw", role="operator")

    def cookie_for(u, p):
        _, _, _, hdr = routes.handle("POST", "/api/login", {}, {"username": u, "password": p}, "")
        return hdr["Set-Cookie"].split(";")[0]

    ca, cb = cookie_for("alice", "pw"), cookie_for("bob", "pw")
    # alice launches a run (bundled VulnLab path is fine; we only check ownership routing)
    st, body, _, _ = routes.handle("POST", "/api/runs", {}, {"target_url": "localhost:8000"}, ca)
    # a run id is returned (or a clean error if no provider) - either way it must not 401
    assert st in (201, 503)
    if st == 201:
        rid = body["id"]
        # bob cannot read alice's run
        _, _, _, _ = routes.handle("GET", f"/api/runs/{rid}/findings", {}, {}, cb)
        from venom.web import api
        assert api.run_visible_to(rid, "alice") is True
        assert api.run_visible_to(rid, "bob") is False


def test_run_id_path_traversal_blocked(web):
    """SECURITY: run_visible_to() returns True for UNKNOWN ids, and the per-run
    handlers build `_data_dir()/<run_id>/<fixed-file>`. A run id of '..' (which the
    route regex [^/]+ matches) would escape the per-run dir — GET /api/runs/../report.md
    would read the PARENT dir's report.md. The router must reject any id outside
    [A-Za-z0-9_-] before it touches the filesystem."""
    auth, routes = web
    auth.add_user("alice", "pw", role="lead")
    _, _, _, hdr = routes.handle("POST", "/api/login", {}, {"username": "alice", "password": "pw"}, "")
    cookie = hdr["Set-Cookie"].split(";")[0]

    from venom.web.runs import _data_dir
    # Plant a secret exactly where a '..' traversal of the per-run path would land.
    planted = _data_dir().parent / "report.md"
    planted.write_text("SECRET-PARENT-FILE", encoding="utf-8")

    for path in ("/api/runs/../report.md",
                 "/api/runs/../findings.json",
                 "/api/runs/..%2f..%2fetc/report.md"):
        st, body, _, _ = routes.handle("GET", path, {}, {}, cookie)
        assert st == 404, f"{path} -> {st}"
        assert "SECRET-PARENT-FILE" not in str(body), f"LEAKED via {path}"

    # A well-formed (but unknown) id still 404s cleanly via the normal path.
    st, _, _, _ = routes.handle("GET", "/api/runs/ENG-WEB-deadbeef", {}, {}, cookie)
    assert st == 404
